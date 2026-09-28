"""CHK-004: bounded login throttling and lockout testing.

The runner performs failed attempts for a verified account, then uses a valid
login as a control. Every attempt gets a fresh browser context and current form
state; the analyser evaluates only the saved status and safe page fingerprints.
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from playwright.async_api import Browser, BrowserContext, async_playwright

from authflowguard.action_executor import BrowserActionExecutor
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    CheckId,
    CheckOutcome,
    CheckResult,
    Coverage,
    EvidenceEvent,
    EvidenceKind,
    FeatureStatus,
    SecurityPolicy,
    TestRunEvidence,
)
from authflowguard.scope import url_without_query_or_fragment
from authflowguard.secrets import RuntimeSecrets

OWASP_REFERENCE = "WSTG-ATHN-03"
ANALYSER_VERSION = "1.0"
DEFAULT_ATTEMPTS = 3
MAX_ATTEMPTS = 5


@dataclass(frozen=True)
class LoginThrottlingRun:
    evidence: TestRunEvidence
    events: list[EvidenceEvent]


def _fingerprint(value: str) -> str:
    return hashlib.sha256(" ".join(value.split()).encode("utf-8")).hexdigest()


def _fill_references(steps: list[BrowserAction]) -> tuple[str, str]:
    references = [
        action.value_reference
        for action in steps
        if action.action_type is BrowserActionType.FILL
        and action.value_reference is not None
    ]
    if len(references) < 2:
        raise ValueError("The saved login flow needs username and password fills")
    user_refs = [
        r
        for r in references
        if "user" in r.lower() or "login" in r.lower() or "email" in r.lower()
    ]
    username_ref = user_refs[0] if user_refs else references[0]
    remaining = [r for r in references if r != username_ref]
    pass_refs = [r for r in remaining if "pass" in r.lower()]
    password_ref = (
        pass_refs[0] if pass_refs else (remaining[0] if remaining else references[1])
    )
    return username_ref, password_ref


def _adapt_steps(
    steps: list[BrowserAction], username_reference: str, password_reference: str
) -> list[BrowserAction]:
    """Use this scan's runtime references while preserving saved control IDs."""
    fill_index = 0
    adapted: list[BrowserAction] = []
    for step in steps:
        if step.action_type is BrowserActionType.FILL:
            val_ref = (step.value_reference or "").lower()
            if "user" in val_ref or "login" in val_ref or "email" in val_ref:
                reference = username_reference
            elif "pass" in val_ref:
                reference = password_reference
            else:
                reference = (
                    username_reference if fill_index == 0 else password_reference
                )
            adapted.append(step.model_copy(update={"value_reference": reference}))
            fill_index += 1
        else:
            adapted.append(step)
    return adapted


async def _attempt(
    *,
    browser: Browser,
    profile: AuthProfile,
    scan_id: UUID,
    steps: list[BrowserAction],
    username_reference: str,
    password_reference: str,
    username: str,
    password: str,
    label: str,
    events: list[EvidenceEvent],
    cancel_requested: Callable[[], bool],
) -> dict[str, Any]:
    context: BrowserContext | None = None
    attempt_secrets = RuntimeSecrets(
        {username_reference: username, password_reference: password}
    )
    response_statuses: list[int] = []
    try:
        context = await browser.new_context(service_workers="block")
        page = await context.new_page()
        executor = BrowserActionExecutor(
            page,
            profile.target,
            attempt_secrets,
            scan_id,
            password_references=frozenset({password_reference}),
        )
        for step in steps:
            if cancel_requested():
                raise RuntimeError("Login throttling execution cancelled")
            result = await executor.execute(
                step.model_copy(update={"action_id": uuid4()})
            )
            for event in result.events:
                safe_details = {
                    key: value
                    for key, value in event.redacted_details.items()
                    if key
                    in {
                        "status",
                        "method",
                        "resource_type",
                        "url",
                        "changed",
                        "url_changed",
                        "title_changed",
                        "visible_text_changed",
                        "control_state_changed",
                        "controls_became_visible",
                        "controls_became_hidden",
                        "started_at",
                        "completed_at",
                    }
                }
                safe_event = event.model_copy(
                    update={
                        "check_id": CheckId.LOGIN_THROTTLING,
                        "redacted_details": safe_details,
                    }
                )
                events.append(safe_event)
                if event.kind is EvidenceKind.RESPONSE and isinstance(
                    event.redacted_details.get("status"), int
                ):
                    response_statuses.append(event.redacted_details["status"])
        body = await page.locator("body").inner_text()
        title = await page.title()
        signature = {
            "status_codes": response_statuses,
            "final_status_code": response_statuses[-1] if response_statuses else None,
            "url": url_without_query_or_fragment(page.url),
            "title_fingerprint": _fingerprint(title),
            "body_fingerprint": _fingerprint(body),
            "safe_indicators": sorted(
                name
                for name, pattern in {
                    "rate_limited": r"try again later|too many|locked|unavailable",
                    "authentication_required": r"authentication required",
                    "signed_in": r"signed in as|developer account",
                }.items()
                if re.search(pattern, body, re.I)
            ),
            "completed": True,
        }
        events.append(
            EvidenceEvent(
                event_id=uuid4(),
                scan_id=scan_id,
                check_id=CheckId.LOGIN_THROTTLING,
                kind=EvidenceKind.PAGE_STATE,
                summary="Captured a safe login throttling attempt outcome.",
                redacted_details={"label": label, "signature": signature},
            )
        )
        return signature
    finally:
        attempt_secrets.discard_all()
        if context is not None:
            await context.close()


async def run_login_throttling_check(
    *,
    profile: AuthProfile,
    scan_id: UUID,
    runtime_secrets: RuntimeSecrets,
    username_reference: str,
    password_reference: str,
    failure_password_reference: str,
    expected_lockout_threshold: int | None = None,
    cancel_requested: Callable[[], bool] = lambda: False,
) -> LoginThrottlingRun:
    """Run bounded failed attempts followed by a valid-login control."""

    if profile.features.get(AuthFeature.LOGIN) is not FeatureStatus.VERIFIED:
        raise ValueError("The auth profile has no verified login feature")
    steps = profile.authentication_steps.get(AuthFeature.LOGIN, [])
    if not steps:
        raise ValueError("The auth profile has no saved login flow")
    saved_username_reference, saved_password_reference = _fill_references(steps)
    username_reference = username_reference or saved_username_reference
    password_reference = password_reference or saved_password_reference
    steps = _adapt_steps(steps, username_reference, password_reference)
    username = runtime_secrets.resolve(username_reference)
    known_password = runtime_secrets.resolve(password_reference)
    failure_password = runtime_secrets.resolve(failure_password_reference)
    attempts = min(expected_lockout_threshold or DEFAULT_ATTEMPTS, MAX_ATTEMPTS)
    if attempts < 1 or not username or not known_password or not failure_password:
        raise ValueError("Login throttling requires nonempty credential references")

    events: list[EvidenceEvent] = []
    failed_attempts: list[dict[str, Any]] = []
    attempted_steps: list[str] = []
    completed_steps: list[str] = []
    errors: list[str] = []
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                for number in range(1, attempts + 1):
                    label = f"failed_attempt_{number}"
                    attempted_steps.append(label)
                    try:
                        failed_attempts.append(
                            await _attempt(
                                browser=browser,
                                profile=profile,
                                scan_id=scan_id,
                                steps=steps,
                                username_reference=username_reference,
                                password_reference=password_reference,
                                username=username,
                                password=failure_password,
                                label=label,
                                events=events,
                                cancel_requested=cancel_requested,
                            )
                        )
                        completed_steps.append(label)
                    except Exception as error:
                        errors.append(type(error).__name__)
                        break
                if not errors:
                    label = "valid_login_control"
                    attempted_steps.append(label)
                    failed_attempts.append(
                        {
                            "valid_login_control": await _attempt(
                                browser=browser,
                                profile=profile,
                                scan_id=scan_id,
                                steps=steps,
                                username_reference=username_reference,
                                password_reference=password_reference,
                                username=username,
                                password=known_password,
                                label=label,
                                events=events,
                                cancel_requested=cancel_requested,
                            )
                        }
                    )
                    completed_steps.append(label)
            finally:
                await browser.close()
    except Exception as error:
        errors.append(type(error).__name__)
    if errors:
        events.append(
            EvidenceEvent(
                event_id=uuid4(),
                scan_id=scan_id,
                check_id=CheckId.LOGIN_THROTTLING,
                kind=EvidenceKind.ERROR,
                summary="Login throttling execution did not complete.",
                redacted_details={"error_types": errors},
            )
        )
    evidence = TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=scan_id,
        check_id=CheckId.LOGIN_THROTTLING,
        profile_version=profile.schema_version,
        event_ids=[event.event_id for event in events],
        observations={
            "failed_attempts": failed_attempts,
            "attempt_count": attempts,
            "captured_at": datetime.now(UTC).isoformat(),
        },
        control_comparisons=[
            "Bounded failed attempts were compared with a valid-login control."
        ]
        if not errors
        else [],
        errors=errors,
        coverage=Coverage(
            attempted_steps=attempted_steps,
            completed_steps=completed_steps,
            limitations=[
                f"The runner tested {attempts} failed attempts and one "
                "valid-login control.",
                "The threshold outside this bounded attempt count was not tested.",
            ],
        ),
    )
    return LoginThrottlingRun(evidence=evidence, events=events)


def analyse_login_throttling(
    evidence: TestRunEvidence,
    profile: AuthProfile,
    policy: SecurityPolicy,
) -> CheckResult:
    """Analyse throttling evidence without browser, network, or credentials."""

    if evidence.check_id is not CheckId.LOGIN_THROTTLING:
        raise ValueError("Evidence belongs to a different security check")
    identity = json.dumps(
        {
            "evidence": evidence.model_dump(mode="json"),
            "policy": policy.model_dump(mode="json"),
            "analyser_version": ANALYSER_VERSION,
        },
        sort_keys=True,
    )
    base = {
        "result_id": uuid5(NAMESPACE_URL, identity),
        "scan_id": evidence.scan_id,
        "check_id": CheckId.LOGIN_THROTTLING,
        "owasp_reference": OWASP_REFERENCE,
        "analyser_version": ANALYSER_VERSION,
        "evidence_references": [evidence.evidence_id, *evidence.event_ids],
        "coverage_limitations": evidence.coverage.limitations,
    }
    if evidence.errors:
        return CheckResult(
            **base,
            outcome=CheckOutcome.EXECUTION_ERROR,
            explanation=(
                "Login throttling execution failed before the control comparison "
                "completed."
            ),
        )
    attempts = evidence.observations.get("failed_attempts")
    expected = evidence.observations.get("attempt_count")
    if (
        not isinstance(attempts, list)
        or not isinstance(expected, int)
        or len(attempts) != expected + 1
    ):
        return CheckResult(
            **base,
            outcome=CheckOutcome.INCONCLUSIVE,
            explanation=(
                "The bounded failed-attempt sequence or valid-login control is "
                "incomplete."
            ),
        )
    valid = (
        attempts[-1].get("valid_login_control")
        if isinstance(attempts[-1], dict)
        else None
    )
    failed = attempts[:-1]

    def valid_signature(value: Any) -> bool:
        return (
            isinstance(value, dict)
            and isinstance(value.get("status_codes"), list)
            and all(isinstance(status, int) for status in value["status_codes"])
            and isinstance(value.get("final_status_code"), int)
            and isinstance(value.get("url"), str)
            and all(
                isinstance(value.get(field), str)
                and re.fullmatch(r"[0-9a-f]{64}", value[field])
                for field in ("title_fingerprint", "body_fingerprint")
            )
            and isinstance(value.get("safe_indicators"), list)
            and all(isinstance(item, str) for item in value["safe_indicators"])
            and value.get("completed") is True
        )

    if not valid_signature(valid) or not all(valid_signature(item) for item in failed):
        return CheckResult(
            **base,
            outcome=CheckOutcome.INCONCLUSIVE,
            explanation="The throttling evidence has an invalid attempt shape.",
        )
    valid = cast(dict[str, Any], valid)
    failed = [cast(dict[str, Any], item) for item in failed]
    valid_status = valid.get("final_status_code")
    valid_indicators = set(valid.get("safe_indicators", []))
    failed_statuses = [item.get("final_status_code") for item in failed]
    all_statuses = [
        status
        for attempt in [*failed, valid]
        for status in attempt.get("status_codes", [])
    ]
    if any(status < 100 or status >= 500 for status in all_statuses):
        return CheckResult(
            **base,
            outcome=CheckOutcome.EXECUTION_ERROR,
            explanation=(
                "The throttling flow returned an unexpected server error status."
            ),
        )
    restricted = (
        valid_status in {401, 403, 423, 429} or "rate_limited" in valid_indicators
    )
    successful_control = valid_status in {200, 201, 202, 204, 302, 303}
    if not successful_control and not restricted:
        outcome = CheckOutcome.INCONCLUSIVE
        explanation = (
            "The valid-login control returned an unrelated or ambiguous response."
        )
    elif not policy.expected_lockout_threshold:
        outcome = (
            CheckOutcome.NO_ISSUE_OBSERVED
            if restricted
            else CheckOutcome.FINDING_CONFIRMED
        )
        explanation = (
            "The valid login was restricted after bounded failures."
            if restricted
            else (
                "The valid login succeeded after bounded failures; no lockout "
                "response was observed."
            )
        )
    elif restricted:
        outcome = CheckOutcome.NO_ISSUE_OBSERVED
        explanation = (
            f"The valid-login control was restricted after {len(failed)} failed "
            "attempts, "
            "consistent with the configured lockout policy."
        )
    else:
        outcome = CheckOutcome.FINDING_CONFIRMED
        explanation = (
            f"The valid-login control succeeded after {len(failed)} failed attempts "
            "without an observed throttling or lockout response."
        )
    if any(
        not isinstance(status, int)
        or status
        not in {
            200,
            201,
            202,
            204,
            301,
            302,
            303,
            307,
            308,
            400,
            401,
            403,
            404,
            409,
            423,
            429,
        }
        for status in failed_statuses
    ):
        outcome = CheckOutcome.EXECUTION_ERROR
        explanation = (
            "One or more failed-attempt responses returned an unexpected status."
        )
    captured_at = datetime(1970, 1, 1, tzinfo=UTC)
    try:
        captured_at = datetime.fromisoformat(str(evidence.observations["captured_at"]))
    except (KeyError, TypeError, ValueError):
        pass
    return CheckResult(
        **base,
        outcome=outcome,
        explanation=explanation,
        created_at=captured_at,
    )
