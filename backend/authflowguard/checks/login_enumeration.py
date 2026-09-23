"""Runner and deterministic offline analyser for login account enumeration."""

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID, uuid4

from playwright.async_api import Browser, BrowserContext, Page, async_playwright

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
from authflowguard.playwright_worker import PlaywrightWorker
from authflowguard.scope import url_without_query_or_fragment
from authflowguard.secrets import RuntimeSecrets

OWASP_REFERENCE = "WSTG-IDNT-04"
ANALYSER_VERSION = "1.0"
PAIR_COUNT = 3


@dataclass(frozen=True)
class LoginEnumerationRun:
    """Nonsecret evidence and events produced by the browser runner."""

    evidence: TestRunEvidence
    events: list[EvidenceEvent]


def _event_for_check(event: EvidenceEvent) -> EvidenceEvent:
    return event.model_copy(update={"check_id": CheckId.LOGIN_ENUMERATION})


def _new_attempt_action(action: BrowserAction) -> BrowserAction:
    return action.model_copy(update={"action_id": uuid4()})


def _normalized_body(text: str, identifier: str) -> str:
    without_identifier = text.replace(identifier, "<identifier>")
    return re.sub(r"\s+", " ", without_identifier).strip()


async def _page_signature(
    page: Page,
    page_evidence: EvidenceEvent,
    action_events: list[EvidenceEvent],
    identifier: str,
) -> dict[str, Any]:
    body = _normalized_body(await page.locator("body").inner_text(), identifier)
    controls = page_evidence.redacted_details.get("controls", [])
    controls_json = json.dumps(controls, separators=(",", ":"), sort_keys=True)
    body_fingerprint = hashlib.sha256(body.encode("utf-8")).hexdigest()
    control_fingerprint = hashlib.sha256(controls_json.encode("utf-8")).hexdigest()
    response_statuses = [
        event.redacted_details.get("status")
        for event in action_events
        if event.kind is EvidenceKind.RESPONSE
    ]
    return {
        "url": url_without_query_or_fragment(page.url),
        "title": await page.title(),
        "body_fingerprint": body_fingerprint,
        "body_length": len(body),
        "control_fingerprint": control_fingerprint,
        "response_statuses": response_statuses,
    }


def _fill_references(
    steps: list[BrowserAction],
    username_reference: str | None,
    password_reference: str | None,
) -> tuple[str, str]:
    fill_references = [
        action.value_reference
        for action in steps
        if action.action_type is BrowserActionType.FILL
        and action.value_reference is not None
    ]
    if username_reference is None:
        if not fill_references:
            raise ValueError("The saved login flow has no username fill action")
        user_matches = [
            r
            for r in fill_references
            if "user" in r.lower() or "login" in r.lower() or "email" in r.lower()
        ]
        username_reference = user_matches[0] if user_matches else fill_references[0]
    if password_reference is None:
        remaining = [
            reference
            for reference in fill_references
            if reference != username_reference
        ]
        if not remaining:
            raise ValueError("The saved login flow has no password fill action")
        pass_matches = [r for r in remaining if "pass" in r.lower()]
        password_reference = pass_matches[0] if pass_matches else remaining[0]
    return username_reference, password_reference


async def _run_failed_login_attempt(
    *,
    browser: Browser,
    profile: AuthProfile,
    scan_id: UUID,
    steps: list[BrowserAction],
    identifier: str,
    username_reference: str,
    password_reference: str,
    failure_password: str,
    label: str,
    events: list[EvidenceEvent],
) -> dict[str, Any]:
    context: BrowserContext | None = None
    attempt_secrets = RuntimeSecrets(
        {
            username_reference: identifier,
            password_reference: failure_password,
        }
    )
    try:
        context = await browser.new_context()
        page = await context.new_page()
        executor = BrowserActionExecutor(
            page,
            profile.target,
            attempt_secrets,
            scan_id,
        )
        action_events: list[EvidenceEvent] = []
        for step in steps:
            result = await executor.execute(_new_attempt_action(step))
            action_events.extend(_event_for_check(event) for event in result.events)
            events.extend(_event_for_check(event) for event in result.events)

        recorder = PlaywrightWorker()
        page_evidence = _event_for_check(
            await recorder.record_page_state(scan_id, page)
        )
        page_evidence = page_evidence.model_copy(
            update={
                "summary": (
                    "The login enumeration runner recorded a normalized failure page."
                ),
                "redacted_details": {
                    **page_evidence.redacted_details,
                    "comparison_label": label,
                    "signature": await _page_signature(
                        page,
                        page_evidence,
                        action_events,
                        identifier,
                    ),
                },
            }
        )
        events.append(page_evidence)
        return cast(dict[str, Any], page_evidence.redacted_details["signature"])
    finally:
        attempt_secrets.discard_all()
        if context is not None:
            await context.close()


async def run_login_enumeration_check(
    *,
    profile: AuthProfile,
    scan_id: UUID,
    runtime_secrets: RuntimeSecrets,
    known_identifier_reference: str,
    nonexistent_identifier_reference: str,
    failure_password_reference: str,
    username_action_reference: str | None = None,
    password_action_reference: str | None = None,
) -> LoginEnumerationRun:
    """Compare failed logins for known and nonexistent identifiers three times."""

    if profile.features.get(AuthFeature.LOGIN) is not FeatureStatus.VERIFIED:
        raise ValueError("The auth profile has no verified login feature")

    steps = profile.authentication_steps.get(AuthFeature.LOGIN, [])
    if not steps:
        raise ValueError("The auth profile has no saved login flow")
    username_reference, password_reference = _fill_references(
        steps,
        username_action_reference,
        password_action_reference,
    )
    known_identifier = runtime_secrets.resolve(known_identifier_reference)
    nonexistent_identifier = runtime_secrets.resolve(nonexistent_identifier_reference)
    failure_password = runtime_secrets.resolve(failure_password_reference)

    events: list[EvidenceEvent] = []
    pairs: list[dict[str, Any]] = []
    attempted_steps: list[str] = []
    completed_steps: list[str] = []
    errors: list[str] = []

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            for pair_number in range(1, PAIR_COUNT + 1):
                pair: dict[str, Any] = {"pair_number": pair_number}
                for label, identifier in [
                    ("known", known_identifier),
                    ("nonexistent", nonexistent_identifier),
                ]:
                    step_label = f"pair-{pair_number}-{label}-failure"
                    attempted_steps.append(step_label)
                    try:
                        pair[label] = await _run_failed_login_attempt(
                            browser=browser,
                            profile=profile,
                            scan_id=scan_id,
                            steps=steps,
                            identifier=identifier,
                            username_reference=username_reference,
                            password_reference=password_reference,
                            failure_password=failure_password,
                            label=label,
                            events=events,
                        )
                        completed_steps.append(step_label)
                    except Exception as error:
                        errors.append(f"{step_label}: {type(error).__name__}")
                        events.append(
                            EvidenceEvent(
                                event_id=uuid4(),
                                scan_id=scan_id,
                                check_id=CheckId.LOGIN_ENUMERATION,
                                kind=EvidenceKind.ERROR,
                                summary="A login enumeration attempt failed.",
                                redacted_details={
                                    "step": step_label,
                                    "error_type": type(error).__name__,
                                },
                            )
                        )
                pairs.append(pair)
        finally:
            await browser.close()

    evidence = TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=scan_id,
        check_id=CheckId.LOGIN_ENUMERATION,
        profile_version=profile.schema_version,
        event_ids=[event.event_id for event in events],
        observations={"pairs": pairs, "pair_count": PAIR_COUNT},
        control_comparisons=[
            (
                f"Pair {pair_number}: normalized page signatures were captured "
                "for both identifiers."
            )
            for pair_number in range(1, PAIR_COUNT + 1)
        ],
        errors=errors,
        coverage=Coverage(
            attempted_steps=attempted_steps,
            completed_steps=completed_steps,
            limitations=[
                (
                    "The check compares three bounded failure pairs and does not "
                    "establish behavior outside those attempts."
                )
            ],
        ),
    )
    return LoginEnumerationRun(evidence=evidence, events=events)


def _observable_signature(signature: dict[str, Any]) -> tuple[Any, ...]:
    """Return fields suitable for comparison without using raw response length alone."""

    return (
        signature.get("url"),
        signature.get("title"),
        signature.get("body_fingerprint"),
        signature.get("control_fingerprint"),
    )


def analyse_login_enumeration(
    evidence: TestRunEvidence,
    profile: AuthProfile,
    policy: SecurityPolicy,
) -> CheckResult:
    """Analyse saved login-enumeration evidence without performing live I/O."""

    if evidence.check_id is not CheckId.LOGIN_ENUMERATION:
        raise ValueError("Evidence belongs to a different security check")
    if not profile.authentication_steps.get(AuthFeature.LOGIN):
        raise ValueError("The auth profile has no login flow")

    base = {
        "result_id": uuid4(),
        "scan_id": evidence.scan_id,
        "check_id": CheckId.LOGIN_ENUMERATION,
        "owasp_reference": OWASP_REFERENCE,
        "analyser_version": ANALYSER_VERSION,
        "evidence_references": [evidence.evidence_id, *evidence.event_ids],
    }
    if evidence.errors:
        return CheckResult(
            **base,
            outcome=CheckOutcome.EXECUTION_ERROR,
            explanation=(
                "One or more login enumeration attempts failed before comparison."
            ),
            coverage_limitations=evidence.coverage.limitations,
        )

    pairs = evidence.observations.get("pairs")
    if not isinstance(pairs, list) or len(pairs) != PAIR_COUNT:
        return CheckResult(
            **base,
            outcome=CheckOutcome.INCONCLUSIVE,
            explanation=(
                "Three complete known-versus-nonexistent comparisons were not recorded."
            ),
            coverage_limitations=[
                *evidence.coverage.limitations,
                "The required three paired comparisons are incomplete.",
            ],
        )

    differences: list[bool] = []
    for pair in pairs:
        if not isinstance(pair, dict):
            return CheckResult(
                **base,
                outcome=CheckOutcome.INCONCLUSIVE,
                explanation="A comparison pair has an invalid evidence shape.",
                coverage_limitations=evidence.coverage.limitations,
            )
        known = pair.get("known")
        nonexistent = pair.get("nonexistent")
        if not isinstance(known, dict) or not isinstance(nonexistent, dict):
            return CheckResult(
                **base,
                outcome=CheckOutcome.INCONCLUSIVE,
                explanation="A comparison pair is missing one of its observations.",
                coverage_limitations=evidence.coverage.limitations,
            )
        differences.append(
            _observable_signature(known) != _observable_signature(nonexistent)
        )

    if not policy.account_existence_is_private:
        outcome = CheckOutcome.NO_ISSUE_OBSERVED
        explanation = (
            "The procedure completed, but the configured policy does not require "
            "account-existence privacy."
        )
    elif all(differences):
        outcome = CheckOutcome.FINDING_CONFIRMED
        explanation = (
            "Known-account and nonexistent-account login failures produced "
            "repeatable observable differences in all three paired comparisons."
        )
    elif not any(differences):
        outcome = CheckOutcome.NO_ISSUE_OBSERVED
        explanation = (
            "No observable page, title, URL, or control-state difference was "
            "found across the three paired comparisons."
        )
    else:
        outcome = CheckOutcome.INCONCLUSIVE
        explanation = (
            "The paired comparisons were inconsistent, so the evidence does not "
            "support a repeatable enumeration conclusion."
        )

    return CheckResult(
        **base,
        outcome=outcome,
        explanation=explanation,
        coverage_limitations=evidence.coverage.limitations,
    )
