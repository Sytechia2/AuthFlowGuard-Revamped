"""CHK-005: session fixation testing with isolated pre-login replay."""

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from playwright.async_api import async_playwright

from authflowguard.checks.session_common import (
    adapt_login_steps,
    check_event,
    cookie_snapshot,
    execute_login_steps,
    login_steps_for,
    protected_state,
)
from authflowguard.models import (
    AuthProfile,
    CheckId,
    CheckOutcome,
    CheckResult,
    Coverage,
    EvidenceEvent,
    EvidenceKind,
    SecurityPolicy,
    TestRunEvidence,
)
from authflowguard.page_settling import goto_and_settle
from authflowguard.secrets import RuntimeSecrets

OWASP_REFERENCE = "WSTG-SESS-03"
ANALYSER_VERSION = "1.0"


class SessionFixationRun:
    def __init__(self, evidence: TestRunEvidence, events: list[EvidenceEvent]):
        self.evidence = evidence
        self.events = events


async def run_session_fixation_check(
    *,
    profile: AuthProfile,
    scan_id: UUID,
    runtime_secrets: RuntimeSecrets,
    username_reference: str,
    password_reference: str,
    protected_resource: str,
    account_marker_selector: str,
    cancel_requested: Callable[[], bool] = lambda: False,
) -> SessionFixationRun:
    steps = adapt_login_steps(
        login_steps_for(profile), username_reference, password_reference
    )
    if not protected_resource or not account_marker_selector:
        raise ValueError("Session fixation requires a protected resource and marker")
    events: list[EvidenceEvent] = []
    attempted_steps = ["capture_pre_login_session", "complete_login"]
    completed_steps: list[str] = []
    observations: dict[str, Any] = {}
    errors: list[str] = []
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                context = await browser.new_context(service_workers="block")
                try:
                    page = await context.new_page()
                    await goto_and_settle(page, str(profile.target.target_url))
                    pre_login_cookies = await context.cookies()
                    observations["pre_login_session"] = cookie_snapshot(
                        pre_login_cookies
                    )
                    events.append(
                        check_event(
                            scan_id,
                            CheckId.SESSION_FIXATION,
                            EvidenceKind.STORAGE_CHANGE,
                            "Captured the pre-login browser session fingerprint.",
                            phase="pre_login",
                            cookie_snapshot=observations["pre_login_session"],
                        )
                    )
                    completed_steps.append("capture_pre_login_session")
                    await execute_login_steps(
                        page=page,
                        profile=profile,
                        scan_id=scan_id,
                        steps=steps,
                        secrets=runtime_secrets,
                        events=events,
                        check_id=CheckId.SESSION_FIXATION,
                        cancel_requested=cancel_requested,
                    )
                    authenticated = await protected_state(
                        page, protected_resource, account_marker_selector
                    )
                    post_login_cookies = await context.cookies()
                    observations["post_login_session"] = cookie_snapshot(
                        post_login_cookies
                    )
                    observations["authenticated_control"] = authenticated
                    completed_steps.append("complete_login")
                    events.append(
                        check_event(
                            scan_id,
                            CheckId.SESSION_FIXATION,
                            EvidenceKind.PAGE_STATE,
                            "Captured authenticated access and post-login "
                            "session state.",
                            phase="authenticated_control",
                            status=authenticated["status"],
                            marker_present=authenticated["marker_present"],
                            cookie_snapshot=observations["post_login_session"],
                        )
                    )
                finally:
                    await context.close()

                replay_context = await browser.new_context(service_workers="block")
                try:
                    await replay_context.add_cookies(cast(Any, pre_login_cookies))
                    replay_page = await replay_context.new_page()
                    replay = await protected_state(
                        replay_page, protected_resource, account_marker_selector
                    )
                    observations["original_session_replay"] = replay
                    events.append(
                        check_event(
                            scan_id,
                            CheckId.SESSION_FIXATION,
                            EvidenceKind.PAGE_STATE,
                            "Tested the original pre-login session in an isolated "
                            "context.",
                            phase="original_session_replay",
                            status=replay["status"],
                            marker_present=replay["marker_present"],
                        )
                    )
                finally:
                    await replay_context.close()

                anonymous_context = await browser.new_context(service_workers="block")
                try:
                    anonymous_page = await anonymous_context.new_page()
                    anonymous = await protected_state(
                        anonymous_page, protected_resource, account_marker_selector
                    )
                    observations["anonymous_control"] = anonymous
                    events.append(
                        check_event(
                            scan_id,
                            CheckId.SESSION_FIXATION,
                            EvidenceKind.PAGE_STATE,
                            "Captured an anonymous protected-resource control.",
                            phase="anonymous_control",
                            status=anonymous["status"],
                            marker_present=anonymous["marker_present"],
                        )
                    )
                finally:
                    await anonymous_context.close()
            finally:
                await browser.close()
    except Exception as error:
        errors.append(type(error).__name__)
        events.append(
            check_event(
                scan_id,
                CheckId.SESSION_FIXATION,
                EvidenceKind.ERROR,
                "Session fixation execution did not complete.",
                error_types=errors,
            )
        )
    evidence = TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=scan_id,
        check_id=CheckId.SESSION_FIXATION,
        profile_version=profile.schema_version,
        event_ids=[event.event_id for event in events],
        observations={
            **observations,
            "session_rotated": observations.get("pre_login_session", {}).get(
                "fingerprint"
            )
            != observations.get("post_login_session", {}).get("fingerprint"),
            "captured_at": datetime.now(UTC).isoformat(),
        },
        control_comparisons=[
            "Authenticated access, original-session replay, and anonymous access "
            "were compared."
        ]
        if not errors
        else [],
        errors=errors,
        coverage=Coverage(
            attempted_steps=attempted_steps,
            completed_steps=completed_steps,
            limitations=[
                "The procedure demonstrates session reuse when the captured "
                "pre-login state authenticates; it does not establish that an "
                "attacker can force a victim to accept that state.",
                "Only browser cookie state visible to the isolated context was "
                "compared.",
            ],
        ),
    )
    return SessionFixationRun(evidence=evidence, events=events)


def analyse_session_fixation(
    evidence: TestRunEvidence, profile: AuthProfile, policy: SecurityPolicy
) -> CheckResult:
    del profile, policy
    if evidence.check_id is not CheckId.SESSION_FIXATION:
        raise ValueError("Evidence belongs to a different security check")
    identity = json.dumps(
        {
            "evidence": evidence.model_dump(mode="json"),
            "analyser_version": ANALYSER_VERSION,
        },
        sort_keys=True,
    )
    base = {
        "result_id": uuid5(NAMESPACE_URL, identity),
        "scan_id": evidence.scan_id,
        "check_id": CheckId.SESSION_FIXATION,
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
                "Session fixation execution failed before all controls completed."
            ),
        )
    observations = evidence.observations
    authenticated = observations.get("authenticated_control")
    replay = observations.get("original_session_replay")
    anonymous = observations.get("anonymous_control")
    if not all(isinstance(item, dict) for item in (authenticated, replay, anonymous)):
        return CheckResult(
            **base,
            outcome=CheckOutcome.INCONCLUSIVE,
            explanation="Session fixation evidence is missing one or more controls.",
        )
    authenticated = cast(dict[str, Any], authenticated)
    replay = cast(dict[str, Any], replay)
    anonymous = cast(dict[str, Any], anonymous)
    statuses = [item.get("status") for item in (authenticated, replay, anonymous)]
    if any(not isinstance(status, int) for status in statuses):
        return CheckResult(
            **base,
            outcome=CheckOutcome.INCONCLUSIVE,
            explanation="Session fixation controls did not produce usable statuses.",
        )
    status_values = [cast(int, status) for status in statuses]
    if any(status >= 500 for status in status_values):
        return CheckResult(
            **base,
            outcome=CheckOutcome.EXECUTION_ERROR,
            explanation="A session fixation control returned a server error.",
        )
    authenticated_status = cast(int, authenticated["status"])
    replay_status = cast(int, replay["status"])
    if not authenticated.get("marker_present") or authenticated_status != 200:
        outcome = CheckOutcome.INCONCLUSIVE
        explanation = "Authenticated access was not demonstrated by the control."
    elif replay_status == 200 and replay.get("marker_present"):
        outcome = CheckOutcome.FINDING_CONFIRMED
        explanation = (
            "The original pre-login session retained authenticated access after login."
        )
    elif replay_status in {401, 403} and not anonymous.get("marker_present"):
        outcome = CheckOutcome.NO_ISSUE_OBSERVED
        explanation = (
            "The original pre-login session did not authenticate in the isolated "
            "replay."
        )
    else:
        outcome = CheckOutcome.INCONCLUSIVE
        explanation = (
            "The original-session replay could not be distinguished from an "
            "authenticated response."
        )
    captured_at = datetime(1970, 1, 1, tzinfo=UTC)
    try:
        captured_at = datetime.fromisoformat(str(observations["captured_at"]))
    except (KeyError, TypeError, ValueError):
        pass
    return CheckResult(
        **base, outcome=outcome, explanation=explanation, created_at=captured_at
    )
