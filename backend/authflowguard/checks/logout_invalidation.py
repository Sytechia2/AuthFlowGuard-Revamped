"""CHK-006: logout invalidation with replay of the captured session."""

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
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
    replay_rejected,
    replay_server_error,
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
from authflowguard.page_settling import background_requests_settled, goto_and_settle
from authflowguard.secrets import RuntimeSecrets

OWASP_REFERENCE = "WSTG-SESS-06"
ANALYSER_VERSION = "1.0"


class LogoutInvalidationRun:
    def __init__(self, evidence: TestRunEvidence, events: list[EvidenceEvent]):
        self.evidence = evidence
        self.events = events


LOGOUT_LABEL = re.compile(r"\b(log|sign)\s*-?\s*(out|off)\b", re.IGNORECASE)
LOGOUT_URL = re.compile(r"(log|sign)[-_]?(out|off)", re.IGNORECASE)
MENU_LABEL = re.compile(r"account|user|profile|menu", re.IGNORECASE)
CLICKABLE = 'button, a[href], [role="button"], [role="menuitem"]'
MENU_TOGGLE = f'{CLICKABLE}, [aria-haspopup="true"], [aria-haspopup="menu"]'
MAX_MENU_TOGGLES = 3


@dataclass
class LogoutAttempt:
    """How logout was performed and what the server was told."""

    method: str
    status: int | None
    request_observed: bool


async def _submit_logout_form(page: Any) -> LogoutAttempt | None:
    forms = page.locator("form")
    for index in range(await forms.count()):
        form = forms.nth(index)
        action = (await form.get_attribute("action") or "").lower()
        text = (await form.inner_text()).lower()
        if "logout" not in action and "log out" not in text and "logout" not in text:
            continue
        submit = form.locator('button, input[type="submit"]').first
        if await submit.count() == 0:
            continue
        async with page.expect_response(
            lambda item: item.request.method.upper() == "POST", timeout=5000
        ) as response_info:
            await submit.click()
        response = await response_info.value
        return LogoutAttempt(
            method="form",
            status=response.status if response is not None else None,
            request_observed=True,
        )
    return None


async def _control_label(control: Any) -> str:
    parts = await control.evaluate(
        """element => [element.innerText, element.getAttribute('aria-label'),
                       element.getAttribute('title'), element.id]"""
    )
    return " ".join(part for part in parts if part)


async def _find_visible_control(
    page: Any, selector: str, label: re.Pattern[str]
) -> Any:
    controls = page.locator(selector)
    for index in range(await controls.count()):
        control = controls.nth(index)
        if await control.is_visible() and label.search(await _control_label(control)):
            return control
    return None


async def _find_logout_control(page: Any) -> Any:
    control = await _find_visible_control(page, CLICKABLE, LOGOUT_LABEL)
    if control is not None:
        return control
    # Single-page apps often keep logout inside an account menu.
    toggles = page.locator(MENU_TOGGLE)
    opened = 0
    for index in range(await toggles.count()):
        if opened >= MAX_MENU_TOGGLES:
            break
        toggle = toggles.nth(index)
        if not await toggle.is_visible():
            continue
        if not MENU_LABEL.search(await _control_label(toggle)):
            continue
        await toggle.click()
        opened += 1
        await page.wait_for_timeout(300)
        control = await _find_visible_control(page, CLICKABLE, LOGOUT_LABEL)
        if control is not None:
            return control
        await page.keyboard.press("Escape")
    return None


async def _click_logout_control(page: Any, app_url: str) -> LogoutAttempt | None:
    control = await _find_logout_control(page)
    if control is None and page.url.split("#", 1)[0] != app_url.split("#", 1)[0]:
        # The protected resource may be a page without the app's navigation.
        await goto_and_settle(page, app_url)
        control = await _find_logout_control(page)
    if control is None:
        return None

    statuses: list[int] = []

    def record(response: Any) -> None:
        request = response.request
        if request.method.upper() != "GET" or LOGOUT_URL.search(request.url):
            statuses.append(response.status)

    page.on("response", record)
    try:
        async with background_requests_settled(page):
            await control.click()
    finally:
        page.remove_listener("response", record)
    return LogoutAttempt(
        method="control",
        status=statuses[-1] if statuses else None,
        request_observed=bool(statuses),
    )


async def _submit_logout(page: Any, app_url: str) -> LogoutAttempt:
    attempt = await _submit_logout_form(page)
    if attempt is None:
        attempt = await _click_logout_control(page, app_url)
    if attempt is None:
        raise ValueError("The application has no identifiable logout control")
    return attempt


async def run_logout_invalidation_check(
    *,
    profile: AuthProfile,
    scan_id: UUID,
    runtime_secrets: RuntimeSecrets,
    username_reference: str,
    password_reference: str,
    protected_resource: str,
    account_marker_selector: str,
    cancel_requested: Callable[[], bool] = lambda: False,
) -> LogoutInvalidationRun:
    steps = adapt_login_steps(
        login_steps_for(profile), username_reference, password_reference
    )
    if not protected_resource or not account_marker_selector:
        raise ValueError("Logout invalidation requires a protected resource and marker")
    events: list[EvidenceEvent] = []
    attempted_steps = ["complete_login", "capture_session", "submit_logout"]
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
                    await execute_login_steps(
                        page=page,
                        profile=profile,
                        scan_id=scan_id,
                        steps=steps,
                        secrets=runtime_secrets,
                        events=events,
                        check_id=CheckId.LOGOUT_INVALIDATION,
                        cancel_requested=cancel_requested,
                    )
                    authenticated = await protected_state(
                        page, protected_resource, account_marker_selector
                    )
                    observations["authenticated_control"] = authenticated
                    completed_steps.append("complete_login")
                    old_cookies = await context.cookies()
                    observations["active_session"] = cookie_snapshot(old_cookies)
                    completed_steps.append("capture_session")
                    logout = await _submit_logout(page, str(profile.target.target_url))
                    logout_status = logout.status
                    observations["logout_status"] = logout_status
                    observations["logout_method"] = logout.method
                    observations["logout_request_observed"] = logout.request_observed
                    after_logout = await protected_state(
                        page, protected_resource, account_marker_selector
                    )
                    observations["post_logout_control"] = after_logout
                    completed_steps.append("submit_logout")
                    events.append(
                        check_event(
                            scan_id,
                            CheckId.LOGOUT_INVALIDATION,
                            EvidenceKind.PAGE_STATE,
                            "Captured authenticated, logout, and post-logout states.",
                            phase="post_logout_control",
                            status=after_logout["status"],
                            marker_present=after_logout["marker_present"],
                            logout_status=logout_status,
                        )
                    )
                finally:
                    await context.close()

                replay_context = await browser.new_context(service_workers="block")
                try:
                    await replay_context.add_cookies(cast(Any, old_cookies))
                    replay_page = await replay_context.new_page()
                    replay = await protected_state(
                        replay_page, protected_resource, account_marker_selector
                    )
                    observations["old_session_replay"] = replay
                    events.append(
                        check_event(
                            scan_id,
                            CheckId.LOGOUT_INVALIDATION,
                            EvidenceKind.PAGE_STATE,
                            "Replayed the captured pre-logout session in isolation.",
                            phase="old_session_replay",
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
                            CheckId.LOGOUT_INVALIDATION,
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
                CheckId.LOGOUT_INVALIDATION,
                EvidenceKind.ERROR,
                "Logout invalidation execution did not complete.",
                error_types=errors,
            )
        )
    evidence = TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=scan_id,
        check_id=CheckId.LOGOUT_INVALIDATION,
        profile_version=profile.schema_version,
        event_ids=[event.event_id for event in events],
        observations={**observations, "captured_at": datetime.now(UTC).isoformat()},
        control_comparisons=[
            "Authenticated, post-logout, old-session replay, and anonymous "
            "controls were compared."
        ]
        if not errors
        else [],
        errors=errors,
        coverage=Coverage(
            attempted_steps=attempted_steps,
            completed_steps=completed_steps,
            limitations=[
                "The replay uses only browser cookie state captured before logout.",
                "Bearer tokens held outside browser cookie storage are not "
                "replayed by this check.",
            ],
        ),
    )
    return LogoutInvalidationRun(evidence=evidence, events=events)


def _client_side_logout_demonstrated(observations: dict[str, Any]) -> bool:
    """Logout by a control that sent no request, proven by a signed-out page.

    Only a positive record from the runner counts: evidence that merely lacks
    a logout status stays inconclusive.
    """

    post_logout = observations.get("post_logout_control")
    return (
        observations.get("logout_method") == "control"
        and observations.get("logout_request_observed") is False
        and isinstance(post_logout, dict)
        and isinstance(post_logout.get("status"), int)
        and post_logout.get("marker_present") is False
    )


def analyse_logout_invalidation(
    evidence: TestRunEvidence, profile: AuthProfile, policy: SecurityPolicy
) -> CheckResult:
    del profile, policy
    if evidence.check_id is not CheckId.LOGOUT_INVALIDATION:
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
        "check_id": CheckId.LOGOUT_INVALIDATION,
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
                "Logout invalidation execution failed before all controls completed."
            ),
        )
    observations = evidence.observations
    authenticated = observations.get("authenticated_control")
    replay = observations.get("old_session_replay")
    anonymous = observations.get("anonymous_control")
    if not all(isinstance(item, dict) for item in (authenticated, replay, anonymous)):
        return CheckResult(
            **base,
            outcome=CheckOutcome.INCONCLUSIVE,
            explanation="Logout evidence is missing one or more controls.",
        )
    authenticated = cast(dict[str, Any], authenticated)
    replay = cast(dict[str, Any], replay)
    anonymous = cast(dict[str, Any], anonymous)
    statuses = [item.get("status") for item in (authenticated, replay, anonymous)]
    logout_status = observations.get("logout_status")
    client_side_logout = _client_side_logout_demonstrated(observations)
    if (not isinstance(logout_status, int) and not client_side_logout) or any(
        not isinstance(status, int) for status in statuses
    ):
        return CheckResult(
            **base,
            outcome=CheckOutcome.INCONCLUSIVE,
            explanation="Logout controls did not produce usable statuses.",
        )
    if (isinstance(logout_status, int) and logout_status >= 500) or (
        replay_server_error(authenticated, replay, anonymous)
    ):
        return CheckResult(
            **base,
            outcome=CheckOutcome.EXECUTION_ERROR,
            explanation="A logout control returned a server error.",
        )
    authenticated_status = cast(int, authenticated["status"])
    replay_status = cast(int, replay["status"])
    if authenticated_status != 200 or not authenticated.get("marker_present"):
        outcome = CheckOutcome.INCONCLUSIVE
        explanation = "Authenticated access was not demonstrated before logout."
    elif replay_status == 200 and replay.get("marker_present"):
        outcome = CheckOutcome.FINDING_CONFIRMED
        explanation = "The captured session retained authenticated access after logout."
        if client_side_logout:
            explanation += (
                " Logout sent no request to the server; it only cleared state in "
                "the browser."
            )
    elif replay_rejected(replay, anonymous):
        outcome = CheckOutcome.NO_ISSUE_OBSERVED
        explanation = (
            "The captured session was rejected after logout, matching the "
            "anonymous control."
        )
    else:
        outcome = CheckOutcome.INCONCLUSIVE
        explanation = (
            "The old-session replay could not be distinguished from an "
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
