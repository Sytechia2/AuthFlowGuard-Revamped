"""Bounded native-form enumeration execution and offline evidence analysis.

Registration is deliberately submitted only once per identifier: repeating the
unknown attempt can turn it into a known account. Callers must supply a fresh
disposable identifier and isolate/reset evaluation application state between runs.
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from playwright.async_api import Browser, Page, async_playwright

from authflowguard.action_executor import CONTROL_SELECTOR, BrowserActionExecutor
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
    SecurityPolicy,
    TestRunEvidence,
)
from authflowguard.playwright_worker import PlaywrightWorker
from authflowguard.scope import url_is_in_scope
from authflowguard.secrets import RuntimeSecrets

ANALYSER_VERSION = "1.0"
OWASP_REFERENCE = "WSTG-IDNT-04"
ATTEMPT_TIMEOUT_MS = 5000
FORM_CHECKS = {CheckId.REGISTRATION_ENUMERATION, CheckId.RESET_REQUEST_ENUMERATION}
LABELS = ("known_identifier_attempt", "nonexistent_identifier_attempt")
LIMITATIONS = [
    "One known/nonexistent pair was submitted in separate fresh browser contexts; "
    "timing differences and repeatability beyond this pair were not tested.",
    "Only unambiguous native POST forms reached through an observed registration "
    "or reset link (or an explicit in-scope form URL) are supported.",
    "Dynamic hidden values, labelled tokens, timestamps and UUIDs are normalized; "
    "unrecognized dynamic content can require manual evidence review.",
]


@dataclass(frozen=True)
class FormEnumerationRun:
    evidence: TestRunEvidence
    events: list[EvidenceEvent]


class EnumerationCancelledError(RuntimeError):
    """Execution was cancelled before the next browser action."""


def _check_cancelled(cancel_requested: Callable[[], bool]) -> None:
    if cancel_requested():
        raise EnumerationCancelledError("Enumeration cancelled")


def normalize_response(text: str, sensitive_values: list[str]) -> str:
    """Normalize volatile content in memory; callers persist only its hash."""

    for value in sorted(set(sensitive_values), key=len, reverse=True):
        if value:
            text = text.replace(value, "<redacted>")
    text = re.sub(
        r"(?i)\b(?:csrf(?:[_ -]?token)?|nonce|request[_ -]?id|"
        r"tracking[_ -]?id|timestamp)\s*[:=]\s*[^\s<]+",
        "<dynamic>",
        text,
    )
    text = re.sub(
        r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
        r"(?:Z|[+-]\d{2}:\d{2})?)?\b",
        "<timestamp>",
        text,
    )
    text = re.sub(
        r"(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b",
        "<uuid>",
        text,
    )
    return " ".join(text.split())


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_event(event: EvidenceEvent, check_id: CheckId) -> EvidenceEvent:
    # Executor events contain no bodies/headers, but titles and URL paths may
    # echo arbitrary server-side secrets. Retain only structural event data here.
    safe_keys = {
        "method",
        "resource_type",
        "status",
        "started_at",
        "completed_at",
        "changed",
        "url_changed",
        "title_changed",
        "visible_text_changed",
        "control_state_changed",
        "controls_became_visible",
        "controls_became_hidden",
    }
    return event.model_copy(
        update={
            "check_id": check_id,
            "redacted_details": {
                key: value
                for key, value in event.redacted_details.items()
                if key in safe_keys
            },
        }
    )


async def _find_form_url(page: Page, check_id: CheckId) -> str:
    pattern = (
        r"\b(register|registration|sign\s*up|create\s+(?:an?\s+)?account)\b"
        if check_id is CheckId.REGISTRATION_ENUMERATION
        else r"\b((?:reset|forgot|recover)\s+(?:your\s+)?password|password\s+reset)\b"
    )
    links = page.get_by_role("link", name=re.compile(pattern, re.I))
    destinations: set[str] = set()
    for index in range(await links.count()):
        link = links.nth(index)
        if await link.is_visible():
            href = await link.get_attribute("href")
            if href and not href.startswith("#"):
                destinations.add(urljoin(page.url, href))
    if len(destinations) != 1:
        raise ValueError("No unambiguous form link was observed")
    return destinations.pop()


async def _form_actions(
    page: Page,
    profile: AuthProfile,
    check_id: CheckId,
) -> tuple[list[BrowserAction], str]:
    forms = page.locator("form")
    visible = [i for i in range(await forms.count()) if await forms.nth(i).is_visible()]
    if len(visible) != 1:
        raise ValueError("Expected one visible form")
    form_index = visible[0]
    form = forms.nth(form_index)
    if (await form.get_attribute("method") or "get").lower() != "post":
        raise ValueError("Only native POST forms are supported")
    destination = urljoin(page.url, await form.get_attribute("action") or page.url)
    if not url_is_in_scope(destination, profile.target):
        raise ValueError("Form submission is outside permitted origins")
    controls = await PlaywrightWorker().read_controls(page)
    owned = []
    for index, control in enumerate(controls):
        if control["visible"] and await page.locator(CONTROL_SELECTOR).nth(
            index
        ).evaluate(
            "(element, index) => element.form === document.forms[index]",
            form_index,
        ):
            owned.append(control)
    identifiers = [
        c
        for c in owned
        if c["tag"] == "input"
        and (
            c["type"] == "email"
            or c["autocomplete"] == "username"
            or (c["type"] in {None, "text"} and c["name"] in {"username", "email"})
        )
    ]
    passwords = [c for c in owned if c["tag"] == "input" and c["type"] == "password"]
    submits = [
        c
        for c in owned
        if (
            c["tag"] == "button"
            and c["type"] in {None, "submit"}
            or c["tag"] == "input"
            and c["type"] == "submit"
        )
    ]
    expected_passwords = 1 if check_id is CheckId.REGISTRATION_ENUMERATION else 0
    if (
        len(identifiers) != 1
        or len(passwords) != expected_passwords
        or len(submits) != 1
    ):
        raise ValueError("Form controls are missing or ambiguous")
    actions = [
        BrowserAction(
            action_type=BrowserActionType.FILL,
            observed_control_id=identifiers[0]["observed_control_id"],
            value_reference="identifier",
            description="Fill the comparison identifier",
        )
    ]
    if passwords:
        actions.append(
            BrowserAction(
                action_type=BrowserActionType.FILL,
                observed_control_id=passwords[0]["observed_control_id"],
                value_reference="registration-password",
                description="Fill the disposable password",
            )
        )
    actions.append(
        BrowserAction(
            action_type=BrowserActionType.CLICK,
            observed_control_id=submits[0]["observed_control_id"],
            description="Submit the comparison form",
        )
    )
    return actions, destination


async def _run_attempt(
    *,
    browser: Browser,
    profile: AuthProfile,
    check_id: CheckId,
    scan_id: UUID,
    identifier: str,
    password: str,
    sensitive_values: list[str],
    label: str,
    form_url: str | None,
    events: list[EvidenceEvent],
    attempted: list[str],
    completed: list[str],
    cancel_requested: Callable[[], bool],
) -> dict[str, Any]:
    context = await browser.new_context(service_workers="block")
    secrets = RuntimeSecrets(
        {"identifier": identifier, "registration-password": password}
    )
    try:
        page = await context.new_page()
        page.set_default_timeout(ATTEMPT_TIMEOUT_MS)
        page.set_default_navigation_timeout(ATTEMPT_TIMEOUT_MS)
        executor = BrowserActionExecutor(page, profile.target, secrets, scan_id)

        async def execute(action: BrowserAction, name: str) -> None:
            _check_cancelled(cancel_requested)
            step = f"{label}:{name}"
            attempted.append(step)
            result = await executor.execute(action)
            events.extend(_safe_event(event, check_id) for event in result.events)
            completed.append(step)
            _check_cancelled(cancel_requested)

        if form_url is None:
            login_navigation = next(
                (
                    action
                    for action in profile.authentication_steps.get(
                        AuthFeature.LOGIN, []
                    )
                    if action.action_type is BrowserActionType.NAVIGATE
                ),
                None,
            )
            await execute(
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url=login_navigation.url
                    if login_navigation
                    else profile.target.target_url,
                    description="Observe the page for a form link",
                ),
                "observe-links",
            )
            form_url = await _find_form_url(page, check_id)
        await execute(
            BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=form_url,
                description="Open a fresh comparison form",
            ),
            "open-form",
        )
        actions, destination = await _form_actions(page, profile, check_id)
        # Hidden values are read only for in-memory normalization; the browser
        # submits the fresh CSRF token naturally without replaying it.
        hidden_values = await page.locator('input[type="hidden"]').evaluate_all(
            "elements => elements.map(element => element.value).filter(Boolean)"
        )
        for action in actions[:-1]:
            await execute(action, action.value_reference or "fill")
        async with page.expect_response(
            lambda response: (
                response.request.method == "POST"
                and response.request.is_navigation_request()
                and response.request.frame == page.main_frame
                and response.url == destination
            ),
        ) as submitted:
            async with page.expect_navigation(
                wait_until="domcontentloaded"
            ) as navigated:
                await execute(actions[-1], "submit")
        response = await submitted.value
        final_response = await navigated.value
        allowed = {200, 201, 202, 302, 303}
        if check_id is CheckId.REGISTRATION_ENUMERATION:
            allowed.add(409)
        if response.status not in allowed or final_response is None:
            raise ValueError("Unexpected form response")
        if final_response.status not in allowed:
            raise ValueError("Unexpected final response")
        _check_cancelled(cancel_requested)
        normalized = normalize_response(
            await page.locator("body").inner_text(),
            [*sensitive_values, *hidden_values],
        )
        controls = await page.locator("input, button, select, textarea").evaluate_all(
            """elements => elements.filter(e => e.type !== 'hidden').map(e => ({
                tag: e.tagName.toLowerCase(), type: e.type,
                visible: !!e.getClientRects().length, disabled: !!e.disabled,
                invalid: e.getAttribute('aria-invalid') === 'true',
                valid: e.validity ? e.validity.valid : true
            }))"""
        )
        indicators = sorted(
            name
            for name, pattern in {
                "existing_account": r"already\s+(registered|exists|in use)",
                "unknown_account": r"no account exists|account (?:was )?not found",
                "generic_instructions": (
                    r"if an account exists|check your email|instructions.*sent"
                ),
            }.items()
            if re.search(pattern, normalized, re.I)
        )
        signature = {
            "status_code": response.status,
            "final_status_code": final_response.status,
            "normalized_body_fingerprint": _fingerprint(normalized),
            "title_fingerprint": _fingerprint(
                normalize_response(
                    await page.title(),
                    [*sensitive_values, *hidden_values],
                )
            ),
            "redirect_path_fingerprint": _fingerprint(
                normalize_response(
                    urlsplit(page.url).path,
                    [*sensitive_values, *hidden_values],
                )
            ),
            "control_fingerprint": _fingerprint(json.dumps(controls, sort_keys=True)),
            "safe_visible_messages": indicators,
            "submission_observed": True,
        }
        events.append(
            EvidenceEvent(
                event_id=uuid4(),
                scan_id=scan_id,
                check_id=check_id,
                kind=EvidenceKind.PAGE_STATE,
                summary="Captured a normalized form outcome.",
                redacted_details={"comparison_label": label, "signature": signature},
            )
        )
        return signature
    finally:
        secrets.discard_all()
        await context.close()


async def run_form_enumeration_check(
    *,
    check_id: CheckId,
    profile: AuthProfile,
    scan_id: UUID,
    runtime_secrets: RuntimeSecrets,
    known_identifier_reference: str,
    nonexistent_identifier_reference: str,
    registration_password_reference: str | None = None,
    form_url: str | None = None,
    cancel_requested: Callable[[], bool] = lambda: False,
) -> FormEnumerationRun:
    """Submit each identifier once, recording failures as evidence, never success."""

    if check_id not in FORM_CHECKS:
        raise ValueError("Unsupported form enumeration check")
    events: list[EvidenceEvent] = []
    observations: dict[str, Any] = {"captured_at": datetime.now(UTC).isoformat()}
    attempted: list[str] = []
    completed: list[str] = []
    errors: list[str] = []
    limitations = list(LIMITATIONS)
    if check_id is CheckId.REGISTRATION_ENUMERATION:
        limitations.append(
            "Registration may create the disposable account. Use a new nonexistent "
            "identifier or reset the evaluation application before the next scan."
        )
    try:
        _check_cancelled(cancel_requested)
        known = runtime_secrets.resolve(known_identifier_reference)
        unknown = runtime_secrets.resolve(nonexistent_identifier_reference)
        password = (
            runtime_secrets.resolve(registration_password_reference)
            if registration_password_reference is not None
            else ""
        )
        if not known or not unknown or known == unknown:
            raise ValueError("Distinct nonempty identifiers are required")
        if check_id is CheckId.REGISTRATION_ENUMERATION and not password:
            raise ValueError("A disposable registration password is required")
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                for label, identifier in zip(LABELS, (known, unknown), strict=True):
                    _check_cancelled(cancel_requested)
                    observations[label] = await _run_attempt(
                        browser=browser,
                        profile=profile,
                        check_id=check_id,
                        scan_id=scan_id,
                        identifier=identifier,
                        password=password,
                        sensitive_values=[known, unknown, password],
                        label=label,
                        form_url=form_url,
                        events=events,
                        attempted=attempted,
                        completed=completed,
                        cancel_requested=cancel_requested,
                    )
            finally:
                await browser.close()
    except Exception as error:
        # Exception messages may embed submitted values, token-bearing URLs or HTML.
        errors.append(type(error).__name__)
        events.append(
            EvidenceEvent(
                event_id=uuid4(),
                scan_id=scan_id,
                check_id=check_id,
                kind=EvidenceKind.ERROR,
                summary="Form enumeration did not complete.",
                redacted_details={"error_type": type(error).__name__},
            )
        )
    return FormEnumerationRun(
        evidence=TestRunEvidence(
            evidence_id=uuid4(),
            scan_id=scan_id,
            check_id=check_id,
            profile_version=profile.schema_version,
            event_ids=[e.event_id for e in events],
            observations=observations,
            control_comparisons=["Known versus nonexistent native-form response"]
            if all(label in observations for label in LABELS)
            else [],
            errors=errors,
            coverage=Coverage(
                attempted_steps=attempted,
                completed_steps=completed,
                limitations=limitations,
            ),
        ),
        events=events,
    )


def analyse_form_enumeration(
    evidence: TestRunEvidence,
    profile: AuthProfile,
    policy: SecurityPolicy,
    *,
    check_id: CheckId,
) -> CheckResult:
    """Produce identical results from identical saved evidence and policy, offline."""

    if evidence.check_id is not check_id or check_id not in FORM_CHECKS:
        raise ValueError("Evidence belongs to a different security check")
    name = (
        "Registration"
        if check_id is CheckId.REGISTRATION_ENUMERATION
        else "Reset-request"
    )
    fields = (
        "status_code",
        "final_status_code",
        "normalized_body_fingerprint",
        "title_fingerprint",
        "redirect_path_fingerprint",
        "control_fingerprint",
        "safe_visible_messages",
    )
    known = evidence.observations.get(LABELS[0])
    unknown = evidence.observations.get(LABELS[1])

    def valid(value: Any) -> bool:
        return (
            isinstance(value, dict)
            and value.get("submission_observed") is True
            and all(field in value for field in fields)
            and all(
                type(value[field]) is int and 200 <= value[field] < 600
                for field in fields[:2]
            )
            and all(
                isinstance(value[field], str)
                and re.fullmatch(r"[0-9a-f]{64}", value[field])
                for field in fields[2:6]
            )
            and isinstance(value["safe_visible_messages"], list)
            and all(isinstance(item, str) for item in value["safe_visible_messages"])
        )

    if evidence.errors:
        outcome = CheckOutcome.EXECUTION_ERROR
        explanation = f"{name} comparison failed or was cancelled before completion."
    elif not valid(known) or not valid(unknown):
        outcome = CheckOutcome.INCONCLUSIVE
        explanation = (
            f"{name} evidence lacks two complete, valid submitted-form observations."
        )
    else:
        assert isinstance(known, dict) and isinstance(unknown, dict)
        differences = [field for field in fields if known[field] != unknown[field]]
        allowed = {200, 201, 202, 302, 303}
        if check_id is CheckId.REGISTRATION_ENUMERATION:
            allowed.add(409)
        if any(
            attempt[field] not in allowed
            for attempt in (known, unknown)
            for field in fields[:2]
        ):
            outcome = CheckOutcome.EXECUTION_ERROR
            explanation = f"{name} evidence records an unexpected form response status."
        elif not policy.account_existence_is_private:
            outcome = CheckOutcome.NO_ISSUE_OBSERVED
            explanation = (
                "The configured policy does not require account-existence privacy."
            )
        elif differences:
            outcome = CheckOutcome.FINDING_CONFIRMED
            explanation = (
                f"{name} responses differed between the known and nonexistent "
                "identifier "
                "in the captured pair: " + ", ".join(differences) + "."
            )
        else:
            outcome = CheckOutcome.NO_ISSUE_OBSERVED
            explanation = (
                f"{name} responses had no observable difference in the captured pair."
            )
    identity = json.dumps(
        {
            "evidence": evidence.model_dump(mode="json"),
            "policy": policy.model_dump(),
            "analyser_version": ANALYSER_VERSION,
        },
        sort_keys=True,
    )
    captured_at = datetime(1970, 1, 1, tzinfo=UTC)
    try:
        captured_at = datetime.fromisoformat(evidence.observations["captured_at"])
    except (KeyError, TypeError, ValueError):
        pass
    return CheckResult(
        result_id=uuid5(NAMESPACE_URL, identity),
        scan_id=evidence.scan_id,
        check_id=check_id,
        outcome=outcome,
        owasp_reference=OWASP_REFERENCE,
        analyser_version=ANALYSER_VERSION,
        explanation=explanation,
        evidence_references=[evidence.evidence_id, *evidence.event_ids],
        coverage_limitations=evidence.coverage.limitations,
        created_at=captured_at,
    )
