"""Bounded native-form enumeration execution and offline evidence analysis.

Registration is deliberately submitted only once per identifier: repeating the
unknown attempt can turn it into a known account. Callers must supply a fresh
disposable identifier and isolate/reset evaluation application state between runs.
"""

import asyncio
import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urljoin, urlsplit
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from playwright.async_api import Browser, Page, Request, Response, async_playwright
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

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
from authflowguard.page_settling import (
    BACKGROUND_REQUEST_TIMEOUT_SECONDS,
    QUIET_WINDOW_SECONDS,
)
from authflowguard.playwright_worker import (
    PlaywrightWorker,
    SafeControlDescription,
)
from authflowguard.scope import url_is_in_scope, url_without_query_keeping_route
from authflowguard.secrets import RuntimeSecrets

ANALYSER_VERSION = "1.0"
OWASP_REFERENCE = "WSTG-IDNT-04"
ATTEMPT_TIMEOUT_MS = 5000
FORM_CHECKS = {CheckId.REGISTRATION_ENUMERATION, CheckId.RESET_REQUEST_ENUMERATION}
LABELS = ("known_identifier_attempt", "nonexistent_identifier_attempt")
# A client-rendered form is also exercised with a second nonexistent
# identifier. Whatever differs between the two nonexistent attempts is
# volatile content, not account state, and cannot support a finding.
REPEAT_LABEL = "repeat_nonexistent_identifier_attempt"
REPEAT_LIMITATION = (
    "The client-rendered form was also exercised with a second nonexistent "
    "identifier; fields that differed between the two nonexistent attempts "
    "were treated as volatile and not used as evidence of enumeration."
)
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


def _repeat_identifier(identifier: str) -> str:
    """Derive a second nonexistent identifier shaped like the first."""

    local, at, domain = identifier.rpartition("@")
    if at:
        return f"{local}-repeat@{domain}"
    return f"{identifier}-repeat"


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


def _safe_visible_messages(normalized: str) -> list[str]:
    return sorted(
        name
        for name, pattern in {
            "existing_account": r"already\s+(registered|exists|in use)|must be unique",
            "unknown_account": r"no account exists|account (?:was )?not found",
            "generic_instructions": (
                r"if an account exists|check your email|instructions.*sent"
            ),
        }.items()
        if re.search(pattern, normalized, re.I)
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
            if href and (not href.startswith("#") or href.startswith("#/")):
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


FORM_FILLER = "AuthFlowGuard evaluation"
IDENTIFIER_LOOKUP_WINDOW_SECONDS = 2.0
IDENTIFIER_HINT = re.compile(r"e-?mail|user\s*name|username|login", re.I)
FILLABLE_INPUT_TYPES = {None, "text", "email", "tel", "url", "search"}
CLIENT_STATE_FIELDS = (
    "background_responses",
    "visible_text_fingerprint",
    "title_fingerprint",
    "route_fingerprint",
    "control_fingerprint",
)


def _is_identifier_control(control: SafeControlDescription) -> bool:
    if control["tag"] != "input" or control["type"] not in FILLABLE_INPUT_TYPES:
        return False
    if control["type"] == "email" or control["autocomplete"] in {"username", "email"}:
        return True
    hints = " ".join(
        value or ""
        for value in (
            control["name"],
            control["id"],
            control["aria_label"],
            control["placeholder"],
        )
    )
    return bool(IDENTIFIER_HINT.search(hints))


class _IdentifierResponses:
    """Background responses to requests that carry the identifier.

    Requests that do not carry the identifier (polling, analytics, assets) are
    ignored so unrelated traffic cannot create a difference. Bodies are read
    in memory and only normalized fingerprints are kept.
    """

    def __init__(self, page: Page, identifier: str) -> None:
        self._page = page
        self._markers = {identifier, quote(identifier), quote(identifier, safe="")}
        self._responses: list[Response] = []
        self._pending: set[Request] = set()
        self._started = 0

    def __enter__(self) -> "_IdentifierResponses":
        self._page.on("request", self._started_request)
        self._page.on("requestfinished", self._finished_request)
        self._page.on("requestfailed", self._finished_request)
        self._page.on("response", self._record)
        return self

    def __exit__(self, *_: object) -> None:
        self._page.remove_listener("request", self._started_request)
        self._page.remove_listener("requestfinished", self._finished_request)
        self._page.remove_listener("requestfailed", self._finished_request)
        self._page.remove_listener("response", self._record)

    def _carries_identifier(self, request: Request) -> bool:
        if request.resource_type not in {"fetch", "xhr"}:
            return False
        carried = f"{request.url} {request.post_data or ''}"
        return any(marker in carried for marker in self._markers)

    def _started_request(self, request: Request) -> None:
        if self._carries_identifier(request):
            self._pending.add(request)
            self._started += 1

    def _finished_request(self, request: Request) -> None:
        self._pending.discard(request)

    def _record(self, response: Response) -> None:
        if self._carries_identifier(response.request):
            self._responses.append(response)

    async def settle(self, lookup_window: float) -> None:
        """Wait for identifier requests, including debounced lookups.

        Many forms look an identifier up only after typing pauses. Wait up to
        lookup_window for such a request to start, then for all of them to
        finish, bounded overall.
        """

        loop = asyncio.get_running_loop()
        start_deadline = loop.time() + lookup_window
        deadline = start_deadline + BACKGROUND_REQUEST_TIMEOUT_SECONDS
        while loop.time() < deadline:
            if not self._pending and (self._started or loop.time() >= start_deadline):
                break
            await asyncio.sleep(0.05)
        # Let the page render the response it just received.
        await asyncio.sleep(QUIET_WINDOW_SECONDS)

    def take(self) -> list[Response]:
        taken, self._responses = self._responses, []
        self._started = 0
        return taken


def _normalize_body(body: str, sensitive_values: list[str]) -> str:
    """Normalize a background response body, keeping its meaning.

    JSON keeps its keys, booleans, nulls and normalized text; every number
    becomes a placeholder, because record ids and counters differ between any
    two requests. A body that is not JSON is normalized as text.
    """

    def normalize(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, int | float):
            return "<number>"
        return normalize_response(str(value), sensitive_values)

    try:
        parsed = json.loads(body)
    except ValueError:
        return normalize_response(body, sensitive_values)
    return json.dumps(normalize(parsed), sort_keys=True)


async def _response_summaries(
    responses: list[Response], sensitive_values: list[str]
) -> list[list[Any]]:
    summaries = []
    for response in responses:
        try:
            body = await response.text()
        except PlaywrightError:
            body = ""
        summaries.append(
            [
                response.request.method,
                _fingerprint(
                    normalize_response(urlsplit(response.url).path, sensitive_values)
                ),
                response.status,
                _fingerprint(_normalize_body(body, sensitive_values)),
            ]
        )
    return sorted(summaries)


async def _client_page_state(
    page: Page, responses: list[Response], sensitive_values: list[str]
) -> dict[str, Any]:
    controls = await page.locator(CONTROL_SELECTOR).evaluate_all(
        """elements => elements.filter(e => e.type !== 'hidden').map(e => ({
            tag: e.tagName.toLowerCase(), type: e.type,
            visible: !!e.getClientRects().length, disabled: !!e.disabled,
            invalid: e.getAttribute('aria-invalid') === 'true'
        }))"""
    )
    return {
        "background_responses": await _response_summaries(responses, sensitive_values),
        "visible_text_fingerprint": _fingerprint(
            normalize_response(
                await page.locator("body").inner_text(), sensitive_values
            )
        ),
        "title_fingerprint": _fingerprint(
            normalize_response(await page.title(), sensitive_values)
        ),
        "route_fingerprint": _fingerprint(
            normalize_response(
                url_without_query_keeping_route(page.url), sensitive_values
            )
        ),
        "control_fingerprint": _fingerprint(json.dumps(controls, sort_keys=True)),
    }


async def _complete_registration_fields(
    page: Page,
    controls: list[SafeControlDescription],
    identifier_index: int,
    execute: Callable[[BrowserAction, str], Awaitable[None]],
) -> None:
    """Fill the rest of the identifier's form with disposable values."""

    elements = page.locator(CONTROL_SELECTOR)
    identifier_element = elements.nth(identifier_index)
    identifier_form = await identifier_element.evaluate_handle("e => e.form")
    for index, control in enumerate(controls):
        if index == identifier_index or not control["visible"]:
            continue
        element = elements.nth(index)
        same_form = await element.evaluate(
            "(element, form) => !!form && element.form === form", identifier_form
        )
        if not same_form or control["value_present"] or not await element.is_enabled():
            continue
        if control["tag"] == "input" and control["type"] == "password":
            reference = "registration-password"
        elif control["tag"] == "input" and control["type"] in FILLABLE_INPUT_TYPES:
            reference = "form-filler"
        else:
            continue
        await execute(
            BrowserAction(
                action_type=BrowserActionType.FILL,
                observed_control_id=control["observed_control_id"],
                value_reference=reference,
                description="Fill a required registration field",
            ),
            reference,
        )
    # Choose the first option of each unset dropdown in the same form. Custom
    # dropdowns are comboboxes that are not native <select> elements.
    form = identifier_element.locator("xpath=ancestor::form[1]")
    selects = form.locator("select")
    for index in range(await selects.count()):
        select = selects.nth(index)
        if await select.is_visible() and not await select.input_value():
            values = await select.locator("option").evaluate_all(
                "options => options.map(o => o.value).filter(Boolean)"
            )
            if values:
                await select.select_option(values[0])
    comboboxes = form.locator('[role="combobox"]:not(input):not(select)')
    for index in range(await comboboxes.count()):
        combobox = comboboxes.nth(index)
        if not await combobox.is_visible():
            continue
        # Open it from the keyboard, as accessible comboboxes support; a
        # pointer click can be intercepted by a floating label.
        await combobox.focus()
        await page.keyboard.press("Enter")
        option = page.locator('[role="option"]:visible').first
        try:
            await option.wait_for(timeout=2000)
        except PlaywrightTimeoutError:
            await page.keyboard.press("Escape")
            continue
        await option.click()


async def _client_form_attempt(
    *,
    page: Page,
    check_id: CheckId,
    identifier: str,
    sensitive_values: list[str],
    execute: Callable[[BrowserAction, str], Awaitable[None]],
) -> dict[str, Any]:
    """Compare how a client-rendered form reacts to one identifier.

    The identifier is entered and the page's reaction recorded, because many
    single-page apps look the identifier up before anything is submitted.
    Registration then completes the form with disposable values and submits
    it. Reset forms are never submitted here: completing one could change a
    real account's password.
    """

    controls = await PlaywrightWorker().read_controls(page)
    candidates = [
        index
        for index, control in enumerate(controls)
        if control["visible"] and _is_identifier_control(control)
    ]
    if len(candidates) != 1:
        raise ValueError("Form controls are missing or ambiguous")
    identifier_index = candidates[0]
    identifier_id = controls[identifier_index]["observed_control_id"]

    with _IdentifierResponses(page, identifier) as responses:
        await execute(
            BrowserAction(
                action_type=BrowserActionType.FILL,
                observed_control_id=identifier_id,
                value_reference="identifier",
                description="Fill the comparison identifier",
            ),
            "identifier",
        )
        await execute(
            BrowserAction(
                action_type=BrowserActionType.PRESS_KEY,
                observed_control_id=identifier_id,
                key="Tab",
                description="Leave the identifier field",
            ),
            "leave-identifier",
        )
        await responses.settle(IDENTIFIER_LOOKUP_WINDOW_SECONDS)
        reaction = await _client_page_state(page, responses.take(), sensitive_values)

        submission: dict[str, Any] | None = None
        if check_id is CheckId.REGISTRATION_ENUMERATION:
            await _complete_registration_fields(
                page, controls, identifier_index, execute
            )
            current = await PlaywrightWorker().read_controls(page)
            submits = [
                control
                for control in current
                if control["visible"]
                and control["tag"] in {"button", "input"}
                and control["type"] == "submit"
            ]
            if len(submits) != 1:
                raise ValueError("Form controls are missing or ambiguous")
            submit_id = submits[0]["observed_control_id"]
            submit = page.locator(CONTROL_SELECTOR).nth(
                int(submit_id.removeprefix("control-")) - 1
            )
            if await submit.is_enabled():
                await execute(
                    BrowserAction(
                        action_type=BrowserActionType.CLICK,
                        observed_control_id=submit_id,
                        description="Submit the comparison form",
                    ),
                    "submit",
                )
                await responses.settle(0)
                submission = await _client_page_state(
                    page, responses.take(), sensitive_values
                )

    visible_text = normalize_response(
        await page.locator("body").inner_text(), sensitive_values
    )
    return {
        "interaction": "client",
        "reaction": reaction,
        "submission_observed": submission is not None,
        "submission": submission,
        "safe_visible_messages": _safe_visible_messages(visible_text),
    }


async def _has_native_post_form(page: Page) -> bool:
    forms = page.locator("form")
    methods = [
        (await forms.nth(index).get_attribute("method") or "get").lower()
        for index in range(await forms.count())
        if await forms.nth(index).is_visible()
    ]
    return methods == ["post"]


async def _native_form_attempt(
    *,
    page: Page,
    profile: AuthProfile,
    check_id: CheckId,
    sensitive_values: list[str],
    execute: Callable[[BrowserAction, str], Awaitable[None]],
    cancel_requested: Callable[[], bool],
) -> dict[str, Any]:
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
        async with page.expect_navigation(wait_until="domcontentloaded") as navigated:
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
    indicators = _safe_visible_messages(normalized)
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
    return signature


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
        {
            "identifier": identifier,
            "registration-password": password,
            "form-filler": FORM_FILLER,
        }
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
        if await _has_native_post_form(page):
            signature = await _native_form_attempt(
                page=page,
                profile=profile,
                check_id=check_id,
                sensitive_values=sensitive_values,
                execute=execute,
                cancel_requested=cancel_requested,
            )
        else:
            signature = await _client_form_attempt(
                page=page,
                check_id=check_id,
                identifier=identifier,
                sensitive_values=sensitive_values,
                execute=execute,
            )
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
            "Registration may create the disposable account (and, for a "
            "client-rendered form, a second one with '-repeat' added to its "
            "identifier). Use a new nonexistent identifier or reset the "
            "evaluation application before the next scan."
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
        repeat = _repeat_identifier(unknown)
        if repeat == known:
            raise ValueError("Distinct nonempty identifiers are required")
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)

            async def attempt(label: str, identifier: str) -> None:
                _check_cancelled(cancel_requested)
                observations[label] = await _run_attempt(
                    browser=browser,
                    profile=profile,
                    check_id=check_id,
                    scan_id=scan_id,
                    identifier=identifier,
                    password=password,
                    sensitive_values=[known, unknown, repeat, password],
                    label=label,
                    form_url=form_url,
                    events=events,
                    attempted=attempted,
                    completed=completed,
                    cancel_requested=cancel_requested,
                )

            try:
                for label, identifier in zip(LABELS, (known, unknown), strict=True):
                    await attempt(label, identifier)
                if observations[LABELS[1]].get("interaction") == "client":
                    limitations.append(REPEAT_LIMITATION)
                    await attempt(REPEAT_LABEL, repeat)
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


def _valid_client_state(state: Any) -> bool:
    return (
        isinstance(state, dict)
        and all(field in state for field in CLIENT_STATE_FIELDS)
        and isinstance(state["background_responses"], list)
        and all(
            isinstance(item, list)
            and len(item) == 4
            and type(item[2]) is int
            and 100 <= item[2] < 600
            for item in state["background_responses"]
        )
        and all(
            isinstance(state[field], str)
            and re.fullmatch(r"[0-9a-f]{64}", state[field])
            for field in CLIENT_STATE_FIELDS[1:]
        )
    )


def _valid_client_signature(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("interaction") == "client"
        and _valid_client_state(value.get("reaction"))
        and isinstance(value.get("submission_observed"), bool)
        and (
            _valid_client_state(value.get("submission"))
            if value.get("submission_observed")
            else value.get("submission") is None
        )
        and isinstance(value.get("safe_visible_messages"), list)
    )


def _client_statuses(signature: dict[str, Any]) -> list[int]:
    states = [signature["reaction"], signature.get("submission") or {}]
    return [
        item[2] for state in states for item in state.get("background_responses", [])
    ]


CLIENT_COMPARED_FIELDS = ("background_statuses", *CLIENT_STATE_FIELDS)


def _client_state_views(state: Any) -> dict[str, Any]:
    """The compared views of one client state.

    Request outcomes (method, path, status) are also compared without their
    bodies, so a volatile body cannot hide a status difference.
    """

    if not isinstance(state, dict):
        return {}
    return {
        "background_statuses": sorted(
            item[:3] for item in state["background_responses"]
        ),
        **{field: state[field] for field in CLIENT_STATE_FIELDS},
    }


def _client_differences(first: dict[str, Any], second: dict[str, Any]) -> list[str]:
    differences: list[str] = []
    for stage in ("reaction", "submission"):
        first_views = _client_state_views(first.get(stage))
        second_views = _client_state_views(second.get(stage))
        differences.extend(
            f"{stage}.{field}"
            for field in CLIENT_COMPARED_FIELDS
            if first_views.get(field) != second_views.get(field)
        )
    differences.extend(
        field
        for field in ("submission_observed", "safe_visible_messages")
        if first[field] != second[field]
    )
    return differences


def _analyse_client_forms(
    known: dict[str, Any],
    unknown: dict[str, Any],
    repeat: Any,
    check_id: CheckId,
    policy: SecurityPolicy,
    name: str,
) -> tuple[CheckOutcome, str]:
    """Compare two client-rendered form attempts.

    Identical observations only count as "no issue" when the procedure
    demonstrably exercised the form; otherwise nothing was compared. When a
    repeat nonexistent-identifier attempt was recorded, only differences that
    did not also appear between the two nonexistent attempts count. Evidence
    captured before the repeat attempt existed is compared as a single pair.
    """

    if repeat is not None and not _valid_client_signature(repeat):
        return (
            CheckOutcome.INCONCLUSIVE,
            f"{name} evidence has an invalid repeat nonexistent-identifier attempt.",
        )
    attempts = [known, unknown, *([repeat] if repeat is not None else [])]
    if any(status >= 500 for sig in attempts for status in _client_statuses(sig)):
        return (
            CheckOutcome.EXECUTION_ERROR,
            f"{name} evidence records a server error from the application.",
        )
    if check_id is CheckId.REGISTRATION_ENUMERATION:
        accepted = unknown["submission_observed"] and any(
            200 <= item[2] < 300
            for item in unknown["submission"]["background_responses"]
        )
        if not accepted:
            return (
                CheckOutcome.INCONCLUSIVE,
                "The disposable registration was not accepted, so a difference "
                "cannot be attributed to account existence.",
            )
    elif not all(
        sig["reaction"]["background_responses"] or sig["submission_observed"]
        for sig in (known, unknown)
    ):
        return (
            CheckOutcome.INCONCLUSIVE,
            f"The {name.lower()} form did not react to the identifier, so nothing "
            "was compared.",
        )
    if not policy.account_existence_is_private:
        return (
            CheckOutcome.NO_ISSUE_OBSERVED,
            "The configured policy does not require account-existence privacy.",
        )
    differences = _client_differences(known, unknown)
    if repeat is not None:
        volatile = set(_client_differences(unknown, repeat))
        stable = [field for field in differences if field not in volatile]
        if differences and not stable:
            return (
                CheckOutcome.INCONCLUSIVE,
                f"{name} responses differed between the known and nonexistent "
                "identifier only in " + ", ".join(differences) + ", which also "
                "differed between two nonexistent identifiers, so the difference "
                "cannot be attributed to account existence.",
            )
        differences = stable
    if differences:
        return (
            CheckOutcome.FINDING_CONFIRMED,
            f"{name} responses differed between the known and nonexistent "
            "identifier in the captured pair: " + ", ".join(differences) + ".",
        )
    return (
        CheckOutcome.NO_ISSUE_OBSERVED,
        f"{name} responses had no observable difference in the captured pair.",
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
    repeat = evidence.observations.get(REPEAT_LABEL)

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
    elif _valid_client_signature(known) and _valid_client_signature(unknown):
        assert isinstance(known, dict) and isinstance(unknown, dict)
        outcome, explanation = _analyse_client_forms(
            known, unknown, repeat, check_id, policy, name
        )
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
