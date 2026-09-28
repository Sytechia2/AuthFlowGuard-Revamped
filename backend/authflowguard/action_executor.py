"""Validated execution of structured browser actions."""

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID, uuid4

from playwright.async_api import (
    Error as PlaywrightError,
)
from playwright.async_api import (
    Locator,
    Page,
    Request,
    Response,
    Route,
)
from playwright.async_api import (
    TimeoutError as PlaywrightTimeoutError,
)

from authflowguard.cancellation import cancellation_checkpoint
from authflowguard.control_fingerprint import (
    DESCRIBE_CONTROLS_SCRIPT,
    FingerprintMiss,
    fingerprints_by_control,
    fingerprints_for,
    resolve,
)
from authflowguard.control_safety import (
    ControlFacts,
    ControlOutcome,
    ControlRefusal,
    RecordedControlNotFoundError,
    UnsafeControlError,
    activation_refusal,
    fill_refusal,
)
from authflowguard.evidence import publish_completed_events
from authflowguard.models import (
    ActionWaitCondition,
    BrowserAction,
    BrowserActionType,
    ControlFingerprint,
    EvidenceEvent,
    EvidenceKind,
    TargetScope,
    TrafficReference,
)
from authflowguard.page_settling import background_requests_settled, goto_and_settle
from authflowguard.scope import url_is_in_scope, url_without_query_or_fragment
from authflowguard.secrets import RuntimeSecrets

CONTROL_SELECTOR = "input, button, select, textarea, a[href]"

# Reads only nonsecret facts about a control. A text field's value is never
# read: it may already hold a credential. Button-like inputs show their value
# as their label, so theirs is read.
_CONTROL_FACTS_SCRIPT = """element => {
    const rect = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    const tag = element.tagName.toLowerCase();
    const inputType = tag === 'input' ? String(element.type).toLowerCase() : null;
    const parts = [element.getAttribute('aria-label'), element.getAttribute('title')];
    if (tag === 'button' || tag === 'a') {
        parts.push(element.innerText);
    } else if (['button', 'submit', 'reset', 'image'].includes(inputType)) {
        parts.push(element.value, element.getAttribute('alt'));
    }
    return {
        tag,
        input_type: inputType,
        visible: rect.width > 0 && rect.height > 0
            && style.visibility !== 'hidden' && style.visibility !== 'collapse',
        enabled: !element.matches(':disabled')
            && element.getAttribute('aria-disabled') !== 'true',
        read_only: !!element.readOnly,
        label: parts.filter(Boolean).join(' ').slice(0, 500),
    };
}"""


class InvalidControlReferenceError(ValueError):
    """Raised when a recorded control cannot be found on the current page."""


@dataclass(frozen=True)
class PageSnapshot:
    """A nonsecret summary used to compare the page before and after an action."""

    url: str
    title: str
    visible_control_ids: list[str]
    visible_text_fingerprint: str
    control_state_fingerprint: str


@dataclass(frozen=True)
class ObservablePageChanges:
    """Observable differences caused while a browser action was running."""

    url_changed: bool
    title_changed: bool
    visible_text_changed: bool
    control_state_changed: bool
    controls_became_visible: list[str]
    controls_became_hidden: list[str]

    @property
    def changed(self) -> bool:
        return any(
            [
                self.url_changed,
                self.title_changed,
                self.visible_text_changed,
                self.control_state_changed,
                self.controls_became_visible,
                self.controls_became_hidden,
            ]
        )


@dataclass(frozen=True)
class ActionExecutionResult:
    action_id: UUID
    started_at: datetime
    completed_at: datetime
    page_url_before: str
    page_url_after: str
    page_changes: ObservablePageChanges
    events: list[EvidenceEvent]
    traffic: list[TrafficReference]
    # The fingerprint of the control the action resolved to, read just
    # before acting on it. None for an action without a control.
    control_fingerprint: ControlFingerprint | None = None

    def recorded(self, action: BrowserAction) -> BrowserAction:
        """Return ``action`` carrying the fingerprint of the control it used.

        A recorder saves this copy so replays can find the control by what it
        is. An action that already has a fingerprint keeps it: the recorded
        identity, not today's, is what a replay must match.
        """

        if (
            action.control_fingerprint is not None
            or self.control_fingerprint is None
            or action.action_id != self.action_id
        ):
            return action
        return action.model_copy(
            update={"control_fingerprint": self.control_fingerprint}
        )


class BrowserActionExecutor:
    """Execute only the action types defined by the shared contract."""

    # How long a recorded control may take to appear, or to stop matching
    # several controls, before the action is refused. A client-rendered page
    # can still be building its form when the navigation settles.
    CONTROL_LOOKUP_TIMEOUT_SECONDS = 5.0
    CONTROL_LOOKUP_INTERVAL_SECONDS = 0.1

    def __init__(
        self,
        page: Page,
        target: TargetScope,
        secrets: RuntimeSecrets,
        scan_id: UUID,
        *,
        password_references: frozenset[str],
    ) -> None:
        """Bind the executor to one page, scope and set of runtime secrets.

        ``password_references`` names the secret references that hold
        passwords. It is required so that every caller states it: a password
        is typed only into a password field, and a password field receives
        only one of these references. Pass an empty set when the caller never
        fills a password.
        """

        self._page = page
        self._target = target
        self._secrets = secrets
        self._scan_id = scan_id
        self._password_references = frozenset(password_references)
        self._scope_guard_installed = False
        self._resolved_fingerprint: ControlFingerprint | None = None

    async def execute(self, action: BrowserAction) -> ActionExecutionResult:
        cancellation_checkpoint()
        await self._install_scope_guard()
        cancellation_checkpoint()

        if action.action_type is not BrowserActionType.NAVIGATE and not url_is_in_scope(
            self._page.url, self._target
        ):
            raise ValueError("The current page is outside permitted_origins")

        started_at = datetime.now(UTC)
        page_before = await self._take_page_snapshot()
        events: list[EvidenceEvent] = []
        traffic: list[TrafficReference] = []
        request_event_ids: dict[int, UUID] = {}

        def record_request(request: Request) -> None:
            self._record_request(
                request,
                action.action_id,
                events,
                request_event_ids,
            )

        def record_response(response: Response) -> None:
            self._record_response(
                response,
                action.action_id,
                events,
                traffic,
                request_event_ids,
            )

        self._page.on("request", record_request)
        self._page.on("response", record_response)

        self._resolved_fingerprint = None
        try:
            await self._execute_action(action)
        finally:
            self._page.remove_listener("request", record_request)
            self._page.remove_listener("response", record_response)

        cancellation_checkpoint()
        page_after = await self._take_page_snapshot()
        cancellation_checkpoint()
        page_changes = self._compare_page_snapshots(page_before, page_after)
        completed_at = datetime.now(UTC)

        events.append(
            EvidenceEvent(
                event_id=uuid4(),
                scan_id=self._scan_id,
                action_id=action.action_id,
                kind=EvidenceKind.ACTION,
                summary=f"Completed browser action: {action.action_type.value}.",
                redacted_details={
                    "started_at": started_at.isoformat(),
                    "completed_at": completed_at.isoformat(),
                },
            )
        )
        events.append(
            self._make_page_change_event(action.action_id, page_after, page_changes)
        )

        result = ActionExecutionResult(
            action_id=action.action_id,
            started_at=started_at,
            completed_at=completed_at,
            page_url_before=page_before.url,
            page_url_after=page_after.url,
            page_changes=page_changes,
            events=events,
            traffic=traffic,
            control_fingerprint=self._resolved_fingerprint,
        )
        publish_completed_events(result.events)
        return result

    async def _execute_action(self, action: BrowserAction) -> None:
        if action.action_type is BrowserActionType.NAVIGATE:
            await self._navigate(action)
        elif action.action_type is BrowserActionType.CLICK:
            await self._click(action)
        elif action.action_type is BrowserActionType.FILL:
            await self._fill(action)
        elif action.action_type is BrowserActionType.SELECT:
            await self._select(action)
        elif action.action_type is BrowserActionType.PRESS_KEY:
            await self._press_key(action)
        elif action.action_type is BrowserActionType.WAIT:
            await self._wait(action)
        else:
            raise ValueError(f"Unsupported browser action: {action.action_type}")

    def _record_request(
        self,
        request: Request,
        action_id: UUID,
        events: list[EvidenceEvent],
        request_event_ids: dict[int, UUID],
    ) -> None:
        if not url_is_in_scope(request.url, self._target):
            return

        event = EvidenceEvent(
            event_id=uuid4(),
            scan_id=self._scan_id,
            action_id=action_id,
            kind=EvidenceKind.REQUEST,
            summary="The browser sent an in-scope request during an action.",
            redacted_details={
                "url": url_without_query_or_fragment(request.url),
                "method": request.method,
                "resource_type": request.resource_type,
            },
        )
        events.append(event)
        request_event_ids[id(request)] = event.event_id

    def _record_response(
        self,
        response: Response,
        action_id: UUID,
        events: list[EvidenceEvent],
        traffic: list[TrafficReference],
        request_event_ids: dict[int, UUID],
    ) -> None:
        if not url_is_in_scope(response.url, self._target):
            return

        event = EvidenceEvent(
            event_id=uuid4(),
            scan_id=self._scan_id,
            action_id=action_id,
            kind=EvidenceKind.RESPONSE,
            summary="The browser received an in-scope response during an action.",
            redacted_details={
                "url": url_without_query_or_fragment(response.url),
                "status": response.status,
            },
        )
        events.append(event)

        request_event_id = request_event_ids.get(id(response.request))
        if request_event_id is not None:
            traffic.append(
                TrafficReference(
                    request_event_id=request_event_id,
                    response_event_id=event.event_id,
                    authentication_action_id=action_id,
                )
            )

    async def _take_page_snapshot(self) -> PageSnapshot:
        try:
            await self._page.wait_for_load_state(
                "domcontentloaded",
                timeout=3000,
            )
        except PlaywrightTimeoutError:
            # A single-page application may keep work pending after a click;
            # snapshot the current DOM rather than blocking indefinitely.
            pass
        # Read a single DOM revision. Per-control awaits can span a redirect,
        # leaving nth(index) waiting for a control absent from the new page.
        for attempt in range(2):
            try:
                snapshot = await self._page.evaluate(
                    """selector => {
                        const controls = [...document.querySelectorAll(selector)]
                            .map((element, index) => {
                                const rect = element.getBoundingClientRect();
                                const style = getComputedStyle(element);
                                const state = {
                                    observed_control_id: `control-${index + 1}`,
                                    visible: rect.width > 0 && rect.height > 0
                                        && style.visibility !== 'hidden'
                                        && style.visibility !== 'collapse',
                                    disabled: element.matches(':disabled')
                                        || !!element.closest('[aria-disabled="true"]')
                                };
                                if (element.tagName === 'SELECT') {
                                    state.selected_option = element.value;
                                } else if (
                                    ['checkbox', 'radio'].includes(element.type)
                                ) {
                                    state.checked = element.checked;
                                }
                                return state;
                            });
                        return {controls, url: location.href, title: document.title,
                                text: document.body?.innerText ?? ''};
                    }""",
                    CONTROL_SELECTOR,
                )
                break
            except PlaywrightError as error:
                if attempt or "Execution context was destroyed" not in str(error):
                    raise
                await self._page.wait_for_load_state("domcontentloaded", timeout=3000)
        safe_control_states = snapshot["controls"]
        visible_control_ids = [
            state["observed_control_id"]
            for state in safe_control_states
            if state["visible"]
        ]
        visible_text = snapshot["text"]
        normalized_text = " ".join(visible_text.split())
        text_fingerprint = sha256(normalized_text.encode("utf-8")).hexdigest()
        serialized_control_states = json.dumps(
            safe_control_states,
            separators=(",", ":"),
            sort_keys=True,
        )
        control_state_fingerprint = sha256(
            serialized_control_states.encode("utf-8")
        ).hexdigest()

        return PageSnapshot(
            url=url_without_query_or_fragment(snapshot["url"]),
            title=snapshot["title"],
            visible_control_ids=visible_control_ids,
            visible_text_fingerprint=text_fingerprint,
            control_state_fingerprint=control_state_fingerprint,
        )

    def _compare_page_snapshots(
        self,
        before: PageSnapshot,
        after: PageSnapshot,
    ) -> ObservablePageChanges:
        controls_before = set(before.visible_control_ids)
        controls_after = set(after.visible_control_ids)

        return ObservablePageChanges(
            url_changed=before.url != after.url,
            title_changed=before.title != after.title,
            visible_text_changed=(
                before.visible_text_fingerprint != after.visible_text_fingerprint
            ),
            control_state_changed=(
                before.control_state_fingerprint != after.control_state_fingerprint
            ),
            controls_became_visible=sorted(controls_after - controls_before),
            controls_became_hidden=sorted(controls_before - controls_after),
        )

    def _make_page_change_event(
        self,
        action_id: UUID,
        page_after: PageSnapshot,
        changes: ObservablePageChanges,
    ) -> EvidenceEvent:
        return EvidenceEvent(
            event_id=uuid4(),
            scan_id=self._scan_id,
            action_id=action_id,
            kind=EvidenceKind.PAGE_STATE,
            summary="The browser compared the page before and after an action.",
            redacted_details={
                "url": page_after.url,
                "title": page_after.title,
                "changed": changes.changed,
                "url_changed": changes.url_changed,
                "title_changed": changes.title_changed,
                "visible_text_changed": changes.visible_text_changed,
                "control_state_changed": changes.control_state_changed,
                "controls_became_visible": changes.controls_became_visible,
                "controls_became_hidden": changes.controls_became_hidden,
            },
        )

    async def _install_scope_guard(self) -> None:
        if self._scope_guard_installed:
            return

        async def keep_request_inside_scope(route: Route) -> None:
            if url_is_in_scope(route.request.url, self._target):
                await route.continue_()
            else:
                await route.abort("blockedbyclient")

        await self._page.context.route("**/*", keep_request_inside_scope)
        self._scope_guard_installed = True

    async def _navigate(self, action: BrowserAction) -> None:
        destination = str(action.url)
        if not url_is_in_scope(destination, self._target):
            raise ValueError("Navigation destination is outside permitted_origins")

        await goto_and_settle(self._page, destination)

    async def _click(self, action: BrowserAction) -> None:
        control = await self._find_control(action)
        control_id = action.observed_control_id or ""
        facts = await self._require_activatable(
            control, control_id, ControlOutcome.NOT_CLICKED
        )
        async with background_requests_settled(self._page):
            try:
                await control.click()
            except PlaywrightTimeoutError as error:
                raise UnsafeControlError(
                    control_id,
                    ControlRefusal.NOT_CLICKABLE_IN_TIME,
                    ControlOutcome.NOT_CLICKED,
                    facts,
                ) from error
        try:
            await self._page.wait_for_load_state(
                "domcontentloaded",
                timeout=3000,
            )
        except PlaywrightTimeoutError:
            # Most application clicks are AJAX or state-only updates. The
            # timeout is only a guard for navigations that never settle.
            pass

    async def _fill(self, action: BrowserAction) -> None:
        if action.value_reference is None:
            raise ValueError("A fill action requires value_reference")
        control = await self._find_control(action)

        password_value = action.value_reference in self._password_references
        outcome = self._outcome(action)
        control_id = action.observed_control_id or ""
        facts = await self._read_control_facts(control)
        refusal = fill_refusal(facts, password_value=password_value)
        if refusal is ControlRefusal.NOT_VISIBLE:
            await self._wait_until_visible(control, control_id, facts, outcome)
            facts = await self._read_control_facts(control)
            refusal = fill_refusal(facts, password_value=password_value)
        if refusal is ControlRefusal.DISABLED:
            # A form often disables a field until the page is ready for it.
            await self._wait_until_enabled(control, control_id, facts, outcome)
            facts = await self._read_control_facts(control)
            refusal = fill_refusal(facts, password_value=password_value)
        if refusal is not None:
            raise UnsafeControlError(control_id, refusal, outcome, facts)

        # Resolve only after every check passed, so a refused action never
        # holds the live value.
        live_value = self._secrets.resolve(action.value_reference)
        try:
            await control.fill(live_value)
        except PlaywrightError as error:
            # Playwright's message can quote the value being typed, so it is
            # replaced by fixed wording and kept only as the chained cause.
            refusal = (
                ControlRefusal.NOT_EDITABLE_IN_TIME
                if isinstance(error, PlaywrightTimeoutError)
                else ControlRefusal.FILL_FAILED
            )
            raise UnsafeControlError(control_id, refusal, outcome, facts) from error

    async def _select(self, action: BrowserAction) -> None:
        control = await self._find_control(action)
        await control.select_option(action.option_value)

    async def _press_key(self, action: BrowserAction) -> None:
        if action.key is None:
            raise ValueError("A press_key action requires key")

        async with background_requests_settled(self._page):
            if action.observed_control_id is None:
                await self._page.keyboard.press(action.key)
                return

            control = await self._find_control(action)
            control_id = action.observed_control_id
            facts = await self._require_activatable(
                control, control_id, ControlOutcome.KEY_NOT_PRESSED
            )
            try:
                await control.press(action.key)
            except PlaywrightTimeoutError as error:
                raise UnsafeControlError(
                    control_id,
                    ControlRefusal.NO_KEY_RESPONSE_IN_TIME,
                    ControlOutcome.KEY_NOT_PRESSED,
                    facts,
                ) from error

    async def _wait(self, action: BrowserAction) -> None:
        if action.wait_for is None:
            raise ValueError("A wait action requires wait_for")

        if action.wait_for is ActionWaitCondition.CONTROL_VISIBLE:
            control = await self._find_control(action)
            await control.wait_for(state="visible")
            return

        if action.wait_for is ActionWaitCondition.CONTROL_HIDDEN:
            control = await self._find_control(action)
            await control.wait_for(state="hidden")
            return

        if action.wait_for is ActionWaitCondition.LOAD:
            await self._page.wait_for_load_state("load")
        elif action.wait_for is ActionWaitCondition.DOM_CONTENT_LOADED:
            await self._page.wait_for_load_state("domcontentloaded")
        else:
            await self._page.wait_for_load_state("networkidle")

    async def _read_control_facts(self, control: Locator) -> ControlFacts:
        facts = await control.evaluate(_CONTROL_FACTS_SCRIPT)
        return ControlFacts(
            tag=str(facts["tag"]),
            input_type=(
                str(facts["input_type"]) if facts["input_type"] is not None else None
            ),
            visible=bool(facts["visible"]),
            enabled=bool(facts["enabled"]),
            read_only=bool(facts["read_only"]),
            label=str(facts["label"]),
        )

    async def _wait_until_visible(
        self,
        control: Locator,
        control_id: str,
        facts: ControlFacts,
        outcome: ControlOutcome,
    ) -> None:
        """Allow a client-rendered control the page's usual time to appear."""

        try:
            await control.wait_for(state="visible")
        except PlaywrightTimeoutError as error:
            raise UnsafeControlError(
                control_id, ControlRefusal.NOT_VISIBLE, outcome, facts
            ) from error

    async def _wait_until_enabled(
        self,
        control: Locator,
        control_id: str,
        facts: ControlFacts,
        outcome: ControlOutcome,
    ) -> None:
        """Allow a briefly disabled field as long as a hidden one gets to appear.

        The bound is the page's default timeout, the same one the visibility
        wait uses. The caller re-reads the facts afterwards, so every other
        check still runs on the enabled field.
        """

        handle = None
        try:
            handle = await control.element_handle()
            await self._page.wait_for_function(
                """element => !element.matches(':disabled')
                    && element.getAttribute('aria-disabled') !== 'true'""",
                arg=handle,
            )
        except PlaywrightTimeoutError as error:
            raise UnsafeControlError(
                control_id, ControlRefusal.DISABLED, outcome, facts
            ) from error
        finally:
            if handle is not None:
                await handle.dispose()

    async def _require_activatable(
        self,
        control: Locator,
        control_id: str,
        outcome: ControlOutcome,
    ) -> ControlFacts:
        """Refuse to click or send keys to a hidden or destructive control."""

        facts = await self._read_control_facts(control)
        refusal = activation_refusal(facts)
        if refusal is ControlRefusal.NOT_VISIBLE:
            await self._wait_until_visible(control, control_id, facts, outcome)
            facts = await self._read_control_facts(control)
            refusal = activation_refusal(facts)
        if refusal is not None:
            raise UnsafeControlError(control_id, refusal, outcome, facts)
        return facts

    def _outcome(self, action: BrowserAction) -> ControlOutcome:
        """What a refusal of ``action`` leaves undone, as fixed wording."""

        if action.action_type is BrowserActionType.FILL:
            if action.value_reference in self._password_references:
                return ControlOutcome.PASSWORD_NOT_TYPED
            return ControlOutcome.VALUE_NOT_TYPED
        if action.action_type is BrowserActionType.SELECT:
            return ControlOutcome.NOT_SELECTED
        if action.action_type is BrowserActionType.PRESS_KEY:
            return ControlOutcome.KEY_NOT_PRESSED
        if action.action_type is BrowserActionType.WAIT:
            return ControlOutcome.NOT_WAITED_FOR
        return ControlOutcome.NOT_CLICKED

    async def _describe_controls(self) -> list[dict[str, object]]:
        """Describe every addressable control in one DOM revision.

        The locator's own element list is read, so an index here is the
        index ``nth`` addresses.
        """

        for attempt in range(2):
            try:
                descriptions: list[dict[str, object]] = await self._page.locator(
                    CONTROL_SELECTOR
                ).evaluate_all(DESCRIBE_CONTROLS_SCRIPT)
                return descriptions
            except PlaywrightError as error:
                if attempt or "Execution context was destroyed" not in str(error):
                    raise
                await self._page.wait_for_load_state("domcontentloaded", timeout=3000)
        raise AssertionError("unreachable")

    async def control_fingerprints(self) -> dict[str, ControlFingerprint]:
        """Fingerprint every control on the page now, keyed by ``control-N``.

        A caller that builds actions from an observation of the page pins
        them with these, so each action later finds the control it was built
        for even if the page shifts before it runs.
        """

        return fingerprints_by_control(
            await self._describe_controls(), self._secrets.redact_text
        )

    async def _locate(self, action: BrowserAction, timeout_seconds: float) -> int:
        """Return the 0-based index of the action's control on the page.

        An action with a fingerprint is resolved by it (see
        ``control_fingerprint.resolve``), polling for up to
        ``timeout_seconds`` while the page is still rendering. It never falls
        back to the recorded position. An action without one, saved before
        fingerprints existed, is resolved by position and relies on the
        kind checks alone. Either way the resolved control's current
        fingerprint is kept for the result.

        The executor's secrets redact the live attributes exactly as saved
        profiles are redacted, so both sides of the comparison agree.
        """

        control_number = self._parse_control_number(action.observed_control_id)
        recorded = action.control_fingerprint
        redact = self._secrets.redact_text
        if recorded is None:
            descriptions = await self._describe_controls()
            if control_number > len(descriptions):
                raise InvalidControlReferenceError(
                    f"The recorded control '{action.observed_control_id}' "
                    "is no longer present"
                )
            index = control_number - 1
        else:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout_seconds
            while True:
                cancellation_checkpoint()
                descriptions = await self._describe_controls()
                found = resolve(recorded, descriptions, redact)
                if not isinstance(found, FingerprintMiss):
                    index = found
                    break
                if loop.time() >= deadline:
                    raise RecordedControlNotFoundError(
                        action.observed_control_id or "",
                        (
                            ControlRefusal.NOT_ON_PAGE
                            if found is FingerprintMiss.ABSENT
                            else ControlRefusal.AMBIGUOUS_ON_PAGE
                        ),
                        self._outcome(action),
                        recorded=recorded,
                    )
                await asyncio.sleep(self.CONTROL_LOOKUP_INTERVAL_SECONDS)
        self._resolved_fingerprint = fingerprints_for(descriptions, redact)[index]
        return index

    async def _find_control(self, action: BrowserAction) -> Locator:
        index = await self._locate(action, self.CONTROL_LOOKUP_TIMEOUT_SECONDS)
        return self._page.locator(CONTROL_SELECTOR).nth(index)

    async def require_control(self, action: BrowserAction) -> None:
        """Check that the action's control can be found, without acting on it.

        Raises ``RecordedControlNotFoundError`` when a fingerprint does not
        resolve and ``InvalidControlReferenceError`` when a position is not
        on the page.
        """

        await self._locate(action, self.CONTROL_LOOKUP_TIMEOUT_SECONDS)

    async def control_is_available(
        self, action: BrowserAction, timeout_ms: float
    ) -> bool:
        """Whether the action's control is on the page and visible in time.

        Used to notice that a multi-step flow ended early, so a control that
        is missing, ambiguous or hidden gives ``False`` rather than an error.
        """

        if action.observed_control_id is None:
            return True
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_ms / 1000
        if action.control_fingerprint is None:
            number = self._parse_control_number(action.observed_control_id)
            control = self._page.locator(CONTROL_SELECTOR).nth(number - 1)
        else:
            try:
                index = await self._locate(action, timeout_ms / 1000)
            except RecordedControlNotFoundError:
                return False
            control = self._page.locator(CONTROL_SELECTOR).nth(index)
        remaining_ms = max((deadline - loop.time()) * 1000, 1)
        try:
            await control.wait_for(state="visible", timeout=remaining_ms)
        except PlaywrightTimeoutError:
            return False
        return True

    def _parse_control_number(self, observed_control_id: str | None) -> int:
        if observed_control_id is None:
            raise InvalidControlReferenceError("The action does not identify a control")

        prefix = "control-"
        if not observed_control_id.startswith(prefix):
            raise InvalidControlReferenceError(
                f"Invalid observed control reference: '{observed_control_id}'"
            )

        number_text = observed_control_id.removeprefix(prefix)
        if not number_text.isdigit() or int(number_text) < 1:
            raise InvalidControlReferenceError(
                f"Invalid observed control reference: '{observed_control_id}'"
            )

        return int(number_text)
