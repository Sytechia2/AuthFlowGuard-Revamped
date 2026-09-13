"""Validated execution of structured browser actions."""

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

from authflowguard.models import (
    ActionWaitCondition,
    BrowserAction,
    BrowserActionType,
    EvidenceEvent,
    EvidenceKind,
    TargetScope,
    TrafficReference,
)
from authflowguard.scope import url_is_in_scope, url_without_query_or_fragment
from authflowguard.secrets import RuntimeSecrets

CONTROL_SELECTOR = "input, button, select, textarea, a[href]"


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


class BrowserActionExecutor:
    """Execute only the action types defined by the shared contract."""

    def __init__(
        self,
        page: Page,
        target: TargetScope,
        secrets: RuntimeSecrets,
        scan_id: UUID,
    ) -> None:
        self._page = page
        self._target = target
        self._secrets = secrets
        self._scan_id = scan_id
        self._scope_guard_installed = False

    async def execute(self, action: BrowserAction) -> ActionExecutionResult:
        await self._install_scope_guard()

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

        try:
            await self._execute_action(action)
        finally:
            self._page.remove_listener("request", record_request)
            self._page.remove_listener("response", record_response)

        page_after = await self._take_page_snapshot()
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

        return ActionExecutionResult(
            action_id=action.action_id,
            started_at=started_at,
            completed_at=completed_at,
            page_url_before=page_before.url,
            page_url_after=page_after.url,
            page_changes=page_changes,
            events=events,
            traffic=traffic,
        )

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

        await self._page.goto(destination, wait_until="domcontentloaded")

    async def _click(self, action: BrowserAction) -> None:
        control = await self._find_control(action.observed_control_id)
        await control.click()
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
        control = await self._find_control(action.observed_control_id)
        if action.value_reference is None:
            raise ValueError("A fill action requires value_reference")

        live_value = self._secrets.resolve(action.value_reference)
        await control.fill(live_value)

    async def _select(self, action: BrowserAction) -> None:
        control = await self._find_control(action.observed_control_id)
        await control.select_option(action.option_value)

    async def _press_key(self, action: BrowserAction) -> None:
        if action.key is None:
            raise ValueError("A press_key action requires key")

        if action.observed_control_id is None:
            await self._page.keyboard.press(action.key)
            return

        control = await self._find_control(action.observed_control_id)
        await control.press(action.key)

    async def _wait(self, action: BrowserAction) -> None:
        if action.wait_for is None:
            raise ValueError("A wait action requires wait_for")

        if action.wait_for is ActionWaitCondition.CONTROL_VISIBLE:
            control = await self._find_control(action.observed_control_id)
            await control.wait_for(state="visible")
            return

        if action.wait_for is ActionWaitCondition.CONTROL_HIDDEN:
            control = await self._find_control(action.observed_control_id)
            await control.wait_for(state="hidden")
            return

        if action.wait_for is ActionWaitCondition.LOAD:
            await self._page.wait_for_load_state("load")
        elif action.wait_for is ActionWaitCondition.DOM_CONTENT_LOADED:
            await self._page.wait_for_load_state("domcontentloaded")
        else:
            await self._page.wait_for_load_state("networkidle")

    async def _find_control(self, observed_control_id: str | None) -> Locator:
        control_number = self._parse_control_number(observed_control_id)
        controls = self._page.locator(CONTROL_SELECTOR)
        control_count = await controls.count()

        if control_number > control_count:
            raise InvalidControlReferenceError(
                f"The recorded control '{observed_control_id}' is no longer present"
            )

        return controls.nth(control_number - 1)

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
