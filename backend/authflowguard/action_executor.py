"""Validated execution of structured browser actions."""

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from playwright.async_api import Locator, Page, Route

from authflowguard.models import (
    ActionWaitCondition,
    BrowserAction,
    BrowserActionType,
    TargetScope,
)
from authflowguard.scope import url_is_in_scope, url_without_query_or_fragment
from authflowguard.secrets import RuntimeSecrets


CONTROL_SELECTOR = "input, button, select, textarea, a[href]"


class InvalidControlReferenceError(ValueError):
    """Raised when a recorded control cannot be found on the current page."""


@dataclass(frozen=True)
class ActionExecutionResult:
    action_id: UUID
    started_at: datetime
    completed_at: datetime
    page_url_before: str
    page_url_after: str


class BrowserActionExecutor:
    """Execute only the action types defined by the shared contract."""

    def __init__(self, page: Page, target: TargetScope, secrets: RuntimeSecrets) -> None:
        self._page = page
        self._target = target
        self._secrets = secrets
        self._scope_guard_installed = False

    async def execute(self, action: BrowserAction) -> ActionExecutionResult:
        await self._install_scope_guard()

        if (
            action.action_type is not BrowserActionType.NAVIGATE
            and not url_is_in_scope(self._page.url, self._target)
        ):
            raise ValueError("The current page is outside permitted_origins")

        started_at = datetime.now(timezone.utc)
        page_url_before = url_without_query_or_fragment(self._page.url)

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

        return ActionExecutionResult(
            action_id=action.action_id,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            page_url_before=page_url_before,
            page_url_after=url_without_query_or_fragment(self._page.url),
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

    async def _fill(self, action: BrowserAction) -> None:
        control = await self._find_control(action.observed_control_id)
        live_value = self._secrets.resolve(action.value_reference)
        await control.fill(live_value)

    async def _select(self, action: BrowserAction) -> None:
        control = await self._find_control(action.observed_control_id)
        await control.select_option(action.option_value)

    async def _press_key(self, action: BrowserAction) -> None:
        if action.observed_control_id is None:
            await self._page.keyboard.press(action.key)
            return

        control = await self._find_control(action.observed_control_id)
        await control.press(action.key)

    async def _wait(self, action: BrowserAction) -> None:
        if action.wait_for is ActionWaitCondition.CONTROL_VISIBLE:
            control = await self._find_control(action.observed_control_id)
            await control.wait_for(state="visible")
            return

        if action.wait_for is ActionWaitCondition.CONTROL_HIDDEN:
            control = await self._find_control(action.observed_control_id)
            await control.wait_for(state="hidden")
            return

        await self._page.wait_for_load_state(action.wait_for.value)

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
