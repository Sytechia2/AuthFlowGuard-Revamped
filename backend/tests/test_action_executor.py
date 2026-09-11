"""Browser-level tests for validated structured action execution."""

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import uuid4

import pytest
from authflowguard.action_executor import (
    BrowserActionExecutor,
    InvalidControlReferenceError,
)
from authflowguard.models import (
    ActionWaitCondition,
    BrowserAction,
    BrowserActionType,
    EvidenceKind,
    TargetScope,
)
from authflowguard.secrets import RuntimeSecrets, SecretReferenceNotFoundError
from playwright.async_api import async_playwright
from pydantic import ValidationError

LIVE_USERNAME = "developer@example.test"


class ActionPageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        encoded_page = self._page_for_path().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded_page)))
        self.end_headers()
        self.wfile.write(encoded_page)

    def _page_for_path(self) -> str:
        if self.path.startswith("/controls"):
            return """<!doctype html>
            <html>
                <head><title>Action Controls</title></head>
                <body onkeydown="document.body.dataset.lastKey = event.key">
                    <input id="username" name="username">
                    <button id="continue" type="button"
                            onclick="
                                this.hidden = true;
                                document.body.dataset.clicked = 'yes';
                            ">
                        Continue
                    </button>
                    <select id="role" name="role">
                        <option value="developer">Developer</option>
                        <option value="administrator">Administrator</option>
                    </select>
                </body>
            </html>"""

        return "<!doctype html><title>Destination</title><p>Arrived</p>"

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def run_action_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ActionPageHandler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join()


async def execute_all_action_types(origin: str) -> None:
    target = TargetScope(
        target_url=f"{origin}/controls",
        permitted_origins=[origin],
    )
    secrets = RuntimeSecrets({"known-username": LIVE_USERNAME})

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        executor = BrowserActionExecutor(page, target, secrets, scan_id=uuid4())

        try:
            navigate_result = await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url=f"{origin}/controls?one_time_code=not-recorded",
                    description="Open the controlled action page",
                )
            )
            assert navigate_result.page_url_after == f"{origin}/controls"
            assert "one_time_code" not in str(navigate_result)
            assert navigate_result.page_changes.url_changed
            assert navigate_result.traffic
            assert all(
                event.action_id == navigate_result.action_id
                for event in navigate_result.events
            )
            assert all(
                reference.authentication_action_id == navigate_result.action_id
                for reference in navigate_result.traffic
            )
            event_by_id = {event.event_id: event for event in navigate_result.events}
            for reference in navigate_result.traffic:
                request_event = event_by_id[reference.request_event_id]
                assert reference.response_event_id is not None
                response_event = event_by_id[reference.response_event_id]
                assert request_event.kind is EvidenceKind.REQUEST
                assert response_event.kind is EvidenceKind.RESPONSE
                assert request_event.redacted_details["url"] == f"{origin}/controls"
                assert response_event.redacted_details["url"] == f"{origin}/controls"

            fill_result = await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.FILL,
                    observed_control_id="control-1",
                    value_reference="known-username",
                    description="Fill the username",
                )
            )
            assert await page.locator("#username").input_value() == LIVE_USERNAME
            assert LIVE_USERNAME not in str(fill_result)
            assert not fill_result.page_changes.changed

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.PRESS_KEY,
                    observed_control_id="control-1",
                    key="End",
                    description="Move to the end of the username",
                )
            )

            select_result = await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.SELECT,
                    observed_control_id="control-3",
                    option_value="administrator",
                    description="Select the administrator role",
                )
            )

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.PRESS_KEY,
                    key="Escape",
                    description="Send a key to the page",
                )
            )
            assert await page.locator("body").get_attribute("data-last-key") == "Escape"
            assert await page.locator("#role").input_value() == "administrator"
            assert select_result.page_changes.changed
            assert select_result.page_changes.control_state_changed

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.WAIT,
                    observed_control_id="control-2",
                    wait_for=ActionWaitCondition.CONTROL_VISIBLE,
                    description="Wait for the continue button",
                )
            )

            for load_state in [
                ActionWaitCondition.LOAD,
                ActionWaitCondition.DOM_CONTENT_LOADED,
            ]:
                await executor.execute(
                    BrowserAction(
                        action_type=BrowserActionType.WAIT,
                        wait_for=load_state,
                        description=f"Wait for {load_state.value}",
                    )
                )

            click_result = await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.CLICK,
                    observed_control_id="control-2",
                    description="Click continue",
                )
            )
            assert await page.locator("body").get_attribute("data-clicked") == "yes"
            assert click_result.page_changes.changed
            assert click_result.page_changes.visible_text_changed
            assert click_result.page_changes.controls_became_hidden == ["control-2"]

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.WAIT,
                    observed_control_id="control-2",
                    wait_for=ActionWaitCondition.CONTROL_HIDDEN,
                    description="Wait for the continue button to disappear",
                )
            )

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.WAIT,
                    wait_for=ActionWaitCondition.NETWORK_IDLE,
                    description="Wait for the network to become idle",
                )
            )

            with pytest.raises(ValueError, match="outside permitted_origins"):
                await executor.execute(
                    BrowserAction(
                        action_type=BrowserActionType.NAVIGATE,
                        url="https://outside.invalid/account",
                        description="Attempt an out-of-scope navigation",
                    )
                )
        finally:
            await context.close()
            await browser.close()


def test_executor_supports_every_browser_action_type() -> None:
    with run_action_server() as origin:
        asyncio.run(execute_all_action_types(origin))


def test_browser_action_rejects_missing_required_fields() -> None:
    with pytest.raises(ValidationError, match="fill action requires value_reference"):
        BrowserAction(
            action_type=BrowserActionType.FILL,
            observed_control_id="control-1",
            description="Invalid fill action",
        )

    with pytest.raises(ValidationError, match="control_visible wait requires"):
        BrowserAction(
            action_type=BrowserActionType.WAIT,
            wait_for=ActionWaitCondition.CONTROL_VISIBLE,
            description="Invalid wait action",
        )


def test_runtime_secrets_can_be_discarded() -> None:
    secrets = RuntimeSecrets({"known-username": LIVE_USERNAME})

    assert secrets.resolve("known-username") == LIVE_USERNAME
    secrets.discard_all()

    assert len(secrets) == 0
    with pytest.raises(SecretReferenceNotFoundError):
        secrets.resolve("known-username")


async def verify_executor_rejects_stale_references(origin: str) -> None:
    target = TargetScope(
        target_url=f"{origin}/controls",
        permitted_origins=[origin],
    )

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        executor = BrowserActionExecutor(
            page,
            target,
            RuntimeSecrets({}),
            scan_id=uuid4(),
        )

        try:
            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url=f"{origin}/controls",
                    description="Open the controlled page",
                )
            )

            with pytest.raises(SecretReferenceNotFoundError):
                await executor.execute(
                    BrowserAction(
                        action_type=BrowserActionType.FILL,
                        observed_control_id="control-1",
                        value_reference="missing-username",
                        description="Attempt to use a missing secret",
                    )
                )

            for invalid_control_id in ["control-99", "username", "control-0"]:
                with pytest.raises(InvalidControlReferenceError):
                    await executor.execute(
                        BrowserAction(
                            action_type=BrowserActionType.CLICK,
                            observed_control_id=invalid_control_id,
                            description="Attempt to use a stale control reference",
                        )
                    )
        finally:
            await context.close()
            await browser.close()


def test_executor_rejects_missing_secrets_and_stale_controls() -> None:
    with run_action_server() as origin:
        asyncio.run(verify_executor_rejects_stale_references(origin))
