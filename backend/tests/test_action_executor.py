"""Browser-level tests for validated structured action execution."""

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from playwright.async_api import async_playwright
from pydantic import ValidationError

from authflowguard.action_executor import BrowserActionExecutor
from authflowguard.models import (
    ActionWaitCondition,
    BrowserAction,
    BrowserActionType,
    TargetScope,
)
from authflowguard.secrets import RuntimeSecrets, SecretReferenceNotFoundError


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
                <body>
                    <input id="username" name="username">
                    <button id="continue" type="button"
                            onclick="this.hidden = true; document.body.dataset.clicked = 'yes'">
                        Continue
                    </button>
                    <select id="role" name="role">
                        <option value="developer">Developer</option>
                        <option value="administrator">Administrator</option>
                    </select>
                </body>
            </html>"""

        return "<!doctype html><title>Destination</title><p>Arrived</p>"

    def log_message(self, format: str, *args) -> None:
        return


@contextmanager
def run_action_server():
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
        executor = BrowserActionExecutor(page, target, secrets)

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

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.FILL,
                    observed_control_id="control-1",
                    value_reference="known-username",
                    description="Fill the username",
                )
            )
            assert await page.locator("#username").input_value() == LIVE_USERNAME

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.PRESS_KEY,
                    observed_control_id="control-1",
                    key="End",
                    description="Move to the end of the username",
                )
            )

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.SELECT,
                    observed_control_id="control-3",
                    option_value="administrator",
                    description="Select the administrator role",
                )
            )
            assert await page.locator("#role").input_value() == "administrator"

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.WAIT,
                    observed_control_id="control-2",
                    wait_for=ActionWaitCondition.CONTROL_VISIBLE,
                    description="Wait for the continue button",
                )
            )

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.CLICK,
                    observed_control_id="control-2",
                    description="Click continue",
                )
            )
            assert await page.locator("body").get_attribute("data-clicked") == "yes"

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
