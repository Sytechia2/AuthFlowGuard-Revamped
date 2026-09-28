"""Browser-level tests for validated structured action execution."""

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import uuid4

import pytest
from authflowguard.action_executor import (
    BrowserActionExecutor,
    InvalidControlReferenceError,
)
from authflowguard.control_safety import UnsafeControlError
from authflowguard.models import (
    ActionWaitCondition,
    BrowserAction,
    BrowserActionType,
    EvidenceKind,
    TargetScope,
)
from authflowguard.secrets import RuntimeSecrets, SecretReferenceNotFoundError
from playwright.async_api import Locator, Page, Route, async_playwright
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from pydantic import ValidationError

LIVE_USERNAME = "developer@example.test"


class ActionPageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/api/"):
            self._background_response()
            return
        encoded_page = self._page_for_path().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded_page)))
        self.end_headers()
        self.wfile.write(encoded_page)

    def _background_response(self) -> None:
        # Slow enough that an action returning early would miss the result.
        time.sleep(0.4)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        if self.path.startswith("/api/login"):
            self.send_header("Set-Cookie", "session=client-rendered; Path=/")
        self.end_headers()
        self.wfile.write(b"{}")

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

        if self.path.startswith("/spa"):
            # Like a hash-routed single-page app: the form exists only after
            # the app has fetched its configuration, and signing in is a
            # background request whose response sets the session cookie.
            return """<!doctype html>
            <html>
                <head><title>Client Rendered</title></head>
                <body>
                    <script>
                        fetch('/api/config').then(() => {
                            document.body.innerHTML = `
                                <button id="sign-in" type="button"
                                        onclick="fetch('/api/login')">
                                    Sign in
                                </button>`;
                        });
                    </script>
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
        executor = BrowserActionExecutor(
            page, target, secrets, scan_id=uuid4(), password_references=frozenset()
        )

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
            password_references=frozenset(),
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


def test_snapshot_remains_consistent_while_page_replaces_its_controls() -> None:
    async def snapshot_changing_page() -> None:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            page.set_default_timeout(1000)
            try:
                await page.set_content("<title>empty</title><body></body>")
                await page.evaluate("""() => {
                    let populated = false;
                    window.snapshotTimer = setInterval(() => {
                        populated = !populated;
                        document.title = populated ? 'populated' : 'empty';
                        document.body.innerHTML = populated
                            ? '<input><input><button>Continue</button>' : '';
                    }, 1);
                }""")
                executor = BrowserActionExecutor(
                    page,
                    TargetScope(
                        target_url="https://app.example/login",
                        permitted_origins=["https://app.example"],
                    ),
                    RuntimeSecrets({}),
                    uuid4(),
                    password_references=frozenset(),
                )
                for _ in range(20):
                    snapshot = await executor._take_page_snapshot()
                    expected = (
                        ["control-1", "control-2", "control-3"]
                        if snapshot.title == "populated"
                        else []
                    )
                    assert snapshot.visible_control_ids == expected
            finally:
                await browser.close()

    asyncio.run(snapshot_changing_page())


async def sign_in_to_client_rendered_page(origin: str) -> None:
    route = f"{origin}/spa#/login"
    target = TargetScope(target_url=route, permitted_origins=[origin])

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        executor = BrowserActionExecutor(
            page, target, RuntimeSecrets({}), uuid4(), password_references=frozenset()
        )
        try:
            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url=route,
                    description="Open the client-rendered sign-in route",
                )
            )
            assert await page.locator("#sign-in").count() == 1

            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.CLICK,
                    observed_control_id="control-1",
                    description="Sign in",
                )
            )
            cookie_names = [cookie["name"] for cookie in await context.cookies()]
            assert cookie_names == ["session"]
        finally:
            await browser.close()


def test_executor_waits_for_client_rendering_and_background_sign_in() -> None:
    with run_action_server() as origin:
        asyncio.run(sign_in_to_client_rendered_page(origin))


SAFETY_ORIGIN = "https://app.example"
LIVE_PASSWORD = "correct-horse-battery"
WRONG_PASSWORD = "not-the-password"
LOGIN_SECRETS = {"username": LIVE_USERNAME, "password": LIVE_PASSWORD}
# Records every key and input event, so a test can prove nothing was typed.
KEY_RECORDER = """<script>
    window.typed = '';
    document.addEventListener('keydown', event => { window.typed += event.key; });
    document.addEventListener('input', () => { window.typed += '[input]'; });
</script>"""


async def run_on_page(
    body: str,
    secrets: RuntimeSecrets,
    password_references: frozenset[str],
    check: Callable[[Page, BrowserActionExecutor], Awaitable[None]],
) -> None:
    """Serve one page on a fake origin and hand an executor to ``check``."""

    html = f"<!doctype html><html><head><title>Safety</title></head>{body}</html>"
    target = TargetScope(
        target_url=f"{SAFETY_ORIGIN}/page", permitted_origins=[SAFETY_ORIGIN]
    )
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            page.set_default_timeout(2000)

            async def serve(route: Route) -> None:
                await route.fulfill(status=200, content_type="text/html", body=html)

            await page.route(f"{SAFETY_ORIGIN}/**", serve)
            executor = BrowserActionExecutor(
                page,
                target,
                secrets,
                uuid4(),
                password_references=password_references,
            )
            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url=f"{SAFETY_ORIGIN}/page",
                    description="Open the page",
                )
            )
            await check(page, executor)
        finally:
            await browser.close()


def fill(control_id: str, reference: str) -> BrowserAction:
    return BrowserAction(
        action_type=BrowserActionType.FILL,
        observed_control_id=control_id,
        value_reference=reference,
        description="Fill a control",
    )


def click(control_id: str) -> BrowserAction:
    return BrowserAction(
        action_type=BrowserActionType.CLICK,
        observed_control_id=control_id,
        description="Click a control",
    )


def test_username_is_not_typed_into_a_button() -> None:
    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        with pytest.raises(UnsafeControlError) as caught:
            await executor.execute(fill("control-1", "username"))

        message = str(caught.value)
        assert message == (
            "control-1 is a button, not a text field, so the value was not "
            "typed into it."
        )
        assert LIVE_USERNAME not in message
        assert "Basket" not in message
        assert await page.evaluate("window.typed") == ""
        assert await page.evaluate("document.body.dataset.added") is None

    asyncio.run(
        run_on_page(
            f"""<body>{KEY_RECORDER}
                <button onclick="document.body.dataset.added = 'yes'">
                    Add to Basket
                </button></body>""",
            RuntimeSecrets(LOGIN_SECRETS),
            frozenset({"password"}),
            check,
        )
    )


def test_password_is_not_typed_into_a_text_field() -> None:
    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        with pytest.raises(UnsafeControlError, match="not a password field"):
            await executor.execute(fill("control-1", "password"))
        assert await page.locator("#search").input_value() == ""
        assert await page.evaluate("window.typed") == ""

    asyncio.run(
        run_on_page(
            f'<body>{KEY_RECORDER}<input id="search" type="search"></body>',
            RuntimeSecrets(LOGIN_SECRETS),
            frozenset({"password"}),
            check,
        )
    )


def test_non_password_is_not_typed_into_a_password_field() -> None:
    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        with pytest.raises(
            UnsafeControlError, match="password field but the value is not"
        ):
            await executor.execute(fill("control-1", "username"))
        assert await page.locator("#password").input_value() == ""

    asyncio.run(
        run_on_page(
            '<body><input id="password" type="password"></body>',
            RuntimeSecrets(LOGIN_SECRETS),
            frozenset({"password"}),
            check,
        )
    )


def test_wrong_password_is_still_typed_into_the_password_field() -> None:
    # Login enumeration's failed attempts type a wrong password on purpose.
    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        await executor.execute(fill("control-1", "username"))
        await executor.execute(fill("control-2", "password"))
        assert await page.locator("#username").input_value() == LIVE_USERNAME
        assert await page.locator("#password").input_value() == WRONG_PASSWORD

    asyncio.run(
        run_on_page(
            """<body><input id="username" type="email">
                <input id="password" type="password"></body>""",
            RuntimeSecrets({"username": LIVE_USERNAME, "password": WRONG_PASSWORD}),
            frozenset({"password"}),
            check,
        )
    )


def test_destructive_controls_are_never_clicked() -> None:
    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        for control_id in ("control-1", "control-2", "control-3"):
            with pytest.raises(UnsafeControlError, match="irreversible account"):
                await executor.execute(click(control_id))
        with pytest.raises(UnsafeControlError, match="irreversible account"):
            await executor.execute(
                BrowserAction(
                    action_type=BrowserActionType.PRESS_KEY,
                    observed_control_id="control-1",
                    key="Enter",
                    description="Press Enter on a control",
                )
            )
        assert await page.evaluate("document.body.dataset.destroyed") is None

    asyncio.run(
        run_on_page(
            """<body>
                <button onclick="document.body.dataset.destroyed = 'yes'">
                    Delete account
                </button>
                <button aria-label="Remove item"
                        onclick="document.body.dataset.destroyed = 'yes'">x</button>
                <input type="submit" value="Close my account"
                       onclick="document.body.dataset.destroyed = 'yes'">
            </body>""",
            RuntimeSecrets({}),
            frozenset(),
            check,
        )
    )


def test_a_cookie_banner_close_button_is_still_clickable() -> None:
    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        await executor.execute(click("control-1"))
        assert await page.locator("#banner").count() == 0

    asyncio.run(
        run_on_page(
            """<body><div id="banner">We use cookies to run your account.
                <button onclick="document.getElementById('banner').remove()">
                    Close
                </button></div></body>""",
            RuntimeSecrets({}),
            frozenset(),
            check,
        )
    )


def test_a_control_that_never_appears_is_not_clicked() -> None:
    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        with pytest.raises(UnsafeControlError, match="did not become visible"):
            await executor.execute(click("control-1"))
        assert await page.evaluate("document.body.dataset.clicked") is None

    asyncio.run(
        run_on_page(
            """<body><button hidden
                onclick="document.body.dataset.clicked = 'yes'">Continue</button>
            </body>""",
            RuntimeSecrets({}),
            frozenset(),
            check,
        )
    )


def test_a_field_revealed_later_is_still_filled() -> None:
    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        await executor.execute(fill("control-1", "username"))
        assert await page.locator("#code").input_value() == LIVE_USERNAME

    asyncio.run(
        run_on_page(
            """<body><input id="code" hidden>
                <script>
                    setTimeout(() => {
                        document.getElementById('code').hidden = false;
                    }, 300);
                </script></body>""",
            RuntimeSecrets(LOGIN_SECRETS),
            frozenset({"password"}),
            check,
        )
    )


def test_a_fill_timeout_becomes_a_safe_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Playwright's own timeout message quotes the value it was typing.
    async def time_out(_locator: Locator, value: str, **_kwargs: object) -> None:
        raise PlaywrightTimeoutError(
            f'Locator.fill: Timeout 2000ms exceeded. "{value}"'
        )

    monkeypatch.setattr(Locator, "fill", time_out)

    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        with pytest.raises(UnsafeControlError) as caught:
            await executor.execute(fill("control-1", "password"))

        assert str(caught.value) == (
            "control-1 did not become editable within the time limit, so the "
            "password was not typed into it."
        )
        assert LIVE_PASSWORD not in str(caught.value)
        # The original stays chained for debugging but is never the message.
        assert isinstance(caught.value.__cause__, PlaywrightTimeoutError)

    asyncio.run(
        run_on_page(
            '<body><input id="password" type="password"></body>',
            RuntimeSecrets(LOGIN_SECRETS),
            frozenset({"password"}),
            check,
        )
    )


def test_a_click_timeout_becomes_a_safe_error() -> None:
    # A control covered by an overlay never receives the click.
    async def check(page: Page, executor: BrowserActionExecutor) -> None:
        with pytest.raises(UnsafeControlError) as caught:
            await executor.execute(click("control-1"))

        assert str(caught.value) == (
            "control-1 did not become clickable within the time limit, so it "
            "was not clicked."
        )
        assert await page.evaluate("document.body.dataset.clicked") is None

    asyncio.run(
        run_on_page(
            """<body>
                <button onclick="document.body.dataset.clicked = 'yes'">Go</button>
                <div style="position: fixed; inset: 0; background: white"></div>
            </body>""",
            RuntimeSecrets({}),
            frozenset(),
            check,
        )
    )
