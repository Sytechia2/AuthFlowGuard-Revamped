"""Real-browser smoke test for the controlled evaluation application."""

import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Thread

import pytest
import uvicorn
from authflowguard.evaluation_targets.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
    SESSION_COOKIE,
    EvaluationMode,
    create_controlled_app,
)
from playwright.sync_api import sync_playwright

pytestmark = pytest.mark.slow


@contextmanager
def run_controlled_server() -> Iterator[str]:
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.bind(("127.0.0.1", 0))
    listening_socket.listen()
    port = listening_socket.getsockname()[1]

    server = uvicorn.Server(
        uvicorn.Config(
            create_controlled_app(EvaluationMode.SECURE),
            log_level="error",
            lifespan="off",
        )
    )
    server_thread = Thread(
        target=server.run,
        kwargs={"sockets": [listening_socket]},
        daemon=True,
    )
    server_thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("Controlled evaluation server did not start")

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        server_thread.join(timeout=5)
        listening_socket.close()


def test_secure_login_works_in_chromium_and_anonymous_context_stays_isolated() -> None:
    with run_controlled_server() as origin, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        authenticated_context = browser.new_context()
        page = authenticated_context.new_page()
        page.goto(f"{origin}/login")
        initial_cookie = next(
            cookie["value"]
            for cookie in authenticated_context.cookies()
            if cookie["name"] == SESSION_COOKIE
        )

        page.get_by_label("Email").fill(KNOWN_USERNAME)
        page.get_by_label("Password").fill(KNOWN_PASSWORD)
        page.get_by_role("button", name="Sign in").click()

        assert page.url == f"{origin}/account"
        assert page.get_by_test_id("account-marker").inner_text() == (
            f"Signed in as {KNOWN_USERNAME}"
        )
        authenticated_cookie = next(
            cookie["value"]
            for cookie in authenticated_context.cookies()
            if cookie["name"] == SESSION_COOKIE
        )
        assert authenticated_cookie != initial_cookie

        anonymous_context = browser.new_context()
        anonymous_page = anonymous_context.new_page()
        response = anonymous_page.goto(f"{origin}/account")
        assert response is not None
        assert response.status == 401
        assert anonymous_page.get_by_text("Authentication required").is_visible()
        assert anonymous_page.get_by_test_id("account-marker").count() == 0

        anonymous_context.close()
        authenticated_context.close()
        browser.close()
