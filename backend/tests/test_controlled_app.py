"""Tests for the controlled form-and-cookie evaluation application."""

import re

import httpx2
import pytest
from authflowguard.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
    LOCKOUT_THRESHOLD,
    SESSION_COOKIE,
    EvaluationMode,
    create_controlled_app,
)
from fastapi.testclient import TestClient


def csrf_token(response_text: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response_text)
    assert match is not None
    return match.group(1)


def post_form(
    client: TestClient,
    path: str,
    values: dict[str, str],
    *,
    follow_redirects: bool = False,
) -> httpx2.Response:
    form = client.get(path)
    values = {"csrf_token": csrf_token(form.text), **values}
    return client.post(path, data=values, follow_redirects=follow_redirects)


@pytest.mark.parametrize("mode", list(EvaluationMode))
def test_csrf_tokens_change_and_cannot_be_reused(mode: EvaluationMode) -> None:
    client = TestClient(create_controlled_app(mode))
    first_token = csrf_token(client.get("/login").text)
    second_token = csrf_token(client.get("/login").text)

    assert first_token != second_token
    response = client.post(
        "/login",
        data={
            "csrf_token": first_token,
            "username": KNOWN_USERNAME,
            "password": KNOWN_PASSWORD,
        },
    )
    assert response.status_code == 400


@pytest.mark.parametrize("mode", list(EvaluationMode))
def test_login_redirects_to_account_with_an_authenticated_marker(
    mode: EvaluationMode,
) -> None:
    client = TestClient(create_controlled_app(mode))
    anonymous = client.get("/account")

    response = post_form(
        client,
        "/login",
        {"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD},
    )

    assert anonymous.status_code == 401
    assert "Signed in as" not in anonymous.text
    assert response.status_code == 303
    assert response.headers["location"] == "/account"
    protected = client.get("/account")
    assert protected.status_code == 200
    assert 'data-testid="account-marker"' in protected.text
    assert KNOWN_USERNAME in protected.text


def test_secure_login_rotates_the_session_cookie() -> None:
    client = TestClient(create_controlled_app(EvaluationMode.SECURE))
    login_form = client.get("/login")
    original_session = client.cookies[SESSION_COOKIE]
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(login_form.text),
            "username": KNOWN_USERNAME,
            "password": KNOWN_PASSWORD,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert client.cookies[SESSION_COOKIE] != original_session


def test_vulnerable_login_preserves_the_session_cookie() -> None:
    client = TestClient(create_controlled_app(EvaluationMode.VULNERABLE))
    login_form = client.get("/login")
    original_session = client.cookies[SESSION_COOKIE]
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(login_form.text),
            "username": KNOWN_USERNAME,
            "password": KNOWN_PASSWORD,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert client.cookies[SESSION_COOKIE] == original_session


def test_secure_login_uses_a_generic_failure_message_and_locks_the_account() -> None:
    client = TestClient(create_controlled_app(EvaluationMode.SECURE))
    unknown_response = post_form(
        client,
        "/login",
        {"username": "absent@example.test", "password": "wrong"},
    )
    known_response = post_form(
        client,
        "/login",
        {"username": KNOWN_USERNAME, "password": "wrong"},
    )

    assert unknown_response.status_code == known_response.status_code == 401
    assert unknown_response.text == known_response.text

    for _ in range(LOCKOUT_THRESHOLD - 1):
        post_form(
            client,
            "/login",
            {"username": KNOWN_USERNAME, "password": "wrong"},
        )
    locked_response = post_form(
        client,
        "/login",
        {"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD},
    )
    assert locked_response.status_code == 429


def test_vulnerable_mode_discloses_account_existence_without_lockout() -> None:
    client = TestClient(create_controlled_app(EvaluationMode.VULNERABLE))
    unknown_response = post_form(
        client,
        "/login",
        {"username": "absent@example.test", "password": "wrong"},
    )
    known_response = post_form(
        client,
        "/login",
        {"username": KNOWN_USERNAME, "password": "wrong"},
    )

    assert "No account exists" in unknown_response.text
    assert "password is incorrect" in known_response.text

    for _ in range(LOCKOUT_THRESHOLD + 1):
        post_form(
            client,
            "/login",
            {"username": KNOWN_USERNAME, "password": "wrong"},
        )
    valid_response = post_form(
        client,
        "/login",
        {"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD},
    )
    assert valid_response.status_code == 303


@pytest.mark.parametrize(
    ("path", "known_fragment", "unknown_fragment"),
    [
        ("/register", "already registered", "Check your email"),
        ("/reset", "reset instructions", "No account exists"),
    ],
)
def test_vulnerable_registration_and_reset_disclose_account_state(
    path: str,
    known_fragment: str,
    unknown_fragment: str,
) -> None:
    client = TestClient(create_controlled_app(EvaluationMode.VULNERABLE))
    known = post_form(
        client,
        path,
        {"username": KNOWN_USERNAME, "password": "new-password"},
    )
    unknown = post_form(
        client,
        path,
        {"username": "absent@example.test", "password": "new-password"},
    )

    assert known_fragment in known.text
    assert unknown_fragment in unknown.text


@pytest.mark.parametrize("path", ["/register", "/reset"])
def test_secure_registration_and_reset_use_generic_responses(path: str) -> None:
    known_client = TestClient(create_controlled_app(EvaluationMode.SECURE))
    unknown_client = TestClient(create_controlled_app(EvaluationMode.SECURE))
    known = post_form(
        known_client,
        path,
        {"username": KNOWN_USERNAME, "password": "new-password"},
    )
    unknown = post_form(
        unknown_client,
        path,
        {"username": "absent@example.test", "password": "new-password"},
    )

    assert known.status_code == unknown.status_code
    assert known.text == unknown.text


@pytest.mark.parametrize(
    ("mode", "expected_status"),
    [(EvaluationMode.SECURE, 401), (EvaluationMode.VULNERABLE, 200)],
)
def test_logout_session_invalidation_depends_on_mode(
    mode: EvaluationMode,
    expected_status: int,
) -> None:
    client = TestClient(create_controlled_app(mode))
    post_form(
        client,
        "/login",
        {"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD},
    )
    account = client.get("/account")
    response = client.post(
        "/logout",
        data={"csrf_token": csrf_token(account.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert client.get("/account").status_code == expected_status
