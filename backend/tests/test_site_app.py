"""Tests for the independent workshop-desk evaluation application."""

import re

import httpx
import pytest
from authflowguard.site_app import (
    KNOWN_MEMBER_ID,
    KNOWN_PASSPHRASE,
    LOCKOUT_THRESHOLD,
    SESSION_COOKIE,
    EvaluationMode,
    create_site_app,
)
from fastapi.testclient import TestClient


def form_seal(response_text: str) -> str:
    match = re.search(r'name="form_seal" value="([^"]+)"', response_text)
    assert match is not None
    return match.group(1)


def post_entry(
    client: TestClient,
    values: dict[str, str],
    *,
    follow_redirects: bool = False,
) -> httpx.Response:
    form = client.get("/desk/entry")
    values = {"form_seal": form_seal(form.text), **values}
    return client.post("/desk/entry", data=values, follow_redirects=follow_redirects)


@pytest.mark.parametrize("mode", list(EvaluationMode))
def test_form_seal_changes_and_cannot_be_reused(mode: EvaluationMode) -> None:
    client = TestClient(create_site_app(mode))
    first_seal = form_seal(client.get("/desk/entry").text)
    second_seal = form_seal(client.get("/desk/entry").text)

    assert first_seal != second_seal
    response = client.post(
        "/desk/entry",
        data={
            "form_seal": first_seal,
            "member_id": KNOWN_MEMBER_ID,
            "passphrase": KNOWN_PASSPHRASE,
        },
    )
    assert response.status_code == 400


@pytest.mark.parametrize("mode", list(EvaluationMode))
def test_login_redirects_to_bookings_with_an_authenticated_marker(
    mode: EvaluationMode,
) -> None:
    client = TestClient(create_site_app(mode))
    anonymous = client.get("/desk/bookings")

    response = post_entry(
        client,
        {"member_id": KNOWN_MEMBER_ID, "passphrase": KNOWN_PASSPHRASE},
    )

    assert anonymous.status_code == 401
    assert 'data-desk="owner"' not in anonymous.text
    assert response.status_code == 303
    assert response.headers["location"] == "/desk/bookings"
    protected = client.get("/desk/bookings")
    assert protected.status_code == 200
    assert 'data-desk="owner"' in protected.text
    assert KNOWN_MEMBER_ID in protected.text


def test_secure_login_rotates_the_session_cookie() -> None:
    client = TestClient(create_site_app(EvaluationMode.SECURE))
    client.get("/desk/entry")
    original_session = client.cookies[SESSION_COOKIE]
    response = post_entry(
        client,
        {"member_id": KNOWN_MEMBER_ID, "passphrase": KNOWN_PASSPHRASE},
    )

    assert response.status_code == 303
    assert client.cookies[SESSION_COOKIE] != original_session


def test_vulnerable_login_preserves_the_session_cookie() -> None:
    client = TestClient(create_site_app(EvaluationMode.VULNERABLE))
    client.get("/desk/entry")
    original_session = client.cookies[SESSION_COOKIE]
    response = post_entry(
        client,
        {"member_id": KNOWN_MEMBER_ID, "passphrase": KNOWN_PASSPHRASE},
    )

    assert response.status_code == 303
    assert client.cookies[SESSION_COOKIE] == original_session


def test_secure_login_uses_a_generic_failure_message_and_locks_the_account() -> None:
    client = TestClient(create_site_app(EvaluationMode.SECURE))
    unknown_response = post_entry(
        client,
        {"member_id": "MBR-00000", "passphrase": "wrong"},
    )
    known_response = post_entry(
        client,
        {"member_id": KNOWN_MEMBER_ID, "passphrase": "wrong"},
    )

    assert unknown_response.status_code == known_response.status_code == 401
    assert unknown_response.text == known_response.text

    for _ in range(LOCKOUT_THRESHOLD - 1):
        post_entry(
            client,
            {"member_id": KNOWN_MEMBER_ID, "passphrase": "wrong"},
        )
    locked_response = post_entry(
        client,
        {"member_id": KNOWN_MEMBER_ID, "passphrase": KNOWN_PASSPHRASE},
    )
    assert locked_response.status_code == 429


def test_vulnerable_mode_discloses_account_existence_without_lockout() -> None:
    client = TestClient(create_site_app(EvaluationMode.VULNERABLE))
    unknown_response = post_entry(
        client,
        {"member_id": "MBR-00000", "passphrase": "wrong"},
    )
    known_response = post_entry(
        client,
        {"member_id": KNOWN_MEMBER_ID, "passphrase": "wrong"},
    )

    assert "No member with that ID" in unknown_response.text
    assert "passphrase is incorrect" in known_response.text

    for _ in range(LOCKOUT_THRESHOLD + 1):
        post_entry(
            client,
            {"member_id": KNOWN_MEMBER_ID, "passphrase": "wrong"},
        )
    valid_response = post_entry(
        client,
        {"member_id": KNOWN_MEMBER_ID, "passphrase": KNOWN_PASSPHRASE},
    )
    assert valid_response.status_code == 303


@pytest.mark.parametrize(
    ("mode", "expected_status"),
    [(EvaluationMode.SECURE, 401), (EvaluationMode.VULNERABLE, 200)],
)
def test_logout_session_invalidation_depends_on_mode(
    mode: EvaluationMode,
    expected_status: int,
) -> None:
    client = TestClient(create_site_app(mode))
    post_entry(
        client,
        {"member_id": KNOWN_MEMBER_ID, "passphrase": KNOWN_PASSPHRASE},
    )
    pre_logout_session = client.cookies[SESSION_COOKIE]
    response = client.post("/desk/depart", follow_redirects=False)

    assert response.status_code == 303
    client.cookies.set(SESSION_COOKIE, pre_logout_session)
    assert client.get("/desk/bookings").status_code == expected_status
