"""Tests for the React/JSON bearer-token evaluation application."""

import asyncio
import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Thread
from uuid import uuid4

import pytest
import uvicorn
from authflowguard.authentication import execute_verified_login_flow
from authflowguard.evaluation_targets.react_json_app import (
    BEARER_STORAGE_KEY,
    KNOWN_USERNAME,
    KNOWN_VERIFICATION_CODE,
    EvaluationMode,
    create_react_json_app,
)
from authflowguard.models import (
    AuthFeature,
    BrowserActionType,
    FeatureStatus,
    TargetScope,
)
from authflowguard.secrets import RuntimeSecrets
from fastapi.testclient import TestClient


@contextmanager
def run_react_json_server() -> Iterator[str]:
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.bind(("127.0.0.1", 0))
    listening_socket.listen()
    port = listening_socket.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            create_react_json_app(EvaluationMode.SECURE),
            log_level="error",
            lifespan="off",
        )
    )
    thread = Thread(
        target=server.run,
        kwargs={"sockets": [listening_socket]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("React/JSON evaluation server did not start")

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listening_socket.close()


def test_react_json_api_issues_and_requires_a_bearer_token() -> None:
    client = TestClient(create_react_json_app(EvaluationMode.SECURE))

    start = client.post("/api/auth/start", json={"username": KNOWN_USERNAME})
    assert start.status_code == 200
    assert start.json()["next"] == "verification"

    invalid = client.post(
        "/api/auth/verify",
        json={"username": KNOWN_USERNAME, "code": "wrong"},
    )
    assert invalid.status_code == 401

    verified = client.post(
        "/api/auth/verify",
        json={"username": KNOWN_USERNAME, "code": KNOWN_VERIFICATION_CODE},
    )
    assert verified.status_code == 200
    token = verified.json()["access_token"]
    assert token
    assert client.get("/api/account").status_code == 401
    account = client.get("/api/account", headers={"Authorization": f"Bearer {token}"})
    assert account.status_code == 200
    assert account.json()["username"] == KNOWN_USERNAME


def test_react_json_vulnerable_mode_discloses_unknown_account() -> None:
    client = TestClient(create_react_json_app(EvaluationMode.VULNERABLE))
    response = client.post(
        "/api/auth/start",
        json={"username": "missing@example.test"},
    )
    assert response.status_code == 401
    assert "No account exists" in response.json()["message"]


def test_react_json_secure_mode_answers_every_email_alike() -> None:
    client = TestClient(create_react_json_app(EvaluationMode.SECURE))
    known = client.post("/api/auth/start", json={"username": KNOWN_USERNAME})
    unknown = client.post("/api/auth/start", json={"username": "missing@example.test"})
    assert unknown.status_code == known.status_code == 200
    assert unknown.json() == known.json()

    rejected = [
        client.post("/api/auth/verify", json={"username": username, "code": "wrong"})
        for username in (KNOWN_USERNAME, "missing@example.test")
    ]
    assert [response.status_code for response in rejected] == [401, 401]
    assert rejected[0].json() == rejected[1].json()


@pytest.mark.slow
def test_automatic_flow_supports_two_step_json_and_bearer_sessions() -> None:
    with run_react_json_server() as origin:
        result = asyncio.run(
            execute_verified_login_flow(
                scan_id=uuid4(),
                target=TargetScope(
                    target_url=f"{origin}/login",
                    permitted_origins=[origin],
                ),
                runtime_secrets=RuntimeSecrets(
                    {
                        "login-username": KNOWN_USERNAME,
                        "login-password": "unused-for-json-login",
                        "login-code": KNOWN_VERIFICATION_CODE,
                    }
                ),
                username_reference="login-username",
                password_reference="login-password",
                second_factor_reference="login-code",
                protected_resource=f"{origin}/account",
                account_marker_selector='[data-testid="account-marker"]',
                account_marker_description="The protected account marker",
            )
        )

    steps = result.profile.authentication_steps[AuthFeature.LOGIN]
    assert [step.action_type for step in steps] == [
        BrowserActionType.NAVIGATE,
        BrowserActionType.FILL,
        BrowserActionType.CLICK,
        BrowserActionType.WAIT,
        BrowserActionType.FILL,
        BrowserActionType.CLICK,
    ]
    assert result.profile.features[AuthFeature.LOGIN] is FeatureStatus.VERIFIED
    assert any(
        reference.storage_type == "local_storage"
        and reference.name == BEARER_STORAGE_KEY
        for reference in result.profile.session_references
    )
    serialized = result.profile.model_dump_json() + "".join(
        event.model_dump_json() for event in result.events
    )
    assert KNOWN_VERIFICATION_CODE not in serialized
    assert "access_token" not in serialized
