"""Tests for the local backend application."""

import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from authflowguard.app import app, create_app
from authflowguard.authentication import (
    GuidedPageObservation,
    LoginFormDiscoveryError,
    VerifiedLoginExecution,
)
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    CheckId,
    EvidenceEvent,
    EvidenceKind,
    FeatureStatus,
    ProtectedResourceCheck,
    ScanRequest,
    TargetScope,
)
from authflowguard.playwright_worker import SafeControlDescription
from authflowguard.scan_manager import ScanExecutionInput, ScanState
from fastapi.testclient import TestClient


def test_health_endpoint_reports_that_the_backend_is_available() -> None:
    client = TestClient(app)

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_backend_serves_a_built_frontend(tmp_path: Path) -> None:
    index_file = tmp_path / "index.html"
    index_file.write_text("<h1>AuthFlowGuard interface</h1>", encoding="utf-8")
    client = TestClient(create_app(frontend_dist=tmp_path))

    response = client.get("/")

    assert response.status_code == 200
    assert "AuthFlowGuard interface" in response.text


def test_api_routes_are_not_shadowed_by_frontend_files(tmp_path: Path) -> None:
    fake_api_directory = tmp_path / "api"
    fake_api_directory.mkdir()
    (fake_api_directory / "health").write_text(
        "this static file must not replace the API",
        encoding="utf-8",
    )
    client = TestClient(create_app(frontend_dist=tmp_path))

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_backend_returns_not_found_when_frontend_has_not_been_built(
    tmp_path: Path,
) -> None:
    missing_directory = tmp_path / "missing-frontend-dist"
    client = TestClient(create_app(frontend_dist=missing_directory))

    response = client.get("/")

    assert response.status_code == 404


def test_validation_errors_do_not_echo_submitted_credentials(tmp_path: Path) -> None:
    canary = "invalid-credential-canary-2-2"
    client = TestClient(create_app(data_root=tmp_path, worker_backend="thread"))

    response = client.post(
        f"/api/scans/{uuid4()}/start",
        json={
            "runtime_secrets": {canary: [canary]},
            "username_reference": "username",
            "password_reference": "password",
            "nonexistent_identifier_reference": "missing",
            "failure_password_reference": "failure",
            "protected_resource": "https://app.example/account",
            "account_marker_selector": "#marker",
            "account_marker_description": "Account marker",
        },
    )

    assert response.status_code == 422
    assert canary not in response.text
    assert response.json()["detail"][0].keys() == {"type", "loc", "msg"}


def test_scan_api_creates_reports_status_and_cancellation(tmp_path: Path) -> None:
    client = TestClient(create_app(data_root=tmp_path, worker_backend="thread"))
    scan_request = {
        "target": {
            "target_url": "https://app.example/login",
            "permitted_origins": ["https://app.example"],
        },
        "selected_checks": [CheckId.LOGIN_ENUMERATION.value],
    }

    created = client.post("/api/scans", json=scan_request)
    assert created.status_code == 201
    scan_id = created.json()["scan_id"]
    assert created.json()["state"] == "created"

    status = client.get(f"/api/scans/{scan_id}")
    assert status.status_code == 200
    assert status.json()["result_count"] == 0

    listing = client.get("/api/scans")
    assert listing.status_code == 200
    assert listing.json()[0]["scan_id"] == scan_id
    assert listing.json()[0]["target_url"] == "https://app.example/login"

    events = client.get(f"/api/scans/{scan_id}/events")
    assert events.status_code == 200
    assert events.json() == []

    cancelled = client.post(f"/api/scans/{scan_id}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"

    execution = {
        "runtime_secrets": {"password": "must-not-be-saved"},
        "username_reference": "username",
        "password_reference": "password",
        "nonexistent_identifier_reference": "missing",
        "failure_password_reference": "password",
        "protected_resource": "https://app.example/account",
        "account_marker_selector": "#marker",
        "account_marker_description": "Private account marker",
    }
    cannot_start = client.post(f"/api/scans/{scan_id}/start", json=execution)
    assert cannot_start.status_code == 409
    assert "must-not-be-saved" not in (tmp_path / scan_id / "metadata.json").read_text()

    reopened_client = TestClient(
        create_app(data_root=tmp_path, worker_backend="thread")
    )
    persisted = reopened_client.get(f"/api/scans/{scan_id}")
    assert persisted.status_code == 200
    assert persisted.json()["state"] == "cancelled"

    missing = client.get(f"/api/scans/{uuid4()}")
    assert missing.status_code == 404


def test_automatic_discovery_failure_pauses_for_guidance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = TestClient(create_app(data_root=tmp_path, worker_backend="thread"))
    created = client.post(
        "/api/scans",
        json={
            "target": {
                "target_url": "https://app.example/login",
                "permitted_origins": ["https://app.example"],
            },
            "selected_checks": [CheckId.LOGIN_ENUMERATION.value],
        },
    )
    scan_id = created.json()["scan_id"]

    async def fail_automatic_discovery(*args: Any, **kwargs: Any) -> None:
        raise LoginFormDiscoveryError("Expected one submit control, found 2")

    monkeypatch.setattr(
        "authflowguard.scan_manager.execute_verified_login_flow",
        fail_automatic_discovery,
    )
    response = client.post(
        f"/api/scans/{scan_id}/start",
        json={
            "runtime_secrets": {"username": "developer", "password": "secret"},
            "username_reference": "username",
            "password_reference": "password",
            "nonexistent_identifier_reference": "missing",
            "failure_password_reference": "failure",
            "protected_resource": "https://app.example/account",
            "account_marker_selector": "#marker",
            "account_marker_description": "Account marker",
        },
    )
    assert response.status_code == 200

    for _ in range(100):
        status = client.get(f"/api/scans/{scan_id}").json()
        if status["state"] == ScanState.AWAITING_GUIDANCE.value:
            break
        time.sleep(0.01)
    assert status["state"] == ScanState.AWAITING_GUIDANCE.value
    assert status["guidance_required"] is True
    assert "submit control" in status["error"]
    assert "secret" not in (tmp_path / scan_id / "metadata.json").read_text()


def test_new_scan_revalidates_and_reuses_a_matching_saved_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = create_app(data_root=tmp_path, worker_backend="thread")
    manager = application.state.scan_manager
    target = TargetScope(
        target_url="https://app.example/login",
        permitted_origins=["https://app.example"],
    )
    saved = manager.create_scan(
        ScanRequest(
            target=target,
            selected_checks=[CheckId.REGISTRATION_ENUMERATION],
        )
    )
    saved.state = ScanState.COMPLETED
    saved.profile = AuthProfile(
        target=target,
        features={AuthFeature.LOGIN: FeatureStatus.VERIFIED},
        authentication_steps={
            AuthFeature.LOGIN: [
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url="https://app.example/login",
                    description="Open login",
                )
            ]
        },
        control_signatures={"control-1": "stable-signature"},
        protected_resource_check=ProtectedResourceCheck(
            resource="https://app.example/account",
            authenticated_evidence_ids=[uuid4()],
            anonymous_evidence_ids=[uuid4()],
            account_marker_description="Account marker",
        ),
    )
    current = manager.create_scan(
        ScanRequest(
            target=target,
            selected_checks=[CheckId.REGISTRATION_ENUMERATION],
        )
    )
    calls: list[str] = []

    async def fake_revalidate(**kwargs: Any) -> None:
        calls.append("revalidate")

    async def fake_replay(**kwargs: Any) -> VerifiedLoginExecution:
        calls.append("replay")
        return VerifiedLoginExecution(profile=saved.profile, events=[], traffic=[])

    monkeypatch.setattr(
        "authflowguard.scan_manager.revalidate_auth_profile", fake_revalidate
    )
    monkeypatch.setattr(
        "authflowguard.scan_manager.replay_verified_auth_profile", fake_replay
    )
    monkeypatch.setattr(
        "authflowguard.scan_manager.execute_verified_login_flow",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("automatic discovery should not run")
        ),
    )

    manager.start_scan(
        current.scan_id,
        ScanExecutionInput(
            runtime_secrets={},
            username_reference="username",
            password_reference="password",
            nonexistent_identifier_reference="missing",
            failure_password_reference="failure",
            protected_resource="https://app.example/account",
            account_marker_selector="#marker",
            account_marker_description="Account marker",
        ),
    )
    assert current.future is not None
    current.future.result(timeout=5)

    assert calls == ["revalidate", "replay"]
    assert current.state is ScanState.COMPLETED


def test_guidance_api_observes_safe_controls_and_accepts_structured_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "guidance-observation-canary-2-2"
    application = create_app(data_root=tmp_path, worker_backend="thread")
    manager = application.state.scan_manager
    record = manager.create_scan(
        ScanRequest(
            target={
                "target_url": "https://app.example/login",
                "permitted_origins": ["https://app.example"],
            },
            selected_checks=[CheckId.LOGIN_ENUMERATION],
        )
    )
    record.state = ScanState.AWAITING_GUIDANCE
    record.pending_execution = ScanExecutionInput(
        runtime_secrets={"username": "developer", "password": canary},
        username_reference="username",
        password_reference="password",
        nonexistent_identifier_reference="missing",
        failure_password_reference="failure",
        protected_resource="https://app.example/account",
        account_marker_selector="#marker",
        account_marker_description="Account marker",
    )
    manager._persist_state(record)

    control: SafeControlDescription = {
        "observed_control_id": "control-1",
        "tag": "input",
        "id": "username",
        "name": "username",
        "type": "text",
        "placeholder": f"Echoed {canary}",
        "autocomplete": "username",
        "aria_label": None,
        "value_present": False,
        "visible": True,
    }
    event = EvidenceEvent(
        event_id=uuid4(),
        scan_id=record.scan_id,
        kind=EvidenceKind.PAGE_STATE,
        summary="Observed controls",
        redacted_details={
            "url": "https://app.example/login",
            "title": f"Login {canary}",
            "controls": [control],
        },
    )

    async def fake_observation(*args: Any, **kwargs: Any) -> GuidedPageObservation:
        return GuidedPageObservation(event=event, controls=[control])

    monkeypatch.setattr(
        "authflowguard.scan_manager.observe_guidance_page", fake_observation
    )
    client = TestClient(application)

    observed = client.post(f"/api/scans/{record.scan_id}/guidance/observe")
    assert observed.status_code == 200
    assert observed.json()["controls"][0]["observed_control_id"] == "control-1"
    assert canary not in observed.text
    assert all(
        canary not in path.read_text(encoding="utf-8")
        for path in (tmp_path / str(record.scan_id)).rglob("*")
        if path.is_file()
    )

    submitted = []
    monkeypatch.setattr(
        manager._executor,
        "submit",
        lambda *args: submitted.append(args),
    )
    guidance = client.post(
        f"/api/scans/{record.scan_id}/guidance",
        json={
            "actions": [
                {
                    "action_type": "navigate",
                    "url": "https://app.example/login?do-not-save=yes",
                    "description": "Open the login page",
                },
                {
                    "action_type": "fill",
                    "observed_control_id": "control-1",
                    "value_reference": "username",
                    "description": "Fill the username",
                },
            ]
        },
    )
    assert guidance.status_code == 200
    assert guidance.json()["state"] == ScanState.RUNNING.value
    assert len(submitted) == 1
    assert str(submitted[0][3].actions[0].url) == (
        "https://app.example/login?do-not-save=yes"
    )
