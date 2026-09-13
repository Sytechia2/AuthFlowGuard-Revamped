"""Tests for the local backend application."""

from pathlib import Path
from uuid import uuid4

from authflowguard.app import app, create_app
from authflowguard.models import CheckId
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


def test_scan_api_creates_reports_status_and_cancellation(tmp_path: Path) -> None:
    client = TestClient(create_app(data_root=tmp_path))
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

    reopened_client = TestClient(create_app(data_root=tmp_path))
    persisted = reopened_client.get(f"/api/scans/{scan_id}")
    assert persisted.status_code == 200
    assert persisted.json()["state"] == "cancelled"

    missing = client.get(f"/api/scans/{uuid4()}")
    assert missing.status_code == 404
