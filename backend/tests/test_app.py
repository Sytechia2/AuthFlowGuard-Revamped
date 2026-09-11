"""Tests for the local backend application."""

from pathlib import Path

from authflowguard.app import app, create_app
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
