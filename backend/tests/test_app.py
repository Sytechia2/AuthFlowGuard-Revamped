"""Tests for the local backend application."""

from fastapi.testclient import TestClient

from authflowguard.app import app


def test_health_endpoint_reports_that_the_backend_is_available() -> None:
    client = TestClient(app)

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
