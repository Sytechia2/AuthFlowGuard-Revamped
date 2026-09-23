"""Public scan-state, recovery, and API error contracts."""

import json
from concurrent.futures import Future
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from authflowguard.app import create_app
from authflowguard.models import CheckId, ScanRequest
from authflowguard.scan_manager import ScanExecutionInput, ScanManager, ScanState
from fastapi.testclient import TestClient


def _request() -> ScanRequest:
    return ScanRequest(
        target={
            "target_url": "https://app.example/login",
            "permitted_origins": ["https://app.example"],
        },
        selected_checks=[CheckId.LOGIN_ENUMERATION],
    )


def _execution_json() -> dict[str, Any]:
    return {
        "runtime_secrets": {"password": "private"},
        "username_reference": "username",
        "password_reference": "password",
        "nonexistent_identifier_reference": "missing",
        "failure_password_reference": "failure",
        "protected_resource": "https://app.example/account",
        "account_marker_selector": "#account",
        "account_marker_description": "Account marker",
    }


def _execution() -> ScanExecutionInput:
    return ScanExecutionInput.model_validate(_execution_json())


def _unscheduled_future(*_args: Any) -> Future[None]:
    return Future()


@pytest.mark.parametrize(
    "state",
    [
        ScanState.RUNNING,
        ScanState.AWAITING_GUIDANCE,
        ScanState.COMPLETED,
        ScanState.FAILED,
        ScanState.CANCELLED,
    ],
)
def test_start_has_one_error_contract_in_every_invalid_state(
    tmp_path: Path,
    state: ScanState,
) -> None:
    application = create_app(data_root=tmp_path)
    manager: ScanManager = application.state.scan_manager
    record = manager.create_scan(_request())
    record.state = state
    manager._persist_state(record)

    response = TestClient(application).post(
        f"/api/scans/{record.scan_id}/start", json=_execution_json()
    )

    assert response.status_code == 409
    assert response.json()["code"] == "invalid_scan_state"
    assert record.future is None


@pytest.mark.parametrize(
    "endpoint,method",
    [
        ("", "get"),
        ("/events", "get"),
        ("/cancel", "post"),
        ("/reanalyse", "post"),
        ("/report/json", "get"),
    ],
)
def test_unknown_scan_actions_share_not_found_contract(
    tmp_path: Path,
    endpoint: str,
    method: str,
) -> None:
    client = TestClient(create_app(data_root=tmp_path))

    response = getattr(client, method)(f"/api/scans/{uuid4()}{endpoint}")

    assert response.status_code == 404
    assert response.json()["code"] == "scan_not_found"


def test_report_and_evidence_errors_are_distinct(tmp_path: Path) -> None:
    application = create_app(data_root=tmp_path)
    manager: ScanManager = application.state.scan_manager
    record = manager.create_scan(_request())
    client = TestClient(application)

    missing_report = client.get(f"/api/scans/{record.scan_id}/report/json")
    invalid_format = client.get(f"/api/scans/{record.scan_id}/report/xml")
    unfinished_reanalysis = client.post(f"/api/scans/{record.scan_id}/reanalyse")
    record.state = ScanState.FAILED
    manager._persist_state(record)
    missing_evidence = client.post(f"/api/scans/{record.scan_id}/reanalyse")

    assert missing_report.status_code == 404
    assert missing_report.json()["code"] == "report_not_available"
    assert invalid_format.status_code == 422
    assert invalid_format.json()["code"] == "invalid_report_format"
    assert unfinished_reanalysis.status_code == 409
    assert unfinished_reanalysis.json()["code"] == "invalid_scan_state"
    assert missing_evidence.status_code == 409
    assert missing_evidence.json()["code"] == "evidence_not_available"


def test_malformed_uuid_uses_safe_invalid_request_contract(tmp_path: Path) -> None:
    response = TestClient(create_app(data_root=tmp_path)).get("/api/scans/not-a-uuid")

    assert response.status_code == 422
    assert response.json()["code"] == "invalid_request"
    assert response.json()["detail"][0]["loc"] == ["path"]


def test_transition_timestamps_are_persisted_and_terminal_state_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path)
    record = manager.create_scan(_request())
    monkeypatch.setattr(manager._executor, "submit", _unscheduled_future)

    manager.start_scan(record.scan_id, _execution())
    running_snapshot = manager.snapshot(record)
    manager.cancel_scan(record.scan_id)
    manager._finalize_cancelled(record)
    manager._finalize_failed(record, RuntimeError("late worker failure"))
    cancelled_snapshot = manager.snapshot(record)
    metadata = json.loads(
        (tmp_path / str(record.scan_id) / "metadata.json").read_text(encoding="utf-8")
    )

    assert running_snapshot["started_at"] is not None
    assert running_snapshot["finished_at"] is None
    assert cancelled_snapshot["state"] == ScanState.CANCELLED.value
    assert cancelled_snapshot["error_code"] == "scan_cancelled"
    assert cancelled_snapshot["finished_at"] is not None
    assert metadata["state"] == ScanState.CANCELLED.value
    assert metadata["finished_at"] == cancelled_snapshot["finished_at"]


def test_cancelling_terminal_scan_is_an_idempotent_no_op(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path)
    record = manager.create_scan(_request())
    monkeypatch.setattr(manager._executor, "submit", _unscheduled_future)
    manager.start_scan(record.scan_id, _execution())
    manager._transition(record, ScanState.COMPLETED, error=None, error_code=None)
    before = manager.snapshot(record)

    manager.cancel_scan(record.scan_id)
    after = manager.snapshot(record)

    assert after == before
    assert record.cancel_requested is False


def test_stale_worker_generation_cannot_finalize_newer_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path)
    record = manager.create_scan(_request())
    monkeypatch.setattr(manager._executor, "submit", _unscheduled_future)
    manager.start_scan(record.scan_id, _execution())
    stale_generation = record.worker_generation
    record.worker_generation += 1

    manager._finalize_failed(
        record,
        RuntimeError("late callback"),
        stale_generation,
    )

    assert record.state is ScanState.RUNNING
    assert record.error_code is None

    manager._finalize_failed(
        record,
        RuntimeError("current callback"),
        record.worker_generation,
    )
    assert record.state is ScanState.FAILED
    assert record.error_code == "scan_execution_failed"


@pytest.mark.parametrize(
    "cancel_requested,expected_state,expected_code",
    [
        (False, ScanState.FAILED, "backend_restarted"),
        (True, ScanState.CANCELLED, "scan_cancelled"),
    ],
)
def test_restart_reconciles_interrupted_scans_without_resuming_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cancel_requested: bool,
    expected_state: ScanState,
    expected_code: str,
) -> None:
    manager = ScanManager(tmp_path)
    record = manager.create_scan(_request())
    monkeypatch.setattr(manager._executor, "submit", _unscheduled_future)
    manager.start_scan(record.scan_id, _execution())
    if cancel_requested:
        manager.cancel_scan(record.scan_id)

    recovered = ScanManager(tmp_path).get_scan(record.scan_id)

    assert recovered.state is expected_state
    assert recovered.error_code == expected_code
    assert recovered.finished_at is not None
    assert recovered.future is None
    assert recovered.pending_execution is None


def test_corrupt_scan_metadata_is_reported_instead_of_hidden(tmp_path: Path) -> None:
    manager = ScanManager(tmp_path)
    record = manager.create_scan(_request())
    metadata_path = tmp_path / str(record.scan_id) / "metadata.json"
    metadata_path.write_text("{truncated", encoding="utf-8")

    response = TestClient(create_app(data_root=tmp_path)).get(
        f"/api/scans/{record.scan_id}"
    )

    assert response.status_code == 409
    assert response.json() == {
        "code": "scan_recovery_failed",
        "detail": "The persisted scan could not be recovered safely",
    }
