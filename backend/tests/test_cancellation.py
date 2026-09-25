"""Deterministic scan cancellation and cleanup tests."""

import asyncio
import time
from pathlib import Path
from threading import Event
from typing import Any

import pytest
from authflowguard.authentication import (
    LoginFormDiscoveryError,
    VerifiedLoginExecution,
)
from authflowguard.cancellation import CancellationControl, close_resources
from authflowguard.checks.login_enumeration import LoginEnumerationRun
from authflowguard.models import CheckId, ScanRequest
from authflowguard.scan_manager import ScanExecutionInput, ScanManager, ScanState
from test_form_enumeration import make_evidence, profile_for


def _request() -> ScanRequest:
    return ScanRequest(
        target={
            "target_url": "https://app.example/login",
            "permitted_origins": ["https://app.example"],
        },
        selected_checks=[CheckId.LOGIN_ENUMERATION],
    )


def _execution() -> ScanExecutionInput:
    return ScanExecutionInput(
        runtime_secrets={"password": "not-persisted"},
        username_reference="username",
        password_reference="password",
        nonexistent_identifier_reference="missing",
        failure_password_reference="failure",
        protected_resource="https://app.example/account",
        account_marker_selector="#account",
        account_marker_description="Account marker",
    )


def test_cancellation_interrupts_active_await_and_waits_for_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    record = manager.create_scan(_request())
    started = Event()
    cleaned = Event()

    async def blocked_login(**_kwargs: Any) -> None:
        started.set()
        try:
            await asyncio.Future()
        finally:
            cleaned.set()

    monkeypatch.setattr(
        "authflowguard.scan_manager.execute_verified_login_flow", blocked_login
    )
    execution = _execution()
    manager.start_scan(record.scan_id, execution)
    assert started.wait(2)

    cancellation_started = time.monotonic()
    cancelling = manager.cancel_scan(record.scan_id)
    assert cancelling.cancel_requested is True
    assert cancelling.state is ScanState.RUNNING
    assert record.future is not None
    record.future.result(timeout=2)
    cancellation_latency = time.monotonic() - cancellation_started

    assert cleaned.is_set()
    assert record.state is ScanState.CANCELLED
    assert record.error == "Scan execution cancelled"
    assert execution.runtime_secrets == {}
    assert cancellation_latency < 5
    assert (tmp_path / str(record.scan_id) / "report.json").exists()


def test_repeated_cancellation_is_idempotent(tmp_path: Path) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    record = manager.create_scan(_request())

    first = manager.cancel_scan(record.scan_id)
    second = manager.cancel_scan(record.scan_id)

    assert first is second
    assert record.state is ScanState.CANCELLED
    assert record.cancel_requested is True
    assert manager.snapshot(record)["execution_progress"]["cancelled_checks"] == [
        CheckId.LOGIN_ENUMERATION.value
    ]


def test_guidance_retains_credentials_only_until_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "guidance-credential-canary-2-2"
    manager = ScanManager(tmp_path, worker_backend="thread")
    record = manager.create_scan(_request())
    execution = _execution()
    execution.runtime_secrets["password"] = canary

    async def require_guidance(**_kwargs: Any) -> None:
        raise LoginFormDiscoveryError(f"Page echoed {canary}")

    monkeypatch.setattr(
        "authflowguard.scan_manager.execute_verified_login_flow", require_guidance
    )
    manager.start_scan(record.scan_id, execution)
    assert record.future is not None
    record.future.result(timeout=2)

    assert record.state is ScanState.AWAITING_GUIDANCE
    assert record.pending_execution is execution
    assert execution.runtime_secrets["password"] == canary
    assert canary not in (record.error or "")
    assert all(
        canary not in path.read_text(encoding="utf-8")
        for path in (tmp_path / str(record.scan_id)).rglob("*")
        if path.is_file()
    )

    manager.cancel_scan(record.scan_id)

    assert record.state is ScanState.CANCELLED
    assert record.pending_execution is None
    assert execution.runtime_secrets == {}


def test_rejected_start_discards_submitted_credentials(tmp_path: Path) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    record = manager.create_scan(_request())
    manager.cancel_scan(record.scan_id)
    execution = _execution()

    with pytest.raises(ValueError, match="Only a created scan"):
        manager.start_scan(record.scan_id, execution)

    assert execution.runtime_secrets == {}


def test_failed_execution_discards_submitted_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    record = manager.create_scan(_request())
    execution = _execution()

    async def fail_login(**_kwargs: Any) -> None:
        raise RuntimeError("browser failed")

    monkeypatch.setattr(
        "authflowguard.scan_manager.execute_verified_login_flow", fail_login
    )
    manager.start_scan(record.scan_id, execution)
    assert record.future is not None
    record.future.result(timeout=2)

    assert record.state is ScanState.FAILED
    assert execution.runtime_secrets == {}


def test_successful_execution_discards_submitted_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    record = manager.create_scan(_request())
    execution = _execution()

    async def fake_login(**_kwargs: Any) -> object:
        return object()

    async def complete(record: Any, *_args: Any) -> None:
        record.state = ScanState.COMPLETED

    monkeypatch.setattr(
        "authflowguard.scan_manager.execute_verified_login_flow", fake_login
    )
    monkeypatch.setattr(manager, "_complete_profile_execution", complete)
    manager.start_scan(record.scan_id, execution)
    assert record.future is not None
    record.future.result(timeout=2)

    assert record.state is ScanState.COMPLETED
    assert execution.runtime_secrets == {}


def test_pre_start_cancellation_prevents_registered_work() -> None:
    control = CancellationControl()
    entered = False
    control.request()

    async def run() -> None:
        nonlocal entered
        with control.register_current_task():
            entered = True

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run())
    assert entered is False
    assert control.has_active_work is False


def test_cancelled_state_and_progress_reload(tmp_path: Path) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    record = manager.create_scan(_request())
    manager.cancel_scan(record.scan_id)

    reloaded = ScanManager(tmp_path, worker_backend="thread").get_scan(record.scan_id)

    assert reloaded.state is ScanState.CANCELLED
    assert reloaded.cancel_requested is True
    assert "cancelled" in (tmp_path / str(record.scan_id) / "report.html").read_text()


def test_cleanup_attempts_every_resource_and_preserves_primary_error() -> None:
    closed: list[str] = []

    class Resource:
        def __init__(self, name: str, fail: bool = False) -> None:
            self.name = name
            self.fail = fail

        async def close(self) -> None:
            closed.append(self.name)
            if self.fail:
                raise RuntimeError(f"{self.name} close failed")

    async def operation() -> None:
        try:
            raise ValueError("primary")
        finally:
            await close_resources(Resource("context", fail=True), Resource("browser"))

    with pytest.raises(ValueError, match="primary"):
        asyncio.run(operation())
    assert closed == ["context", "browser"]


def test_cancellation_during_a_check_leaves_no_active_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    profile = profile_for("https://app.example")
    record = manager.create_scan(
        ScanRequest(target=profile.target, selected_checks=[CheckId.LOGIN_ENUMERATION])
    )
    manager._transition(record, ScanState.RUNNING)

    async def cancelled_mid_check(**kwargs: Any) -> LoginEnumerationRun:
        assert record.active_check is CheckId.LOGIN_ENUMERATION
        record.cancellation.request()
        evidence = make_evidence(CheckId.LOGIN_ENUMERATION)
        evidence.scan_id = kwargs["scan_id"]
        return LoginEnumerationRun(evidence=evidence, events=[])

    monkeypatch.setattr(
        "authflowguard.scan_manager.run_login_enumeration_check",
        cancelled_mid_check,
    )
    asyncio.run(
        manager._complete_profile_execution(
            record,
            _execution(),
            VerifiedLoginExecution(profile=profile, events=[], traffic=[]),
        )
    )

    snapshot = manager.snapshot(record)
    assert record.state is ScanState.CANCELLED
    assert record.active_check is None
    assert snapshot["execution_progress"]["active_check"] is None
    assert snapshot["execution_progress"]["cancelled_checks"] == [
        CheckId.LOGIN_ENUMERATION.value
    ]
