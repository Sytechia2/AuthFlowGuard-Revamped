"""Spawned-process ownership, responsiveness, crash, and cleanup tests."""

import asyncio
import os
import subprocess
import sys
import time
from concurrent.futures import Future
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from authflowguard.app import create_app
from authflowguard.evaluation_targets.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
)
from authflowguard.models import CheckId, ScanRequest
from authflowguard.scan_manager import (
    GuidanceSubmission,
    ScanBusyError,
    ScanExecutionInput,
    ScanManager,
    ScanState,
)
from authflowguard.worker_protocol import (
    WorkerCommand,
    WorkerMessage,
    WorkerMessageType,
    WorkerOperation,
)
from authflowguard.worker_supervisor import WorkerSupervisor
from fastapi.testclient import TestClient
from test_authentication import guided_login_actions, run_controlled_server


def _unresponsive_worker(
    command_data: dict[str, Any], output: Any, _control: Any, _cancel_event: Any
) -> None:
    command = WorkerCommand.model_validate(command_data)
    output.put(
        WorkerMessage(
            correlation_id=command.correlation_id,
            scan_id=command.scan_id,
            worker_generation=command.worker_generation,
            sequence=1,
            message_type=WorkerMessageType.READY,
        ).model_dump(mode="json")
    )
    time.sleep(30)


def _request() -> ScanRequest:
    return ScanRequest(
        target={
            "target_url": "http://10.255.255.1/login",
            "permitted_origins": ["http://10.255.255.1"],
        },
        selected_checks=[CheckId.LOGIN_ENUMERATION],
    )


def _execution() -> ScanExecutionInput:
    return ScanExecutionInput(
        runtime_secrets={
            "username": "process-user-canary",
            "password": "process-password-canary",
            "missing": "missing@example.test",
            "failure": "wrong-password",
        },
        username_reference="username",
        password_reference="password",
        nonexistent_identifier_reference="missing",
        failure_password_reference="failure",
        protected_resource="http://10.255.255.1/account",
        account_marker_selector="#account",
        account_marker_description="Account marker",
    )


def _controlled_execution(origin: str) -> ScanExecutionInput:
    return ScanExecutionInput(
        runtime_secrets={
            "login-username": KNOWN_USERNAME,
            "login-password": KNOWN_PASSWORD,
            "missing": "missing@example.test",
            "failure": "wrong-password",
        },
        username_reference="login-username",
        password_reference="login-password",
        nonexistent_identifier_reference="missing",
        failure_password_reference="failure",
        protected_resource=f"{origin}/account",
        account_marker_selector='[data-testid="account-marker"]',
        account_marker_description="Authenticated account marker",
    )


def test_process_worker_keeps_api_responsive_and_releases_slot_after_cancel(
    tmp_path: Path,
) -> None:
    application = create_app(data_root=tmp_path)
    manager: ScanManager = application.state.scan_manager
    first = manager.create_scan(_request())
    second = manager.create_scan(_request())
    execution = _execution()
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        manager.start_scan(first.scan_id, execution)
        assert execution.runtime_secrets == {}
        assert manager._supervisor is not None
        handle = manager._supervisor._get(first.scan_id, first.worker_generation)
        assert handle is not None
        assert handle.process.pid != os.getpid()

        started = time.monotonic()
        health = TestClient(application).get("/api/health")
        latency = time.monotonic() - started
        assert health.status_code == 200
        assert latency < 0.5

        with pytest.raises(ScanBusyError):
            manager.start_scan(second.scan_id, _execution())

        cancellation_started = time.monotonic()
        manager.cancel_scan(first.scan_id)
        assert first.future is not None
        first.future.result(timeout=10)

        assert first.state is ScanState.CANCELLED
        assert first.worker_active is False
        assert time.monotonic() - cancellation_started < 5
        assert first.worker_cleanup in {"graceful", "forced"}
        assert first.worker_cleanup_seconds is not None
        assert first.worker_cleanup_seconds < 5
        assert not handle.process.is_alive()
        assert unrelated.poll() is None
        persisted = "".join(
            path.read_text(encoding="utf-8")
            for path in (tmp_path / str(first.scan_id)).rglob("*")
            if path.is_file()
        )
        assert "process-user-canary" not in persisted
        assert "process-password-canary" not in persisted

        manager.start_scan(second.scan_id, _execution())
        manager.cancel_scan(second.scan_id)
        assert second.future is not None
        second.future.result(timeout=10)
        assert second.state is ScanState.CANCELLED
    finally:
        manager.shutdown()
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_abrupt_worker_exit_becomes_safe_failed_state(tmp_path: Path) -> None:
    manager = ScanManager(tmp_path, cancellation_grace_seconds=0.2)
    record = manager.create_scan(_request())
    try:
        manager.start_scan(record.scan_id, _execution())
        assert manager._supervisor is not None
        handle = manager._supervisor._get(record.scan_id, record.worker_generation)
        assert handle is not None

        handle.process.terminate()
        assert record.future is not None
        record.future.result(timeout=10)

        assert record.state is ScanState.FAILED
        assert record.error_code == "scan_worker_crashed"
        assert record.worker_active is False
        assert not handle.process.is_alive()
        assert (tmp_path / str(record.scan_id) / "report.json").exists()
    finally:
        manager.shutdown()


def test_unresponsive_worker_is_force_terminated_after_grace_deadline(
    tmp_path: Path,
) -> None:
    supervisor = WorkerSupervisor(
        cancellation_grace_seconds=0.1,
        entrypoint=_unresponsive_worker,
    )
    scan_id = UUID("00000000-0000-0000-0000-000000000024")
    command = WorkerCommand(
        scan_id=scan_id,
        worker_generation=1,
        operation=WorkerOperation.OBSERVE_GUIDANCE,
        data_root=str(tmp_path),
        request=_request(),
    )
    result: Future[tuple[WorkerMessage | None, int | None, bool]] = Future()
    future = supervisor.start(
        command,
        lambda message, exit_code, forced: result.set_result(
            (message, exit_code, forced)
        ),
    )
    identity = supervisor.identity(scan_id, 1)
    assert identity is not None

    started = time.monotonic()
    assert supervisor.cancel(scan_id, 1) is True
    future.result(timeout=5)
    message, exit_code, forced = result.result(timeout=1)

    assert time.monotonic() - started < 5
    assert forced is True
    assert message is not None
    assert message.message_type is WorkerMessageType.READY
    assert exit_code not in {0, None}
    assert supervisor.is_active(scan_id, 1) is False


def test_manager_shutdown_reaps_its_active_worker(tmp_path: Path) -> None:
    manager = ScanManager(tmp_path, cancellation_grace_seconds=0.2)
    record = manager.create_scan(_request())
    manager.start_scan(record.scan_id, _execution())
    assert manager._supervisor is not None
    handle = manager._supervisor._get(record.scan_id, record.worker_generation)
    assert handle is not None

    manager.shutdown()
    assert record.future is not None
    record.future.result(timeout=5)

    assert not handle.process.is_alive()
    assert record.worker_active is False
    assert record.state is ScanState.CANCELLED


def test_parent_durably_acknowledges_worker_usage_transitions(tmp_path: Path) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    record = manager.create_scan(_request())
    record.worker_generation = 1
    record.worker_active = True
    manager._transition(record, ScanState.RUNNING)
    correlation_id = uuid4()
    attempt_id = uuid4()

    def message(message_type: WorkerMessageType, **updates: Any) -> WorkerMessage:
        return WorkerMessage(
            correlation_id=correlation_id,
            scan_id=record.scan_id,
            worker_generation=1,
            sequence=1,
            message_type=message_type,
            attempt_id=attempt_id,
            **updates,
        )

    reservation = manager._apply_process_result(
        record,
        1,
        message(
            WorkerMessageType.USAGE_RESERVE,
            model_id="amazon.nova-micro-v1:0",
            region="us-east-1",
            reserved_cost_usd=0.01,
            input_price_usd_per_1000_tokens=0.000035,
            output_price_usd_per_1000_tokens=0.00014,
        ),
        None,
        False,
    )
    assert reservation is not None and reservation.accepted
    dispatched = manager._apply_process_result(
        record,
        1,
        message(WorkerMessageType.USAGE_DISPATCHED),
        None,
        False,
    )
    assert dispatched is not None and dispatched.accepted
    settlement = manager._apply_process_result(
        record,
        1,
        message(
            WorkerMessageType.USAGE_SETTLE,
            input_tokens=100,
            output_tokens=20,
            actual_cost_usd=0.001,
        ),
        None,
        False,
    )
    assert settlement is not None and settlement.accepted

    restored = ScanManager(tmp_path, worker_backend="thread")
    try:
        usage = restored.snapshot(restored.get_scan(record.scan_id))["usage"]
        assert usage["input_tokens"] == 100
        assert usage["settled_cost_usd"] == "0.00100000"
        assert usage["outstanding_reserved_cost_usd"] == "0.00000000"
    finally:
        manager.shutdown()
        restored.shutdown()


def test_complete_scan_runs_and_persists_outside_api_process(tmp_path: Path) -> None:
    with run_controlled_server() as origin:
        manager = ScanManager(tmp_path)
        record = manager.create_scan(
            ScanRequest(
                target={
                    "target_url": f"{origin}/login",
                    "permitted_origins": [origin],
                },
                selected_checks=[CheckId.LOGIN_ENUMERATION],
            )
        )
        try:
            manager.start_scan(record.scan_id, _controlled_execution(origin))
            assert manager._supervisor is not None
            handle = manager._supervisor._get(record.scan_id, record.worker_generation)
            assert handle is not None
            worker_pid = handle.process.pid
            assert worker_pid != os.getpid()
            assert record.future is not None
            record.future.result(timeout=90)

            assert record.state is ScanState.COMPLETED
            assert record.evidence
            assert record.results
            assert record.completed_checks == [CheckId.LOGIN_ENUMERATION]
            assert not handle.process.is_alive()
            assert (tmp_path / str(record.scan_id) / "report.json").exists()
        finally:
            manager.shutdown()


def test_guidance_observation_and_replay_use_spawned_workers(tmp_path: Path) -> None:
    with run_controlled_server() as origin:
        manager = ScanManager(tmp_path)
        record = manager.create_scan(
            ScanRequest(
                target={
                    "target_url": f"{origin}/login",
                    "permitted_origins": [origin],
                },
                selected_checks=[CheckId.LOGIN_ENUMERATION],
            )
        )
        record.state = ScanState.AWAITING_GUIDANCE
        record.pending_execution = _controlled_execution(origin)
        manager._persist_state(record)
        try:
            observation = asyncio.run(manager.observe_guidance(record.scan_id))

            assert observation["controls"]
            assert record.state is ScanState.AWAITING_GUIDANCE
            assert record.worker_active is False
            assert record.pending_execution is not None

            manager.submit_guidance(
                record.scan_id,
                GuidanceSubmission(actions=guided_login_actions(origin)),
            )
            assert record.future is not None
            record.future.result(timeout=90)

            assert record.state is ScanState.COMPLETED
            assert record.profile is not None
            assert record.evidence
            assert record.results
        finally:
            manager.shutdown()
