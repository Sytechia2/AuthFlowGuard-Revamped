"""Spawned-process ownership, responsiveness, crash, and cleanup tests."""

import asyncio
import os
import subprocess
import sys
import time
from concurrent.futures import Future
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from authflowguard.app import create_app
from authflowguard.evaluation.cost_tracking import (
    CostEntry,
    CostLedgerStore,
    UsageSource,
    WorkflowPhase,
)
from authflowguard.evaluation_targets.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
)
from authflowguard.models import (
    CheckId,
    DiscoveryMode,
    DiscoveryProvenance,
    ScanRequest,
)
from authflowguard.scan_manager import (
    GuidanceSubmission,
    ScanBusyError,
    ScanExecutionInput,
    ScanManager,
    ScanRecord,
    ScanState,
)
from authflowguard.scan_worker import _ArtifactWorkerManager
from authflowguard.worker_protocol import (
    WorkerCommand,
    WorkerMessage,
    WorkerMessageType,
    WorkerOperation,
    WorkerProgress,
)
from authflowguard.worker_supervisor import WorkerSupervisor
from fastapi.testclient import TestClient
from test_authentication import guided_login_actions, run_controlled_server


def _never_ready_worker(
    _command_data: dict[str, Any], _output: Any, _cancel_event: Any
) -> None:
    time.sleep(30)


def _unresponsive_worker(
    command_data: dict[str, Any], output: Any, _cancel_event: Any
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


def _wait_until_ready(
    supervisor: WorkerSupervisor, scan_id: UUID, generation: int
) -> None:
    handle = supervisor._get(scan_id, generation)
    assert handle is not None
    assert handle.ready.wait(timeout=30)


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
    result: Future[tuple[WorkerMessage | None, int | None, bool, bool]] = Future()
    future = supervisor.start(
        command,
        lambda message, exit_code, forced, timed_out: result.set_result(
            (message, exit_code, forced, timed_out)
        ),
    )
    identity = supervisor.identity(scan_id, 1)
    assert identity is not None

    _wait_until_ready(supervisor, scan_id, 1)
    started = time.monotonic()
    assert supervisor.cancel(scan_id, 1) is True
    future.result(timeout=5)
    message, exit_code, forced, timed_out = result.result(timeout=1)

    assert time.monotonic() - started < 5
    assert forced is True
    assert timed_out is False
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


def test_worker_start_does_not_wait_and_startup_timeout_fails_safely(
    tmp_path: Path,
) -> None:
    manager = ScanManager(tmp_path, cancellation_grace_seconds=0.2)
    manager._supervisor = WorkerSupervisor(
        cancellation_grace_seconds=0.2,
        entrypoint=_never_ready_worker,
        startup_timeout_seconds=0.5,
    )
    record = manager.create_scan(_request())
    execution = _execution()
    try:
        started = time.monotonic()
        manager.start_scan(record.scan_id, execution)
        assert time.monotonic() - started < 2
        assert record.state is ScanState.RUNNING
        assert execution.runtime_secrets == {}

        assert record.future is not None
        record.future.result(timeout=10)

        assert record.state is ScanState.FAILED
        assert record.error_code == "scan_worker_timeout"
        assert record.worker_active is False
        assert record.worker_cleanup == "forced"
    finally:
        manager.shutdown()


def test_hung_worker_is_stopped_at_its_runtime_limit(tmp_path: Path) -> None:
    manager = ScanManager(tmp_path, worker_timeout=1.0)
    manager._supervisor = WorkerSupervisor(
        cancellation_grace_seconds=0.2,
        entrypoint=_unresponsive_worker,
    )
    record = manager.create_scan(_request())
    try:
        manager.start_scan(record.scan_id, _execution())
        assert record.future is not None
        record.future.result(timeout=30)

        assert record.state is ScanState.FAILED
        assert record.error_code == "scan_worker_timeout"
        assert record.cancel_requested is False
        assert record.worker_cleanup == "forced"
        assert (tmp_path / str(record.scan_id) / "report.json").exists()
    finally:
        manager.shutdown()


def _bedrock_progress(**updates: Any) -> WorkerProgress:
    values: dict[str, Any] = {
        "phase": "discovering",
        "decision_count": 2,
        "model_request_count": 2,
        "total_input_tokens": 300,
        "total_output_tokens": 40,
        "estimated_cost_usd": 0.0002,
        "unresolved_reservations_usd": 0.0001,
        "provenance": DiscoveryProvenance(
            requested_mode=DiscoveryMode.BEDROCK,
            actual_engine="bedrock",
            usage_source="mock",
            model_id="amazon.nova-micro-v1:0",
        ),
    }
    values.update(updates)
    return WorkerProgress(**values)


def test_worker_progress_mirrors_bedrock_usage_and_ledger_is_authoritative(
    tmp_path: Path,
) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    record = manager.create_scan(_request())
    record.worker_generation = 1
    record.worker_active = True
    manager._transition(record, ScanState.RUNNING)
    correlation_id = uuid4()

    def message(
        message_type: WorkerMessageType, sequence: int, **updates: Any
    ) -> WorkerMessage:
        return WorkerMessage(
            correlation_id=correlation_id,
            scan_id=record.scan_id,
            worker_generation=1,
            sequence=sequence,
            message_type=message_type,
            **updates,
        )

    manager._apply_process_result(
        record,
        1,
        message(WorkerMessageType.PROGRESS, 2, progress=_bedrock_progress()),
        None,
        False,
    )
    live = manager.snapshot(record)
    assert live["decision_count"] == 2
    assert live["phase"] == "discovering"
    assert live["provenance"]["actual_engine"] == "bedrock"
    assert live["usage"]["input_tokens"] == 300
    assert live["usage"]["settled_cost_usd"] == "0.00020000"
    assert live["usage"]["usage_source"] == "mock"

    # The worker's durable ledger, not the progress copy, settles the totals.
    ledger = CostLedgerStore(tmp_path / str(record.scan_id) / "cost-ledger.ndjson")
    common: dict[str, Any] = {
        "request_id": uuid4(),
        "run_id": str(record.scan_id),
        "scan_id": record.scan_id,
        "workflow": "login_discovery",
        "phase": WorkflowPhase.ACTION_SELECTION,
        "model_id": "amazon.nova-micro-v1:0",
        "source": UsageSource.MOCK,
    }
    ledger.append(
        CostEntry(
            **common,
            input_tokens=0,
            output_tokens=0,
            reserved_cost_usd=Decimal("0.001"),
            is_reservation=True,
        )
    )
    ledger.append(
        CostEntry(
            **common,
            input_tokens=1000,
            output_tokens=100,
            reserved_cost_usd=Decimal("0.001"),
            reconciled=True,
        )
    )
    ledger.append(
        CostEntry(
            **{**common, "request_id": uuid4()},
            input_tokens=0,
            output_tokens=0,
            reserved_cost_usd=Decimal("0.002"),
            is_reservation=True,
        )
    )
    manager._apply_process_result(
        record,
        1,
        message(
            WorkerMessageType.FAILED,
            3,
            error="Automatic discovery stopped",
            error_code="scan_execution_failed",
            progress=_bedrock_progress(stop_reason="cost_limit_reached"),
            cleanup_confirmed=True,
        ),
        0,
        False,
    )
    expected = CostLedgerStore(ledger.ledger_path).load_into()
    final = manager.snapshot(record)
    assert record.state is ScanState.FAILED
    assert final["stop_reason"] == "cost_limit_reached"
    assert final["usage"]["input_tokens"] == 1000
    assert final["usage"]["output_tokens"] == 100
    assert final["usage"]["uncertain_requests"] == 1
    assert final["usage"]["outstanding_reserved_cost_usd"] == "0.00200000"
    assert Decimal(str(final["usage"]["settled_cost_usd"])) == (
        expected.total_observed_cost_usd()
    )

    restored = ScanManager(tmp_path, worker_backend="thread")
    try:
        reloaded = restored.snapshot(restored.get_scan(record.scan_id))
        assert reloaded["usage"] == final["usage"]
        assert reloaded["provenance"]["actual_engine"] == "bedrock"
    finally:
        manager.shutdown()
        restored.shutdown()


def test_worker_side_state_changes_publish_full_progress(tmp_path: Path) -> None:
    command = WorkerCommand(
        scan_id=uuid4(),
        worker_generation=1,
        operation=WorkerOperation.SCAN,
        data_root=str(tmp_path),
        request=_request(),
        provenance=DiscoveryProvenance(requested_mode=DiscoveryMode.BEDROCK),
    )
    published: list[dict[str, Any]] = []

    class Output:
        def put(self, item: dict[str, Any], **_kwargs: Any) -> None:
            published.append(item)

    manager = _ArtifactWorkerManager(tmp_path, None, command, Output())
    record = ScanRecord(
        scan_id=command.scan_id,
        request=command.request,
        state=ScanState.RUNNING,
        provenance=command.provenance,
    )
    record.phase = "discovering"
    record.decision_count = 3
    record.total_input_tokens = 900
    record.estimated_cost_usd = 0.0005
    assert record.provenance is not None
    record.provenance.actual_engine = "bedrock"
    try:
        manager._persist_state(record)
    finally:
        manager.shutdown()

    message = WorkerMessage.model_validate(published[-1])
    assert message.message_type is WorkerMessageType.PROGRESS
    assert message.progress is not None
    assert message.progress.decision_count == 3
    assert message.progress.total_input_tokens == 900
    assert message.progress.estimated_cost_usd == 0.0005
    assert message.progress.provenance is not None
    assert message.progress.provenance.actual_engine == "bedrock"


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
