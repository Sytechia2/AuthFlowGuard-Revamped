"""Spawned scan-worker runtime; imported only inside a child process."""

from __future__ import annotations

import asyncio
import queue
from pathlib import Path
from typing import Any

from authflowguard.authentication import observe_guidance_page
from authflowguard.control_safety import SafeMessageError
from authflowguard.evidence import redact_persisted_data, transient_secret_redaction
from authflowguard.models import AuthProfile, EvidenceEvent
from authflowguard.scan_manager import (
    GuidanceSubmission,
    ScanExecutionInput,
    ScanManager,
    ScanRecord,
    ScanState,
    public_failure_message,
)
from authflowguard.worker_protocol import (
    WorkerCommand,
    WorkerMessage,
    WorkerMessageType,
    WorkerOperation,
    WorkerProgress,
)


class _ArtifactWorkerManager(ScanManager):
    """Run live work while leaving lifecycle metadata to the API parent."""

    def __init__(
        self,
        data_root: str | Path,
        saved_profile: AuthProfile | None,
        command: WorkerCommand,
        output: Any,
    ) -> None:
        self._worker_saved_profile = saved_profile
        self._worker_command = command
        self._worker_output = output
        self._worker_sequence = 1
        super().__init__(data_root, worker_backend="inline")

    def _load_persisted_scans(self) -> None:
        return

    def _persist_state(self, record: ScanRecord) -> None:
        # Progress is advisory: the terminal message carries the final state, so
        # a momentarily full pipe must never fail the scan itself.
        try:
            self._worker_output.put(
                _message(
                    self._worker_command,
                    self.next_sequence(),
                    WorkerMessageType.PROGRESS,
                    progress=_progress(record),
                ),
                block=True,
                timeout=1,
            )
        except queue.Full:
            pass

    def _export_reports(self, record: ScanRecord) -> None:
        return

    def _find_saved_profile(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
    ) -> AuthProfile | None:
        return self._worker_saved_profile

    def next_sequence(self) -> int:
        self._worker_sequence += 1
        return self._worker_sequence


async def _run_with_cancellation(
    record: ScanRecord,
    operation: Any,
    cancel_event: Any,
) -> None:
    async def registered() -> None:
        with record.cancellation.register_current_task():
            await operation

    task = asyncio.create_task(registered())
    while not task.done():
        if cancel_event.is_set():
            record.cancellation.request()
        await asyncio.wait({task}, timeout=0.05)
    await task


def _progress(record: ScanRecord) -> WorkerProgress:
    return WorkerProgress(
        phase=record.phase,
        active_check=record.active_check.value if record.active_check else None,
        completed_checks=[check.value for check in record.completed_checks],
        decision_count=record.decision_count,
        model_request_count=record.model_request_count,
        total_input_tokens=record.total_input_tokens,
        total_output_tokens=record.total_output_tokens,
        estimated_cost_usd=record.estimated_cost_usd,
        unresolved_reservations_usd=record.unresolved_reservations_usd,
        stop_reason=record.stop_reason,
        provenance=record.provenance,
    )


def _message(
    command: WorkerCommand,
    sequence: int,
    message_type: WorkerMessageType,
    **updates: Any,
) -> dict[str, Any]:
    return WorkerMessage(
        correlation_id=command.correlation_id,
        scan_id=command.scan_id,
        worker_generation=command.worker_generation,
        sequence=sequence,
        message_type=message_type,
        **updates,
    ).model_dump(mode="json")


async def _execute_scan_command(
    command: WorkerCommand,
    cancel_event: Any,
    output: Any,
) -> WorkerMessage:
    if command.execution is None:
        raise ValueError("A scan worker command requires execution input")
    execution = ScanExecutionInput.model_validate(command.execution)
    manager = _ArtifactWorkerManager(
        command.data_root,
        command.saved_profile,
        command,
        output,
    )
    record = ScanRecord(
        scan_id=command.scan_id,
        request=command.request,
        state=ScanState.RUNNING,
        worker_generation=command.worker_generation,
        provenance=(command.provenance.model_copy() if command.provenance else None),
    )
    manager._records[record.scan_id] = record
    try:
        try:
            if command.operation is WorkerOperation.SCAN:
                operation = manager._run_scan_async(
                    record,
                    execution,
                    command.worker_generation,
                )
            elif command.operation is WorkerOperation.GUIDED_SCAN:
                if command.guidance is None:
                    raise ValueError("A guided command requires guidance input")
                guidance = GuidanceSubmission.model_validate(command.guidance)
                operation = manager._run_guided_scan_async(
                    record,
                    execution,
                    guidance,
                    command.worker_generation,
                )
            else:
                raise ValueError("Unsupported scan worker operation")
            await _run_with_cancellation(record, operation, cancel_event)
        except asyncio.CancelledError:
            manager._finalize_cancelled(record, command.worker_generation)
        except ValueError as error:
            if command.operation is WorkerOperation.GUIDED_SCAN:
                record.pending_execution = execution
                manager._transition(
                    record,
                    ScanState.AWAITING_GUIDANCE,
                    error=execution.redact_text(str(error)),
                    error_code="guidance_required",
                )
            else:
                manager._finalize_failed(
                    record,
                    error,
                    command.worker_generation,
                )
        except Exception as error:
            manager._finalize_failed(record, error, command.worker_generation)

        if record.state is ScanState.AWAITING_GUIDANCE:
            message_type = WorkerMessageType.GUIDANCE_REQUIRED
            continuation = execution.model_dump(mode="json")
        elif record.state is ScanState.COMPLETED:
            message_type = WorkerMessageType.COMPLETED
            continuation = None
        elif record.state is ScanState.CANCELLED:
            message_type = WorkerMessageType.CANCELLED
            continuation = None
        else:
            message_type = WorkerMessageType.FAILED
            continuation = None
        return WorkerMessage(
            correlation_id=command.correlation_id,
            scan_id=command.scan_id,
            worker_generation=command.worker_generation,
            sequence=manager.next_sequence(),
            message_type=message_type,
            error_code=record.error_code,
            error=record.error,
            continuation_execution=continuation,
            progress=_progress(record),
            cleanup_confirmed=True,
        )
    finally:
        execution.discard_runtime_secrets()
        manager.shutdown()


async def _execute_observation_command(
    command: WorkerCommand,
    cancel_event: Any,
) -> WorkerMessage:
    secret_values: tuple[str, ...] = ()
    if command.execution is not None:
        execution = ScanExecutionInput.model_validate(command.execution)
        secret_values = execution.secret_values()
    record = ScanRecord(
        scan_id=command.scan_id,
        request=command.request,
        state=ScanState.RUNNING,
        worker_generation=command.worker_generation,
    )
    observation: Any = None

    async def observe() -> None:
        nonlocal observation
        observation = await observe_guidance_page(
            scan_id=command.scan_id,
            target=command.request.target,
            observation_url=command.observation_url,
        )

    try:
        with transient_secret_redaction(secret_values):
            await _run_with_cancellation(record, observe(), cancel_event)
            if observation is None:
                raise RuntimeError("Guidance observation returned no result")
            safe_event = EvidenceEvent.model_validate(
                redact_persisted_data(observation.event.model_dump(mode="json"))
            )
            controls = safe_event.redacted_details.get("controls", [])
            payload = {
                "scan_id": str(command.scan_id),
                "event": safe_event.model_dump(mode="json"),
                "url": safe_event.redacted_details.get("url"),
                "title": safe_event.redacted_details.get("title"),
                "controls": controls if isinstance(controls, list) else [],
            }
        return WorkerMessage(
            correlation_id=command.correlation_id,
            scan_id=command.scan_id,
            worker_generation=command.worker_generation,
            sequence=2,
            message_type=WorkerMessageType.OBSERVATION,
            observation=payload,
            cleanup_confirmed=True,
        )
    except asyncio.CancelledError:
        return WorkerMessage(
            correlation_id=command.correlation_id,
            scan_id=command.scan_id,
            worker_generation=command.worker_generation,
            sequence=2,
            message_type=WorkerMessageType.CANCELLED,
            error_code="scan_cancelled",
            error="Guidance observation cancelled",
            cleanup_confirmed=True,
        )


def execute_worker_command(
    command_data: dict[str, Any],
    output: Any,
    cancel_event: Any,
) -> None:
    """Validate one command, execute it, and publish one terminal message."""

    command = WorkerCommand.model_validate(command_data)
    output.put(
        _message(command, 1, WorkerMessageType.READY),
        block=True,
        timeout=5,
    )
    published = False

    async def execute_and_publish() -> None:
        nonlocal published
        if command.operation is WorkerOperation.OBSERVE_GUIDANCE:
            result = await _execute_observation_command(command, cancel_event)
        else:
            result = await _execute_scan_command(command, cancel_event, output)
        # Publish before the event loop shuts down, so a hang in loop or
        # interpreter teardown cannot hide a result that is already final.
        output.put(result.model_dump(mode="json"), block=True, timeout=5)
        published = True

    try:
        asyncio.run(execute_and_publish())
    except BaseException as error:
        if published:
            return
        message = WorkerMessage(
            correlation_id=command.correlation_id,
            scan_id=command.scan_id,
            worker_generation=command.worker_generation,
            sequence=2,
            message_type=WorkerMessageType.FAILED,
            error_code="scan_worker_failed",
            # Only a safe-message error may cross the process boundary as text.
            error=(
                public_failure_message(error)
                if isinstance(error, SafeMessageError)
                else "The isolated scan worker failed"
            ),
            cleanup_confirmed=True,
        )
        output.put(message.model_dump(mode="json"), block=True, timeout=5)
