"""Spawned scan-worker runtime; imported only inside a child process."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from uuid import UUID

from authflowguard.authentication import observe_guidance_page
from authflowguard.evidence import redact_persisted_data, transient_secret_redaction
from authflowguard.models import AuthProfile, EvidenceEvent
from authflowguard.scan_manager import (
    GuidanceSubmission,
    ScanExecutionInput,
    ScanManager,
    ScanRecord,
    ScanState,
)
from authflowguard.usage_ledger import UsageBudgetExceeded, UsageLedgerError
from authflowguard.worker_protocol import (
    WorkerAcknowledgement,
    WorkerCommand,
    WorkerMessage,
    WorkerMessageType,
    WorkerOperation,
)


class _ParentUsageAccountant:
    """Synchronously obtain a durable parent acknowledgement for each transition."""

    def __init__(self, manager: _ArtifactWorkerManager, control: Any) -> None:
        self._manager = manager
        self._control = control

    def reserve(
        self,
        *,
        attempt_id: UUID,
        model_id: str,
        region: str,
        reserved_cost_usd: float,
        input_price_usd_per_1000_tokens: float,
        output_price_usd_per_1000_tokens: float,
    ) -> None:
        self._exchange(
            WorkerMessageType.USAGE_RESERVE,
            attempt_id,
            model_id=model_id,
            region=region,
            reserved_cost_usd=reserved_cost_usd,
            input_price_usd_per_1000_tokens=input_price_usd_per_1000_tokens,
            output_price_usd_per_1000_tokens=output_price_usd_per_1000_tokens,
        )

    def mark_dispatched(self, attempt_id: UUID) -> None:
        self._exchange(WorkerMessageType.USAGE_DISPATCHED, attempt_id)

    def settle(
        self,
        attempt_id: UUID,
        *,
        input_tokens: int,
        output_tokens: int,
        actual_cost_usd: float,
    ) -> None:
        self._exchange(
            WorkerMessageType.USAGE_SETTLE,
            attempt_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            actual_cost_usd=actual_cost_usd,
        )

    def release(self, attempt_id: UUID, safe_reason: str) -> None:
        self._exchange(
            WorkerMessageType.USAGE_RELEASE,
            attempt_id,
            safe_reason=safe_reason,
        )

    def _exchange(
        self, message_type: WorkerMessageType, attempt_id: UUID, **updates: Any
    ) -> None:
        command = self._manager._worker_command
        self._manager._worker_output.put(
            _message(
                command,
                self._manager.next_sequence(),
                message_type,
                attempt_id=attempt_id,
                **updates,
            ),
            block=True,
            timeout=5,
        )
        acknowledgement = WorkerAcknowledgement.model_validate(
            self._control.get(block=True, timeout=10)
        )
        if (
            acknowledgement.correlation_id != command.correlation_id
            or acknowledgement.attempt_id != attempt_id
            or acknowledgement.message_type is not message_type
        ):
            raise UsageLedgerError("Invalid usage acknowledgement")
        if not acknowledgement.accepted:
            if acknowledgement.error_code == "usage_budget_exceeded":
                raise UsageBudgetExceeded("The scan usage budget was exhausted")
            raise UsageLedgerError("The usage transition was not persisted")


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
        self.usage_accountant: _ParentUsageAccountant | None = None
        super().__init__(data_root, worker_backend="inline")

    def _load_persisted_scans(self) -> None:
        return

    def _persist_state(self, record: ScanRecord) -> None:
        self._worker_sequence += 1
        self._worker_output.put(
            _message(
                self._worker_command,
                self._worker_sequence,
                WorkerMessageType.PROGRESS,
                active_check=(
                    record.active_check.value if record.active_check else None
                ),
                completed_checks=[check.value for check in record.completed_checks],
            ),
            block=True,
            timeout=5,
        )

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
    control: Any,
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
    )
    manager._records[record.scan_id] = record
    # The broker is retained by the worker manager for future scan-owned
    # Bedrock clients; current web scans do not create model calls.
    manager.usage_accountant = _ParentUsageAccountant(manager, control)
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
            completed_checks=[check.value for check in record.completed_checks],
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
    control: Any,
    cancel_event: Any,
) -> None:
    """Validate one command, execute it, and publish one terminal message."""

    command = WorkerCommand.model_validate(command_data)
    output.put(
        _message(command, 1, WorkerMessageType.READY),
        block=True,
        timeout=5,
    )
    try:
        if command.operation is WorkerOperation.OBSERVE_GUIDANCE:
            message = asyncio.run(_execute_observation_command(command, cancel_event))
        else:
            message = asyncio.run(
                _execute_scan_command(command, cancel_event, output, control)
            )
    except BaseException:
        message = WorkerMessage(
            correlation_id=command.correlation_id,
            scan_id=command.scan_id,
            worker_generation=command.worker_generation,
            sequence=2,
            message_type=WorkerMessageType.FAILED,
            error_code="scan_worker_failed",
            error="The isolated scan worker failed",
            cleanup_confirmed=True,
        )
    output.put(message.model_dump(mode="json"), block=True, timeout=5)
