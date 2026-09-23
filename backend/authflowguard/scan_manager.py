"""Local scan lifecycle orchestration for the first complete check slice."""

import asyncio
import time
from collections.abc import Coroutine
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from authflowguard.authentication import (
    GuidedPageObservation,
    LoginFormDiscoveryError,
    VerifiedLoginExecution,
    execute_guided_verified_login_flow,
    execute_verified_login_flow,
    observe_guidance_page,
    replay_verified_auth_profile,
    revalidate_auth_profile,
)
from authflowguard.cancellation import CancellationControl
from authflowguard.checks.form_enumeration import FormEnumerationRun
from authflowguard.checks.login_enumeration import (
    LoginEnumerationRun,
    analyse_login_enumeration,
    run_login_enumeration_check,
)
from authflowguard.checks.login_throttling import (
    LoginThrottlingRun,
    analyse_login_throttling,
    run_login_throttling_check,
)
from authflowguard.checks.logout_invalidation import (
    LogoutInvalidationRun,
    analyse_logout_invalidation,
    run_logout_invalidation_check,
)
from authflowguard.checks.registration_enumeration import (
    analyse_registration_enumeration,
    run_registration_enumeration_check,
)
from authflowguard.checks.reset_request_enumeration import (
    analyse_reset_request_enumeration,
    run_reset_request_enumeration_check,
)
from authflowguard.checks.session_fixation import (
    SessionFixationRun,
    analyse_session_fixation,
    run_session_fixation_check,
)
from authflowguard.evidence import (
    EvidenceStore,
    incremental_event_sink,
    redact_persisted_data,
    transient_secret_redaction,
)
from authflowguard.models import (
    AuthProfile,
    BrowserAction,
    CheckId,
    CheckResult,
    Coverage,
    EvidenceEvent,
    EvidenceKind,
    ScanRequest,
    TestRunEvidence,
)
from authflowguard.reports import export_scan_reports
from authflowguard.scope import url_without_query_or_fragment
from authflowguard.secrets import RuntimeSecrets, redact_text
from authflowguard.worker_protocol import (
    WorkerCommand,
    WorkerMessage,
    WorkerMessageType,
    WorkerOperation,
)
from authflowguard.worker_supervisor import WorkerSupervisor

ANALYSERS = {
    CheckId.LOGIN_ENUMERATION: analyse_login_enumeration,
    CheckId.REGISTRATION_ENUMERATION: analyse_registration_enumeration,
    CheckId.RESET_REQUEST_ENUMERATION: analyse_reset_request_enumeration,
    CheckId.LOGIN_THROTTLING: analyse_login_throttling,
    CheckId.SESSION_FIXATION: analyse_session_fixation,
    CheckId.LOGOUT_INVALIDATION: analyse_logout_invalidation,
}


def _latest_results(results: list[CheckResult]) -> list[CheckResult]:
    """Keep version history on disk, but expose one current result per evidence."""
    latest = {}
    for result in results:
        evidence_id = (
            result.evidence_references[0]
            if result.evidence_references
            else result.result_id
        )
        latest[(result.check_id, evidence_id)] = result
    return list(latest.values())


class ScanState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    AWAITING_GUIDANCE = "awaiting_guidance"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_SCAN_STATES = {
    ScanState.COMPLETED,
    ScanState.FAILED,
    ScanState.CANCELLED,
}

_UNCHANGED = object()

ALLOWED_SCAN_TRANSITIONS = {
    ScanState.CREATED: {ScanState.RUNNING, ScanState.CANCELLED},
    ScanState.RUNNING: {
        ScanState.AWAITING_GUIDANCE,
        ScanState.COMPLETED,
        ScanState.FAILED,
        ScanState.CANCELLED,
    },
    ScanState.AWAITING_GUIDANCE: {
        ScanState.RUNNING,
        ScanState.FAILED,
        ScanState.CANCELLED,
    },
    ScanState.COMPLETED: set(),
    ScanState.FAILED: set(),
    ScanState.CANCELLED: set(),
}


class ScanManagerError(ValueError):
    """Safe, machine-readable failure exposed by the local API."""

    code = "scan_error"
    status_code = 409

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class ScanNotFoundError(ScanManagerError):
    code = "scan_not_found"
    status_code = 404


class ScanRecoveryError(ScanManagerError):
    code = "scan_recovery_failed"


class InvalidScanStateError(ScanManagerError):
    code = "invalid_scan_state"


class ScanBusyError(ScanManagerError):
    code = "scan_busy"


class EvidenceNotAvailableError(ScanManagerError):
    code = "evidence_not_available"


class ReportNotAvailableError(ScanManagerError):
    code = "report_not_available"
    status_code = 404


class InvalidReportFormatError(ScanManagerError):
    code = "invalid_report_format"
    status_code = 422


class ScanWorkerUnavailableError(ScanManagerError):
    code = "scan_worker_unavailable"
    status_code = 503


class GuidanceObservationError(ScanManagerError):
    code = "guidance_observation_failed"


class ScanExecutionInput(BaseModel):
    """Transient execution input; this model is never saved with a scan."""

    model_config = ConfigDict(extra="forbid")

    runtime_secrets: dict[str, str] = Field(default_factory=dict)
    username_reference: str = Field(min_length=1)
    password_reference: str = Field(min_length=1)
    second_factor_reference: str | None = None
    nonexistent_identifier_reference: str = Field(min_length=1)
    failure_password_reference: str = Field(min_length=1)
    protected_resource: HttpUrl
    account_marker_selector: str = Field(min_length=1)
    account_marker_description: str = Field(min_length=1)
    registration_url: HttpUrl | None = None
    reset_request_url: HttpUrl | None = None
    registration_password_reference: str | None = None

    def secret_values(self) -> tuple[str, ...]:
        return tuple(value for value in self.runtime_secrets.values() if value)

    def redact_text(self, value: str) -> str:
        return redact_text(value, self.runtime_secrets.values())

    def discard_runtime_secrets(self) -> None:
        """Release this transient owner's credential references idempotently."""

        for reference_id in list(self.runtime_secrets):
            self.runtime_secrets[reference_id] = ""
        self.runtime_secrets.clear()


class GuidanceSubmission(BaseModel):
    """Transient guided-flow input; actions are sanitized before they are saved."""

    model_config = ConfigDict(extra="forbid")

    actions: list[BrowserAction] = Field(min_length=1)
    protected_resource: HttpUrl | None = None
    account_marker_selector: str | None = None
    account_marker_description: str | None = None


class GuidanceObservationRequest(BaseModel):
    """Optional page override for observing a login route during guidance."""

    model_config = ConfigDict(extra="forbid")

    url: HttpUrl | None = None


@dataclass
class ScanRecord:
    scan_id: UUID
    request: ScanRequest
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    state: ScanState = ScanState.CREATED
    events: list[EvidenceEvent] = field(default_factory=list)
    evidence: list[TestRunEvidence] = field(default_factory=list)
    results: list[CheckResult] = field(default_factory=list)
    profile: AuthProfile | None = None
    error: str | None = None
    error_code: str | None = None
    state_changed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cancellation: CancellationControl = field(default_factory=CancellationControl)
    future: Future[None] | None = None
    pending_execution: ScanExecutionInput | None = None
    active_check: CheckId | None = None
    completed_checks: list[CheckId] = field(default_factory=list)
    pending_observations: int = 0
    worker_generation: int = 0
    worker_active: bool = False
    cancellation_requested_at: float | None = None
    worker_cleanup: str | None = None
    worker_cleanup_seconds: float | None = None
    worker_pid: int | None = None
    worker_correlation_id: UUID | None = None

    @property
    def cancel_requested(self) -> bool:
        return self.cancellation.is_requested()


class ScanManager:
    """Keep one active local scan and persist its nonsecret artifacts."""

    def __init__(
        self,
        data_root: str | Path,
        *,
        worker_backend: Literal["process", "thread", "inline"] = "process",
        cancellation_grace_seconds: float = 3.0,
    ) -> None:
        self._store = EvidenceStore(data_root)
        self._data_root = Path(data_root).resolve()
        self._worker_backend = worker_backend
        self._records: dict[UUID, ScanRecord] = {}
        self._recovery_errors: dict[UUID, str] = {}
        self._lock = RLock()
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="afg-scan"
        )
        self._supervisor = (
            WorkerSupervisor(cancellation_grace_seconds)
            if worker_backend == "process"
            else None
        )
        self._load_persisted_scans()

    def shutdown(self) -> None:
        """Stop owned work without waiting indefinitely during API shutdown."""

        with self._lock:
            for record in self._records.values():
                if not self._is_active(record):
                    continue
                record.cancellation.request()
                record.cancellation_requested_at = time.monotonic()
                self._persist_state(record)
        if self._supervisor is not None:
            self._supervisor.shutdown()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def create_scan(self, request: ScanRequest) -> ScanRecord:
        record = ScanRecord(scan_id=uuid4(), request=request)
        with self._lock:
            self._records[record.scan_id] = record
        self._store.create_scan(
            record.scan_id,
            {
                **request.model_dump(mode="json"),
                "created_at": record.created_at.isoformat(),
                "state": record.state.value,
                "state_changed_at": record.state_changed_at.isoformat(),
            },
        )
        return record

    def get_scan(self, scan_id: UUID) -> ScanRecord:
        with self._lock:
            return self._get_scan_locked(scan_id)

    def start_scan(self, scan_id: UUID, execution: ScanExecutionInput) -> ScanRecord:
        try:
            with self._lock:
                record = self._get_scan_locked(scan_id)
                if record.state is not ScanState.CREATED:
                    raise InvalidScanStateError("Only a created scan can be started")
                if any(self._is_active(other) for other in self._records.values()):
                    raise ScanBusyError("Another scan is already running")
                record.worker_generation += 1
                worker_generation = record.worker_generation
                self._transition(record, ScanState.RUNNING)
                try:
                    if self._worker_backend == "process":
                        record.worker_active = True
                        command = WorkerCommand(
                            scan_id=record.scan_id,
                            worker_generation=worker_generation,
                            operation=WorkerOperation.SCAN,
                            data_root=str(self._data_root),
                            request=record.request,
                            execution=execution.model_dump(mode="json"),
                            saved_profile=self._find_saved_profile(record, execution),
                        )
                        record.future = self._start_process_worker(record, command)
                        self._record_worker_identity(record, command)
                        execution.discard_runtime_secrets()
                    else:
                        record.future = self._executor.submit(
                            self._run_scan,
                            record,
                            execution,
                            worker_generation,
                        )
                except BaseException:
                    record.worker_active = False
                    self._transition(
                        record,
                        ScanState.FAILED,
                        error="The scan worker could not be started",
                        error_code="scan_worker_unavailable",
                    )
                    raise ScanWorkerUnavailableError(
                        "The scan worker could not be started"
                    ) from None
                return record
        except BaseException:
            execution.discard_runtime_secrets()
            raise

    def cancel_scan(self, scan_id: UUID) -> ScanRecord:
        with self._lock:
            record = self._get_scan_locked(scan_id)
            if record.state in {
                ScanState.COMPLETED,
                ScanState.FAILED,
                ScanState.CANCELLED,
            }:
                return record
            record.cancellation.request()
            record.cancellation_requested_at = time.monotonic()
            if record.state is ScanState.CREATED or (
                record.state is ScanState.AWAITING_GUIDANCE
                and not record.cancellation.has_active_work
                and record.pending_observations == 0
            ):
                self._discard_pending_execution(record)
                self._transition(
                    record,
                    ScanState.CANCELLED,
                    error="Scan execution cancelled",
                    error_code="scan_cancelled",
                )
                self._export_reports(record)
            else:
                self._persist_state(record)
                if self._supervisor is not None and record.worker_active:
                    self._supervisor.cancel(record.scan_id, record.worker_generation)
            return record

    async def observe_guidance(
        self,
        scan_id: UUID,
        observation_url: HttpUrl | None = None,
    ) -> dict[str, Any]:
        """Observe the target page for a developer without retaining live values."""

        with self._lock:
            record = self._get_scan_locked(scan_id)
            if record.state is not ScanState.AWAITING_GUIDANCE:
                raise InvalidScanStateError("The scan is not waiting for guidance")
            if record.cancel_requested:
                raise InvalidScanStateError("The scan has been cancelled")
            record.pending_observations += 1
            secret_values = (
                record.pending_execution.secret_values()
                if record.pending_execution is not None
                else ()
            )
            process_command: WorkerCommand | None = None
            if self._worker_backend == "process":
                record.worker_generation += 1
                record.worker_active = True
                process_command = WorkerCommand(
                    scan_id=record.scan_id,
                    worker_generation=record.worker_generation,
                    operation=WorkerOperation.OBSERVE_GUIDANCE,
                    data_root=str(self._data_root),
                    request=record.request,
                    execution=(
                        record.pending_execution.model_dump(mode="json")
                        if record.pending_execution is not None
                        else None
                    ),
                    observation_url=(str(observation_url) if observation_url else None),
                )
                self._persist_state(record)
        loop = asyncio.get_running_loop()
        try:
            if process_command is not None:
                process_message = await self._observe_guidance_in_process(
                    record, process_command
                )
                observation_payload = process_message.observation or {}
                safe_event = EvidenceEvent.model_validate(
                    observation_payload.get("event")
                )
            else:
                observation = await loop.run_in_executor(
                    self._executor,
                    self._observe_guidance_in_worker,
                    record,
                    str(observation_url) if observation_url else None,
                    secret_values,
                )
                with transient_secret_redaction(secret_values):
                    safe_event = EvidenceEvent.model_validate(
                        redact_persisted_data(observation.event.model_dump(mode="json"))
                    )
        except asyncio.CancelledError:
            raise RuntimeError("Guidance observation cancelled") from None
        finally:
            with self._lock:
                record.pending_observations -= 1
                if process_command is not None:
                    record.worker_active = False
                    record.worker_pid = None
                    record.worker_correlation_id = None
                finalize_cancelled = (
                    record.cancel_requested and record.pending_observations == 0
                )
                if not finalize_cancelled:
                    self._persist_state(record)
            if finalize_cancelled:
                self._finalize_cancelled(record)
        if record.cancel_requested:
            raise RuntimeError("Guidance observation cancelled")
        self._save_events(record, [safe_event])
        safe_controls = safe_event.redacted_details.get("controls", [])
        return {
            "scan_id": str(record.scan_id),
            "event_id": str(safe_event.event_id),
            "url": safe_event.redacted_details.get("url"),
            "title": safe_event.redacted_details.get("title"),
            "controls": safe_controls if isinstance(safe_controls, list) else [],
        }

    async def _observe_guidance_in_process(
        self,
        record: ScanRecord,
        command: WorkerCommand,
    ) -> WorkerMessage:
        if self._supervisor is None:
            raise RuntimeError("The process worker supervisor is unavailable")
        result: Future[tuple[WorkerMessage | None, int | None, bool]] = Future()

        def completed(
            message: WorkerMessage | None,
            exit_code: int | None,
            forced: bool,
        ) -> None:
            if not result.done():
                result.set_result((message, exit_code, forced))

        record.future = self._supervisor.start(command, completed)
        self._record_worker_identity(record, command)
        message, exit_code, forced = await asyncio.wrap_future(result)
        with self._lock:
            record.worker_cleanup = (
                "forced"
                if forced
                else (
                    "crashed"
                    if message is None or exit_code not in {0, None}
                    else "graceful"
                )
            )
            if record.cancellation_requested_at is not None:
                record.worker_cleanup_seconds = round(
                    time.monotonic() - record.cancellation_requested_at, 6
                )
        if (
            message is None
            or exit_code not in {0, None}
            or not message.cleanup_confirmed
            or message.message_type is not WorkerMessageType.OBSERVATION
        ):
            raise RuntimeError("The isolated guidance observer failed")
        return message

    def _observe_guidance_in_worker(
        self,
        record: ScanRecord,
        observation_url: str | None,
        secret_values: tuple[str, ...],
    ) -> GuidedPageObservation:
        async def run() -> GuidedPageObservation:
            with transient_secret_redaction(secret_values):
                with record.cancellation.register_current_task():
                    return await observe_guidance_page(
                        scan_id=record.scan_id,
                        target=record.request.target,
                        observation_url=observation_url,
                    )

        return asyncio.run(run())

    def submit_guidance(
        self,
        scan_id: UUID,
        guidance: GuidanceSubmission,
    ) -> ScanRecord:
        """Resume an awaiting scan with a developer-recorded structured flow."""

        with self._lock:
            record = self._get_scan_locked(scan_id)
            if record.state is not ScanState.AWAITING_GUIDANCE:
                raise InvalidScanStateError("The scan is not waiting for guidance")
            if record.pending_execution is None:
                raise InvalidScanStateError(
                    "The scan no longer has runtime guidance input"
                )
            if record.cancel_requested:
                raise InvalidScanStateError("The scan has been cancelled")
            if any(self._is_active(other) for other in self._records.values()):
                raise ScanBusyError("Another scan is already running")

            pending_execution = record.pending_execution
            execution_data = pending_execution.model_dump()
            for field_name in (
                "protected_resource",
                "account_marker_selector",
                "account_marker_description",
            ):
                value = getattr(guidance, field_name)
                if value is not None:
                    execution_data[field_name] = value
            execution = ScanExecutionInput.model_validate(execution_data)
            pending_execution.discard_runtime_secrets()
            record.pending_execution = None
            record.worker_generation += 1
            worker_generation = record.worker_generation
            self._transition(record, ScanState.RUNNING, error=None, error_code=None)
            try:
                if self._worker_backend == "process":
                    record.worker_active = True
                    command = WorkerCommand(
                        scan_id=record.scan_id,
                        worker_generation=worker_generation,
                        operation=WorkerOperation.GUIDED_SCAN,
                        data_root=str(self._data_root),
                        request=record.request,
                        execution=execution.model_dump(mode="json"),
                        guidance=guidance.model_dump(mode="json"),
                    )
                    record.future = self._start_process_worker(record, command)
                    self._record_worker_identity(record, command)
                    execution.discard_runtime_secrets()
                else:
                    record.future = self._executor.submit(
                        self._run_guided_scan,
                        record,
                        execution,
                        guidance,
                        worker_generation,
                    )
            except BaseException:
                record.worker_active = False
                execution.discard_runtime_secrets()
                self._transition(
                    record,
                    ScanState.FAILED,
                    error="The guided scan worker could not be started",
                    error_code="scan_worker_unavailable",
                )
                raise ScanWorkerUnavailableError(
                    "The guided scan worker could not be started"
                ) from None
            return record

    def list_scans(self) -> list[ScanRecord]:
        with self._lock:
            return sorted(
                self._records.values(),
                key=lambda record: record.created_at,
                reverse=True,
            )

    def _start_process_worker(
        self,
        record: ScanRecord,
        command: WorkerCommand,
    ) -> Future[None]:
        if self._supervisor is None:
            raise RuntimeError("The process worker supervisor is unavailable")
        return self._supervisor.start(
            command,
            lambda message, exit_code, forced: self._apply_process_result(
                record,
                command.worker_generation,
                message,
                exit_code,
                forced,
            ),
        )

    def _record_worker_identity(
        self,
        record: ScanRecord,
        command: WorkerCommand,
    ) -> None:
        if self._supervisor is None:
            return
        identity = self._supervisor.identity(command.scan_id, command.worker_generation)
        record.worker_pid = identity[0] if identity is not None else None
        record.worker_correlation_id = command.correlation_id
        self._persist_state(record)

    def _apply_process_result(
        self,
        record: ScanRecord,
        worker_generation: int,
        message: WorkerMessage | None,
        exit_code: int | None,
        forced: bool,
    ) -> None:
        export_report = False
        with self._lock:
            if not self._worker_is_current(record, worker_generation):
                return
            if (
                message is not None
                and message.message_type is WorkerMessageType.PROGRESS
            ):
                record.active_check = (
                    CheckId(message.active_check) if message.active_check else None
                )
                record.completed_checks = [
                    CheckId(value) for value in message.completed_checks
                ]
                self._persist_state(record)
                return
            record.worker_active = False
            record.worker_pid = None
            record.worker_correlation_id = None
            if record.cancellation_requested_at is not None:
                record.worker_cleanup_seconds = round(
                    time.monotonic() - record.cancellation_requested_at, 6
                )
            record.worker_cleanup = (
                "forced"
                if forced
                else (
                    "crashed"
                    if message is None or exit_code not in {0, None}
                    else "graceful"
                )
            )
            self._reload_worker_artifacts(record)
            if record.cancel_requested:
                self._preserve_interrupted_check(record)
                self._discard_pending_execution(record)
                record.active_check = None
                self._transition(
                    record,
                    ScanState.CANCELLED,
                    error=(
                        "Scan execution cancelled after forced worker termination"
                        if forced
                        else "Scan execution cancelled"
                    ),
                    error_code=(
                        "scan_cancelled_forced" if forced else "scan_cancelled"
                    ),
                )
                export_report = True
            elif (
                message is None
                or message.message_type is WorkerMessageType.READY
                or not message.cleanup_confirmed
                or exit_code not in {0, None}
            ):
                self._discard_pending_execution(record)
                self._transition(
                    record,
                    ScanState.FAILED,
                    error="The isolated scan worker exited unexpectedly",
                    error_code="scan_worker_crashed",
                )
                export_report = True
            elif message.message_type is WorkerMessageType.GUIDANCE_REQUIRED:
                try:
                    continuation = ScanExecutionInput.model_validate(
                        message.continuation_execution
                    )
                except (TypeError, ValueError):
                    self._transition(
                        record,
                        ScanState.FAILED,
                        error="The isolated worker returned invalid continuation data",
                        error_code="scan_worker_protocol_error",
                    )
                    export_report = True
                else:
                    record.pending_execution = continuation
                    self._transition(
                        record,
                        ScanState.AWAITING_GUIDANCE,
                        error=message.error or "Developer guidance is required",
                        error_code="guidance_required",
                    )
            elif message.message_type is WorkerMessageType.COMPLETED:
                record.completed_checks = [
                    CheckId(value) for value in message.completed_checks
                ]
                self._discard_pending_execution(record)
                self._transition(
                    record,
                    ScanState.COMPLETED,
                    error=None,
                    error_code=None,
                )
                export_report = True
            elif message.message_type is WorkerMessageType.CANCELLED:
                self._discard_pending_execution(record)
                self._transition(
                    record,
                    ScanState.CANCELLED,
                    error="Scan execution cancelled",
                    error_code="scan_cancelled",
                )
                export_report = True
            else:
                self._discard_pending_execution(record)
                self._transition(
                    record,
                    ScanState.FAILED,
                    error=message.error or "The isolated scan worker failed",
                    error_code=message.error_code or "scan_worker_failed",
                )
                export_report = True
        if export_report:
            self._export_reports(record)

    def _reload_worker_artifacts(self, record: ScanRecord) -> None:
        record.events = self._store.read_events(record.scan_id)
        record.evidence = self._store.read_all_evidence(record.scan_id)
        record.profile = self._store.read_profile(record.scan_id)
        results: list[CheckResult] = []
        for raw_result in self._store.read_results(record.scan_id):
            result_data = dict(raw_result)
            result_data.pop("result_version", None)
            results.append(CheckResult.model_validate(result_data))
        record.results = _latest_results(results)

    def _find_saved_profile(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
    ) -> AuthProfile | None:
        protected_resource = url_without_query_or_fragment(
            str(execution.protected_resource)
        )
        with self._lock:
            candidates = sorted(
                self._records.values(),
                key=lambda saved_record: saved_record.created_at,
                reverse=True,
            )
            for saved_record in candidates:
                if saved_record.scan_id == record.scan_id:
                    continue
                if saved_record.state is not ScanState.COMPLETED:
                    continue
                profile = saved_record.profile
                if profile is None or profile.target != record.request.target:
                    continue
                protected_check = profile.protected_resource_check
                if (
                    protected_check is None
                    or url_without_query_or_fragment(protected_check.resource)
                    != protected_resource
                ):
                    continue
                return profile
        return None

    def reanalyse(self, scan_id: UUID) -> list[CheckResult]:
        record = self.get_scan(scan_id)
        if record.state in {
            ScanState.CREATED,
            ScanState.RUNNING,
            ScanState.AWAITING_GUIDANCE,
        }:
            raise InvalidScanStateError(
                "Wait for scan execution to finish before reanalysis"
            )
        if record.profile is None or not record.evidence:
            raise EvidenceNotAvailableError(
                "The scan has no completed evidence to reanalyse"
            )
        if any(evidence.check_id not in ANALYSERS for evidence in record.evidence):
            raise EvidenceNotAvailableError(
                "No offline analyser is available for some stored evidence"
            )
        results = [
            ANALYSERS[evidence.check_id](
                evidence, record.profile, record.request.policy
            )
            for evidence in record.evidence
        ]
        for result in results:
            self._store.save_result(result)
        record.results = _latest_results([*record.results, *results])
        export_scan_reports(self._store, scan_id, record.evidence, record.results)
        return results

    def report_path(self, scan_id: UUID, extension: str) -> Path:
        self.get_scan(scan_id)
        if extension not in {"json", "html"}:
            raise InvalidReportFormatError("Only JSON and HTML reports are available")
        path = self._store.scan_directory(scan_id) / f"report.{extension}"
        if not path.exists():
            raise ReportNotAvailableError(f"No {extension} report exists for this scan")
        return path

    def _run_scan(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        worker_generation: int,
    ) -> None:
        try:
            asyncio.run(
                self._run_registered(
                    record,
                    self._run_scan_async(record, execution, worker_generation),
                    execution.secret_values(),
                )
            )
        except asyncio.CancelledError:
            self._finalize_cancelled(record, worker_generation)
        except Exception as error:
            self._finalize_failed(record, error, worker_generation)
        finally:
            if record.pending_execution is not execution:
                execution.discard_runtime_secrets()

    def _run_guided_scan(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        guidance: GuidanceSubmission,
        worker_generation: int,
    ) -> None:
        try:
            asyncio.run(
                self._run_registered(
                    record,
                    self._run_guided_scan_async(
                        record, execution, guidance, worker_generation
                    ),
                    execution.secret_values(),
                )
            )
        except asyncio.CancelledError:
            self._finalize_cancelled(record, worker_generation)
        except ValueError as error:
            with self._lock:
                if not self._worker_is_current(record, worker_generation):
                    return
                next_state = (
                    ScanState.CANCELLED
                    if record.cancel_requested
                    else ScanState.AWAITING_GUIDANCE
                )
                if next_state is ScanState.AWAITING_GUIDANCE:
                    record.pending_execution = execution
                else:
                    self._discard_pending_execution(record)
                self._transition(
                    record,
                    next_state,
                    error=(
                        "Scan execution cancelled"
                        if next_state is ScanState.CANCELLED
                        else execution.redact_text(str(error))
                    ),
                    error_code=(
                        "scan_cancelled"
                        if next_state is ScanState.CANCELLED
                        else "guidance_required"
                    ),
                )
        except Exception as error:
            self._finalize_failed(record, error, worker_generation)
        finally:
            if record.pending_execution is not execution:
                execution.discard_runtime_secrets()

    async def _run_registered(
        self,
        record: ScanRecord,
        coroutine: Coroutine[Any, Any, None],
        secret_values: tuple[str, ...],
    ) -> None:
        started = False
        try:
            with transient_secret_redaction(secret_values):
                with record.cancellation.register_current_task():
                    with incremental_event_sink(
                        lambda events: self._save_incremental_events(record, events)
                    ):
                        started = True
                        await coroutine
        finally:
            if not started:
                coroutine.close()

    async def _run_scan_async(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        worker_generation: int | None = None,
    ) -> None:
        with self._lock:
            if not self._worker_is_current(record, worker_generation):
                return
        record.cancellation.checkpoint()

        runtime_secrets = RuntimeSecrets(execution.runtime_secrets)
        try:
            saved_profile = self._find_saved_profile(record, execution)
            try:
                if saved_profile is not None:
                    await revalidate_auth_profile(
                        profile=saved_profile,
                        scan_id=record.scan_id,
                    )
                    profile_execution = await replay_verified_auth_profile(
                        profile=saved_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=runtime_secrets,
                        account_marker_selector=execution.account_marker_selector,
                    )
                else:
                    profile_execution = await execute_verified_login_flow(
                        scan_id=record.scan_id,
                        target=record.request.target,
                        runtime_secrets=runtime_secrets,
                        username_reference=execution.username_reference,
                        password_reference=execution.password_reference,
                        second_factor_reference=execution.second_factor_reference,
                        protected_resource=str(execution.protected_resource),
                        account_marker_selector=execution.account_marker_selector,
                        account_marker_description=execution.account_marker_description,
                    )
            except (LoginFormDiscoveryError, ValueError) as error:
                with self._lock:
                    if not self._worker_is_current(record, worker_generation):
                        return
                    next_state = (
                        ScanState.CANCELLED
                        if record.cancel_requested
                        else ScanState.AWAITING_GUIDANCE
                    )
                    unsafe_error = (
                        f"Saved authentication flow needs guidance: {error}"
                        if saved_profile is not None
                        else str(error)
                    )
                    safe_error = runtime_secrets.redact_text(unsafe_error)
                    record.pending_execution = (
                        execution if next_state is ScanState.AWAITING_GUIDANCE else None
                    )
                    self._transition(
                        record,
                        next_state,
                        error=(
                            "Scan execution cancelled"
                            if next_state is ScanState.CANCELLED
                            else safe_error
                        ),
                        error_code=(
                            "scan_cancelled"
                            if next_state is ScanState.CANCELLED
                            else "guidance_required"
                        ),
                    )
                return
            await self._complete_profile_execution(
                record,
                execution,
                profile_execution,
                worker_generation,
            )
        finally:
            runtime_secrets.discard_all()

    async def _run_guided_scan_async(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        guidance: GuidanceSubmission,
        worker_generation: int | None = None,
    ) -> None:
        with self._lock:
            if not self._worker_is_current(record, worker_generation):
                return
        runtime_secrets = RuntimeSecrets(execution.runtime_secrets)
        try:
            profile_execution = await execute_guided_verified_login_flow(
                scan_id=record.scan_id,
                target=record.request.target,
                runtime_secrets=runtime_secrets,
                actions=guidance.actions,
                protected_resource=str(execution.protected_resource),
                account_marker_selector=execution.account_marker_selector,
                account_marker_description=execution.account_marker_description,
            )
            await self._complete_profile_execution(
                record,
                execution,
                profile_execution,
                worker_generation,
            )
            self._discard_pending_execution(record)
        finally:
            runtime_secrets.discard_all()

    async def _complete_profile_execution(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        profile_execution: VerifiedLoginExecution,
        worker_generation: int | None = None,
    ) -> None:
        with self._lock:
            if not self._worker_is_current(record, worker_generation):
                return
        safe_profile = AuthProfile.model_validate(
            redact_persisted_data(profile_execution.profile.model_dump(mode="json"))
        )
        record.profile = safe_profile
        self._store.save_profile(record.scan_id, safe_profile)
        self._save_events(record, profile_execution.events)

        record.cancellation.checkpoint()

        # Registration can create the disposable account. Execute all checks
        # depending on its nonexistence before the registration submission.
        check_order = (
            CheckId.LOGIN_ENUMERATION,
            CheckId.RESET_REQUEST_ENUMERATION,
            CheckId.REGISTRATION_ENUMERATION,
            CheckId.LOGIN_THROTTLING,
            CheckId.SESSION_FIXATION,
            CheckId.LOGOUT_INVALIDATION,
        )
        for check_id in check_order:
            if record.cancel_requested:
                break
            if check_id not in record.request.selected_checks:
                continue
            record.active_check = check_id
            self._persist_state(record)
            check_secrets = RuntimeSecrets(execution.runtime_secrets)
            run: (
                LoginEnumerationRun
                | FormEnumerationRun
                | LoginThrottlingRun
                | SessionFixationRun
                | LogoutInvalidationRun
            )
            try:
                if check_id is CheckId.LOGIN_ENUMERATION:
                    run = await run_login_enumeration_check(
                        profile=safe_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        known_identifier_reference=execution.username_reference,
                        nonexistent_identifier_reference=execution.nonexistent_identifier_reference,
                        failure_password_reference=execution.failure_password_reference,
                        cancel_requested=record.cancellation.is_requested,
                    )
                elif check_id is CheckId.RESET_REQUEST_ENUMERATION:
                    run = await run_reset_request_enumeration_check(
                        profile=safe_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        known_identifier_reference=execution.username_reference,
                        nonexistent_identifier_reference=execution.nonexistent_identifier_reference,
                        form_url=str(execution.reset_request_url)
                        if execution.reset_request_url
                        else None,
                        cancel_requested=record.cancellation.is_requested,
                    )
                elif check_id is CheckId.LOGIN_THROTTLING:
                    run = await run_login_throttling_check(
                        profile=safe_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        username_reference=execution.username_reference,
                        password_reference=execution.password_reference,
                        failure_password_reference=execution.failure_password_reference,
                        expected_lockout_threshold=(
                            record.request.policy.expected_lockout_threshold
                        ),
                        cancel_requested=record.cancellation.is_requested,
                    )
                elif check_id is CheckId.SESSION_FIXATION:
                    run = await run_session_fixation_check(
                        profile=safe_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        username_reference=execution.username_reference,
                        password_reference=execution.password_reference,
                        protected_resource=str(execution.protected_resource),
                        account_marker_selector=execution.account_marker_selector,
                        cancel_requested=record.cancellation.is_requested,
                    )
                elif check_id is CheckId.LOGOUT_INVALIDATION:
                    run = await run_logout_invalidation_check(
                        profile=safe_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        username_reference=execution.username_reference,
                        password_reference=execution.password_reference,
                        protected_resource=str(execution.protected_resource),
                        account_marker_selector=execution.account_marker_selector,
                        cancel_requested=record.cancellation.is_requested,
                    )
                else:
                    run = await run_registration_enumeration_check(
                        profile=safe_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        known_identifier_reference=execution.username_reference,
                        nonexistent_identifier_reference=execution.nonexistent_identifier_reference,
                        registration_password_reference=(
                            execution.registration_password_reference
                            or execution.failure_password_reference
                        ),
                        form_url=str(execution.registration_url)
                        if execution.registration_url
                        else None,
                        cancel_requested=record.cancellation.is_requested,
                    )
            finally:
                check_secrets.discard_all()
            self._save_events(record, run.events)
            safe_evidence = TestRunEvidence.model_validate(
                redact_persisted_data(run.evidence.model_dump(mode="json"))
            )
            record.evidence.append(safe_evidence)
            self._store.save_evidence(safe_evidence)
            result = ANALYSERS[check_id](
                safe_evidence,
                safe_profile,
                record.request.policy,
            )
            safe_result = CheckResult.model_validate(
                redact_persisted_data(result.model_dump(mode="json"))
            )
            record.results.append(safe_result)
            self._store.save_result(safe_result)
            if record.cancel_requested:
                break
            record.completed_checks.append(check_id)
            record.active_check = None
            self._persist_state(record)
        with self._lock:
            if not self._worker_is_current(record, worker_generation):
                return
            next_state = (
                ScanState.CANCELLED if record.cancel_requested else ScanState.COMPLETED
            )
            self._transition(
                record,
                next_state,
                error=(
                    "Scan execution cancelled"
                    if next_state is ScanState.CANCELLED
                    else None
                ),
                error_code=(
                    "scan_cancelled" if next_state is ScanState.CANCELLED else None
                ),
            )
        self._export_reports(record)

    def _save_events(
        self,
        record: ScanRecord,
        events: list[EvidenceEvent],
    ) -> None:
        known_ids = {event.event_id for event in record.events}
        new_events = [
            EvidenceEvent.model_validate(
                redact_persisted_data(event.model_dump(mode="json"))
            )
            for event in events
            if event.event_id not in known_ids
        ]
        record.events.extend(new_events)
        for event in new_events:
            self._store.append_event(event)

    def _save_incremental_events(
        self, record: ScanRecord, events: list[EvidenceEvent]
    ) -> None:
        check_id = record.active_check
        self._save_events(
            record,
            [
                event.model_copy(update={"check_id": check_id})
                if check_id is not None and event.check_id is None
                else event
                for event in events
            ],
        )

    def _get_scan_locked(self, scan_id: UUID) -> ScanRecord:
        try:
            return self._records[scan_id]
        except KeyError as error:
            if scan_id in self._recovery_errors:
                raise ScanRecoveryError(
                    "The persisted scan could not be recovered safely"
                ) from error
            raise ScanNotFoundError(f"Scan '{scan_id}' was not found") from error

    def _transition(
        self,
        record: ScanRecord,
        next_state: ScanState,
        *,
        error: str | None | object = _UNCHANGED,
        error_code: str | None | object = _UNCHANGED,
    ) -> None:
        """Apply and persist one validated lifecycle transition."""

        current_state = record.state
        if next_state not in ALLOWED_SCAN_TRANSITIONS[current_state]:
            raise RuntimeError(
                f"Invalid internal scan transition: {current_state} -> {next_state}"
            )
        now = datetime.now(UTC)
        record.state = next_state
        record.state_changed_at = now
        if next_state is ScanState.RUNNING and record.started_at is None:
            record.started_at = now
        if next_state in TERMINAL_SCAN_STATES:
            record.finished_at = now
        if error is not _UNCHANGED:
            record.error = error if isinstance(error, str) else None
        if error_code is not _UNCHANGED:
            record.error_code = error_code if isinstance(error_code, str) else None
        self._persist_state(record)

    @staticmethod
    def _discard_pending_execution(record: ScanRecord) -> None:
        if record.pending_execution is not None:
            record.pending_execution.discard_runtime_secrets()
            record.pending_execution = None

    @staticmethod
    def _is_active(record: ScanRecord) -> bool:
        return (
            record.state is ScanState.RUNNING
            or record.worker_active
            or record.cancellation.has_active_work
            or record.pending_observations > 0
        )

    @staticmethod
    def _worker_is_current(
        record: ScanRecord,
        worker_generation: int | None,
    ) -> bool:
        return worker_generation is None or (
            worker_generation == record.worker_generation
            and record.state is ScanState.RUNNING
        )

    def _finalize_cancelled(
        self,
        record: ScanRecord,
        worker_generation: int | None = None,
    ) -> None:
        """Publish cancellation only after the registered worker has unwound."""

        with self._lock:
            if not self._worker_is_current(record, worker_generation):
                return
            if record.state in TERMINAL_SCAN_STATES:
                return
            self._preserve_interrupted_check(record)
            self._discard_pending_execution(record)
            record.active_check = None
            self._transition(
                record,
                ScanState.CANCELLED,
                error="Scan execution cancelled",
                error_code="scan_cancelled",
            )
        self._export_reports(record)

    def _preserve_interrupted_check(self, record: ScanRecord) -> None:
        check_id = record.active_check
        if check_id is None or any(
            evidence.check_id is check_id for evidence in record.evidence
        ):
            return
        event = EvidenceEvent(
            event_id=uuid4(),
            scan_id=record.scan_id,
            check_id=check_id,
            kind=EvidenceKind.ERROR,
            summary="The security check was interrupted by scan cancellation.",
            redacted_details={"reason": "scan_cancelled"},
        )
        self._save_events(record, [event])
        evidence = TestRunEvidence(
            evidence_id=uuid4(),
            scan_id=record.scan_id,
            check_id=check_id,
            profile_version=(
                record.profile.schema_version if record.profile else "1.0"
            ),
            event_ids=[
                saved.event_id for saved in record.events if saved.check_id is check_id
            ],
            observations={"execution_status": "cancelled"},
            errors=["ScanCancelledError"],
            coverage=Coverage(
                attempted_steps=[f"run-{check_id.value}"],
                completed_steps=[],
                limitations=["Execution was interrupted by scan cancellation."],
            ),
        )
        record.evidence.append(evidence)
        self._store.save_evidence(evidence)

    def _finalize_failed(
        self,
        record: ScanRecord,
        error: BaseException,
        worker_generation: int | None = None,
    ) -> None:
        with self._lock:
            if not self._worker_is_current(record, worker_generation):
                return
            if record.state in TERMINAL_SCAN_STATES:
                return
            if record.cancel_requested:
                self._preserve_interrupted_check(record)
                next_state = ScanState.CANCELLED
                public_error = "Scan execution cancelled"
                error_code = "scan_cancelled"
            else:
                next_state = ScanState.FAILED
                public_error = "Scan execution failed"
                error_code = "scan_execution_failed"
            self._discard_pending_execution(record)
            record.active_check = None
            self._transition(
                record,
                next_state,
                error=public_error,
                error_code=error_code,
            )
        self._export_reports(record)

    def _export_reports(self, record: ScanRecord) -> None:
        export_scan_reports(
            self._store, record.scan_id, record.evidence, record.results
        )

    def _persist_state(self, record: ScanRecord) -> None:
        self._store.update_metadata(
            record.scan_id,
            {
                "state": record.state.value,
                "error": record.error,
                "error_code": record.error_code,
                "cancel_requested": record.cancel_requested,
                "state_changed_at": record.state_changed_at.isoformat(),
                "started_at": (
                    record.started_at.isoformat() if record.started_at else None
                ),
                "finished_at": (
                    record.finished_at.isoformat() if record.finished_at else None
                ),
                "worker_generation": record.worker_generation,
                "worker_active": record.worker_active,
                "worker_cleanup": record.worker_cleanup,
                "worker_cleanup_seconds": record.worker_cleanup_seconds,
                "worker_pid": record.worker_pid,
                "worker_correlation_id": (
                    str(record.worker_correlation_id)
                    if record.worker_correlation_id
                    else None
                ),
                "execution_progress": {
                    "active_check": (
                        record.active_check.value if record.active_check else None
                    ),
                    "completed_checks": [
                        check_id.value for check_id in record.completed_checks
                    ],
                    "cancelled_checks": [
                        check_id.value
                        for check_id in record.request.selected_checks
                        if record.cancel_requested
                        and check_id not in record.completed_checks
                    ],
                },
            },
        )

    def _load_persisted_scans(self) -> None:
        for scan_id in self._store.list_scan_ids():
            try:
                metadata = self._store.read_metadata(scan_id)
                request_data = dict(metadata)
                request_data.pop("scan_id", None)
                request_data.pop("created_at", None)
                request_data.pop("state", None)
                request_data.pop("error", None)
                request_data.pop("error_code", None)
                request_data.pop("cancel_requested", None)
                request_data.pop("state_changed_at", None)
                request_data.pop("started_at", None)
                request_data.pop("finished_at", None)
                request_data.pop("worker_generation", None)
                request_data.pop("worker_active", None)
                request_data.pop("worker_cleanup", None)
                request_data.pop("worker_cleanup_seconds", None)
                request_data.pop("worker_pid", None)
                request_data.pop("worker_correlation_id", None)
                progress = request_data.pop("execution_progress", None)
                request = ScanRequest.model_validate(request_data)
                created_at_value = metadata.get("created_at")
                created_at = (
                    datetime.fromisoformat(str(created_at_value))
                    if created_at_value
                    else datetime.fromtimestamp(
                        self._store.scan_directory(scan_id).stat().st_mtime,
                        UTC,
                    )
                )
                raw_state = metadata.get("state")
                if raw_state is None:
                    raw_state = (
                        ScanState.COMPLETED.value
                        if self._store.read_results(scan_id)
                        else ScanState.CREATED.value
                    )
                state = ScanState(str(raw_state))
                error = metadata.get("error")
                error_code = metadata.get("error_code")
                interrupted_state = state
                if state in {ScanState.RUNNING, ScanState.AWAITING_GUIDANCE}:
                    if metadata.get("cancel_requested"):
                        state = ScanState.CANCELLED
                        error = "Scan execution cancelled during backend restart"
                        error_code = "scan_cancelled"
                    else:
                        state = ScanState.FAILED
                        error = "Backend restarted during scan execution"
                        error_code = "backend_restarted"
                results = []
                for raw_result in self._store.read_results(scan_id):
                    result_data = dict(raw_result)
                    result_data.pop("result_version", None)
                    results.append(CheckResult.model_validate(result_data))
                record = ScanRecord(
                    scan_id=scan_id,
                    request=request,
                    created_at=created_at,
                    state=state,
                    events=self._store.read_events(scan_id),
                    evidence=self._store.read_all_evidence(scan_id),
                    results=_latest_results(results),
                    profile=self._store.read_profile(scan_id),
                    error=str(error) if error is not None else None,
                    error_code=(str(error_code) if error_code is not None else None),
                    state_changed_at=self._read_datetime(
                        metadata.get("state_changed_at"), created_at
                    ),
                    started_at=self._read_optional_datetime(metadata.get("started_at")),
                    finished_at=self._read_optional_datetime(
                        metadata.get("finished_at")
                    ),
                    worker_generation=int(metadata.get("worker_generation", 0)),
                    worker_cleanup=(
                        str(metadata["worker_cleanup"])
                        if metadata.get("worker_cleanup") is not None
                        else None
                    ),
                    worker_cleanup_seconds=(
                        float(metadata["worker_cleanup_seconds"])
                        if metadata.get("worker_cleanup_seconds") is not None
                        else None
                    ),
                    completed_checks=[
                        CheckId(value)
                        for value in (
                            progress.get("completed_checks", [])
                            if isinstance(progress, dict)
                            else []
                        )
                    ],
                )
                if metadata.get("cancel_requested"):
                    record.cancellation.request()
                if interrupted_state in {
                    ScanState.RUNNING,
                    ScanState.AWAITING_GUIDANCE,
                }:
                    now = datetime.now(UTC)
                    record.state_changed_at = now
                    record.finished_at = now
                self._records[scan_id] = record
                if state is ScanState.FAILED and metadata.get("state") in {
                    ScanState.RUNNING.value,
                    ScanState.AWAITING_GUIDANCE.value,
                }:
                    self._persist_state(record)
                elif state is ScanState.CANCELLED and interrupted_state in {
                    ScanState.RUNNING,
                    ScanState.AWAITING_GUIDANCE,
                }:
                    self._persist_state(record)
            except (OSError, TypeError, ValueError):
                self._recovery_errors[scan_id] = (
                    "The persisted scan metadata or artifacts are invalid"
                )

    @staticmethod
    def _read_optional_datetime(value: Any) -> datetime | None:
        if value is None:
            return None
        return datetime.fromisoformat(str(value))

    @classmethod
    def _read_datetime(cls, value: Any, fallback: datetime) -> datetime:
        return cls._read_optional_datetime(value) or fallback

    def snapshot(self, record: ScanRecord) -> dict[str, Any]:
        scan_directory = self._store.scan_directory(record.scan_id)
        return {
            "scan_id": str(record.scan_id),
            "created_at": record.created_at.isoformat(),
            "state": record.state.value,
            "state_changed_at": record.state_changed_at.isoformat(),
            "started_at": record.started_at.isoformat() if record.started_at else None,
            "finished_at": (
                record.finished_at.isoformat() if record.finished_at else None
            ),
            "worker_generation": record.worker_generation,
            "worker_active": record.worker_active,
            "worker_cleanup": record.worker_cleanup,
            "worker_cleanup_seconds": record.worker_cleanup_seconds,
            "worker_pid": record.worker_pid,
            "worker_correlation_id": (
                str(record.worker_correlation_id)
                if record.worker_correlation_id
                else None
            ),
            "cancel_requested": record.cancel_requested,
            "target_url": str(record.request.target.target_url),
            "event_count": len(record.events),
            "evidence_count": len(record.evidence),
            "result_count": len(record.results),
            "partial_results_available": bool(record.evidence or record.results),
            "reanalysis_available": (
                record.state in TERMINAL_SCAN_STATES
                and record.profile is not None
                and bool(record.evidence)
            ),
            "report_available": (
                (scan_directory / "report.json").exists()
                and (scan_directory / "report.html").exists()
            ),
            "error": record.error,
            "error_code": record.error_code,
            "profile_source": (
                record.profile.discovery_history[-1].source.value
                if record.profile and record.profile.discovery_history
                else None
            ),
            "guidance_required": record.state is ScanState.AWAITING_GUIDANCE,
            "execution_progress": {
                "active_check": (
                    record.active_check.value if record.active_check else None
                ),
                "completed_checks": [
                    check_id.value for check_id in record.completed_checks
                ],
                "cancelled_checks": [
                    check_id.value
                    for check_id in record.request.selected_checks
                    if record.cancel_requested
                    and check_id not in record.completed_checks
                ],
            },
            "results": [result.model_dump(mode="json") for result in record.results],
        }
