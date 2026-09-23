"""Local scan lifecycle orchestration for the first complete check slice."""

import asyncio
from collections.abc import Coroutine
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Any
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
    cancellation: CancellationControl = field(default_factory=CancellationControl)
    future: Future[None] | None = None
    pending_execution: ScanExecutionInput | None = None
    active_check: CheckId | None = None
    completed_checks: list[CheckId] = field(default_factory=list)
    pending_observations: int = 0

    @property
    def cancel_requested(self) -> bool:
        return self.cancellation.is_requested()


class ScanManager:
    """Keep one active local scan and persist its nonsecret artifacts."""

    def __init__(self, data_root: str | Path) -> None:
        self._store = EvidenceStore(data_root)
        self._records: dict[UUID, ScanRecord] = {}
        self._lock = Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="afg-scan"
        )
        self._load_persisted_scans()

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
            },
        )
        return record

    def get_scan(self, scan_id: UUID) -> ScanRecord:
        try:
            return self._records[scan_id]
        except KeyError as error:
            raise KeyError(f"Unknown scan '{scan_id}'") from error

    def start_scan(self, scan_id: UUID, execution: ScanExecutionInput) -> ScanRecord:
        try:
            with self._lock:
                record = self._get_scan_locked(scan_id)
                if record.state is not ScanState.CREATED:
                    raise ValueError("Only a created scan can be started")
                if any(self._is_active(other) for other in self._records.values()):
                    raise ValueError("Another scan is already running")
                record.state = ScanState.RUNNING
                self._persist_state(record)
                try:
                    record.future = self._executor.submit(
                        self._run_scan,
                        record,
                        execution,
                    )
                except BaseException:
                    record.state = ScanState.FAILED
                    record.error = "The scan worker could not be started"
                    self._persist_state(record)
                    raise
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
            if record.state is ScanState.CREATED or (
                record.state is ScanState.AWAITING_GUIDANCE
                and not record.cancellation.has_active_work
                and record.pending_observations == 0
            ):
                record.state = ScanState.CANCELLED
                self._discard_pending_execution(record)
                self._persist_state(record)
                self._export_reports(record)
            else:
                self._persist_state(record)
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
                raise ValueError("The scan is not waiting for guidance")
            if record.cancel_requested:
                raise ValueError("The scan has been cancelled")
            record.pending_observations += 1
            secret_values = (
                record.pending_execution.secret_values()
                if record.pending_execution is not None
                else ()
            )
        loop = asyncio.get_running_loop()
        try:
            observation = await loop.run_in_executor(
                self._executor,
                self._observe_guidance_in_worker,
                record,
                str(observation_url) if observation_url else None,
                secret_values,
            )
        except asyncio.CancelledError:
            raise RuntimeError("Guidance observation cancelled") from None
        finally:
            with self._lock:
                record.pending_observations -= 1
                finalize_cancelled = (
                    record.cancel_requested and record.pending_observations == 0
                )
            if finalize_cancelled:
                self._finalize_cancelled(record)
        if record.cancel_requested:
            raise RuntimeError("Guidance observation cancelled")
        with transient_secret_redaction(secret_values):
            safe_event = EvidenceEvent.model_validate(
                redact_persisted_data(observation.event.model_dump(mode="json"))
            )
        self._save_events(record, [safe_event])
        safe_controls = safe_event.redacted_details.get("controls", [])
        return {
            "scan_id": str(record.scan_id),
            "event_id": str(safe_event.event_id),
            "url": safe_event.redacted_details.get("url"),
            "title": safe_event.redacted_details.get("title"),
            "controls": safe_controls if isinstance(safe_controls, list) else [],
        }

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
                raise ValueError("The scan is not waiting for guidance")
            if record.pending_execution is None:
                raise ValueError("The scan no longer has runtime guidance input")
            if record.cancel_requested:
                raise ValueError("The scan has been cancelled")
            if any(self._is_active(other) for other in self._records.values()):
                raise ValueError("Another scan is already running")

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
            record.state = ScanState.RUNNING
            record.error = None
            self._persist_state(record)
            try:
                record.future = self._executor.submit(
                    self._run_guided_scan,
                    record,
                    execution,
                    guidance,
                )
            except BaseException:
                execution.discard_runtime_secrets()
                record.state = ScanState.FAILED
                record.error = "The guided scan worker could not be started"
                self._persist_state(record)
                raise
            return record

    def list_scans(self) -> list[ScanRecord]:
        with self._lock:
            return sorted(
                self._records.values(),
                key=lambda record: record.created_at,
                reverse=True,
            )

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
        if record.state in {ScanState.RUNNING, ScanState.AWAITING_GUIDANCE}:
            raise ValueError("Wait for scan execution to finish before reanalysis")
        if record.profile is None or not record.evidence:
            raise ValueError("The scan has no completed evidence to reanalyse")
        if any(evidence.check_id not in ANALYSERS for evidence in record.evidence):
            raise ValueError(
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
        if extension not in {"json", "html"}:
            raise ValueError("Only JSON and HTML reports are available")
        path = self._store.scan_directory(scan_id) / f"report.{extension}"
        if not path.exists():
            raise FileNotFoundError(f"No {extension} report exists for this scan")
        return path

    def _run_scan(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
    ) -> None:
        try:
            asyncio.run(
                self._run_registered(
                    record,
                    self._run_scan_async(record, execution),
                    execution.secret_values(),
                )
            )
        except asyncio.CancelledError:
            self._finalize_cancelled(record)
        except Exception as error:
            self._finalize_failed(record, error)
        finally:
            if record.pending_execution is not execution:
                execution.discard_runtime_secrets()

    def _run_guided_scan(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        guidance: GuidanceSubmission,
    ) -> None:
        try:
            asyncio.run(
                self._run_registered(
                    record,
                    self._run_guided_scan_async(record, execution, guidance),
                    execution.secret_values(),
                )
            )
        except asyncio.CancelledError:
            self._finalize_cancelled(record)
        except ValueError as error:
            with self._lock:
                record.state = (
                    ScanState.CANCELLED
                    if record.cancel_requested
                    else ScanState.AWAITING_GUIDANCE
                )
                if record.state is ScanState.AWAITING_GUIDANCE:
                    record.pending_execution = execution
                else:
                    self._discard_pending_execution(record)
                record.error = execution.redact_text(str(error))
            self._persist_state(record)
        except Exception as error:
            self._finalize_failed(record, error)
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
    ) -> None:
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
                    record.state = (
                        ScanState.CANCELLED
                        if record.cancel_requested
                        else ScanState.AWAITING_GUIDANCE
                    )
                    unsafe_error = (
                        f"Saved authentication flow needs guidance: {error}"
                        if saved_profile is not None
                        else str(error)
                    )
                    record.error = runtime_secrets.redact_text(unsafe_error)
                    record.pending_execution = (
                        execution
                        if record.state is ScanState.AWAITING_GUIDANCE
                        else None
                    )
                self._persist_state(record)
                return
            await self._complete_profile_execution(record, execution, profile_execution)
        finally:
            runtime_secrets.discard_all()

    async def _run_guided_scan_async(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        guidance: GuidanceSubmission,
    ) -> None:
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
            await self._complete_profile_execution(record, execution, profile_execution)
            self._discard_pending_execution(record)
        finally:
            runtime_secrets.discard_all()

    async def _complete_profile_execution(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        profile_execution: VerifiedLoginExecution,
    ) -> None:
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
            record.state = (
                ScanState.CANCELLED if record.cancel_requested else ScanState.COMPLETED
            )
            self._persist_state(record)
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
            raise KeyError(f"Unknown scan '{scan_id}'") from error

    @staticmethod
    def _discard_pending_execution(record: ScanRecord) -> None:
        if record.pending_execution is not None:
            record.pending_execution.discard_runtime_secrets()
            record.pending_execution = None

    @staticmethod
    def _is_active(record: ScanRecord) -> bool:
        return (
            record.state is ScanState.RUNNING
            or record.cancellation.has_active_work
            or record.pending_observations > 0
        )

    def _finalize_cancelled(self, record: ScanRecord) -> None:
        """Publish cancellation only after the registered worker has unwound."""

        with self._lock:
            if record.state in {ScanState.COMPLETED, ScanState.FAILED}:
                return
            self._preserve_interrupted_check(record)
            record.state = ScanState.CANCELLED
            record.error = "Scan execution cancelled"
            self._discard_pending_execution(record)
            record.active_check = None
            self._persist_state(record)
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

    def _finalize_failed(self, record: ScanRecord, error: BaseException) -> None:
        with self._lock:
            if record.cancel_requested:
                self._preserve_interrupted_check(record)
                record.state = ScanState.CANCELLED
                record.error = "Scan execution cancelled"
            elif record.state is not ScanState.CANCELLED:
                record.state = ScanState.FAILED
                record.error = type(error).__name__
            self._discard_pending_execution(record)
            record.active_check = None
            self._persist_state(record)
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
                "cancel_requested": record.cancel_requested,
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
                request_data.pop("cancel_requested", None)
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
                if state in {ScanState.RUNNING, ScanState.AWAITING_GUIDANCE}:
                    state = ScanState.FAILED
                    error = "Backend restarted during scan execution"
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
                self._records[scan_id] = record
                if state is ScanState.FAILED and metadata.get("state") in {
                    ScanState.RUNNING.value,
                    ScanState.AWAITING_GUIDANCE.value,
                }:
                    self._persist_state(record)
            except (OSError, TypeError, ValueError):
                continue

    def snapshot(self, record: ScanRecord) -> dict[str, Any]:
        return {
            "scan_id": str(record.scan_id),
            "created_at": record.created_at.isoformat(),
            "state": record.state.value,
            "cancel_requested": record.cancel_requested,
            "target_url": str(record.request.target.target_url),
            "event_count": len(record.events),
            "evidence_count": len(record.evidence),
            "result_count": len(record.results),
            "error": record.error,
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
