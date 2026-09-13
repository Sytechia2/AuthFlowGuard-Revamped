"""Local scan lifecycle orchestration for the first complete check slice."""

import asyncio
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import Event, Lock
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
from authflowguard.checks.login_enumeration import (
    analyse_login_enumeration,
    run_login_enumeration_check,
)
from authflowguard.evidence import EvidenceStore
from authflowguard.models import (
    AuthProfile,
    BrowserAction,
    CheckId,
    CheckResult,
    EvidenceEvent,
    ScanRequest,
    TargetScope,
    TestRunEvidence,
)
from authflowguard.reports import export_scan_reports
from authflowguard.scope import url_without_query_or_fragment
from authflowguard.secrets import RuntimeSecrets


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
    cancel_requested: Event = field(default_factory=Event)
    future: Future[None] | None = None
    pending_execution: ScanExecutionInput | None = None


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
        with self._lock:
            record = self._get_scan_locked(scan_id)
            if record.state is not ScanState.CREATED:
                raise ValueError("Only a created scan can be started")
            if any(
                other.state is ScanState.RUNNING for other in self._records.values()
            ):
                raise ValueError("Another scan is already running")
            record.state = ScanState.RUNNING
            self._persist_state(record)
            record.future = self._executor.submit(
                self._run_scan,
                record,
                execution,
            )
            return record

    def cancel_scan(self, scan_id: UUID) -> ScanRecord:
        with self._lock:
            record = self._get_scan_locked(scan_id)
            if record.state in {
                ScanState.COMPLETED,
                ScanState.FAILED,
                ScanState.CANCELLED,
            }:
                return record
            record.cancel_requested.set()
            if record.state in {ScanState.CREATED, ScanState.AWAITING_GUIDANCE}:
                record.state = ScanState.CANCELLED
                record.pending_execution = None
                self._persist_state(record)
            return record

    async def observe_guidance(
        self,
        scan_id: UUID,
        observation_url: HttpUrl | None = None,
    ) -> dict[str, Any]:
        """Observe the target page for a developer without retaining live values."""

        record = self.get_scan(scan_id)
        if record.state is not ScanState.AWAITING_GUIDANCE:
            raise ValueError("The scan is not waiting for guidance")
        loop = asyncio.get_running_loop()
        observation = await loop.run_in_executor(
            self._executor,
            self._observe_guidance_in_worker,
            record.scan_id,
            record.request.target,
            str(observation_url) if observation_url else None,
        )
        self._save_events(record, [observation.event])
        return {
            "scan_id": str(record.scan_id),
            "event_id": str(observation.event.event_id),
            "url": observation.event.redacted_details.get("url"),
            "title": observation.event.redacted_details.get("title"),
            "controls": observation.controls,
        }

    @staticmethod
    def _observe_guidance_in_worker(
        scan_id: UUID,
        target: TargetScope,
        observation_url: str | None,
    ) -> GuidedPageObservation:
        return asyncio.run(
            observe_guidance_page(
                scan_id=scan_id,
                target=target,
                observation_url=observation_url,
            )
        )

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
            if any(
                other.state is ScanState.RUNNING for other in self._records.values()
            ):
                raise ValueError("Another scan is already running")

            execution_data = record.pending_execution.model_dump()
            for field_name in (
                "protected_resource",
                "account_marker_selector",
                "account_marker_description",
            ):
                value = getattr(guidance, field_name)
                if value is not None:
                    execution_data[field_name] = value
            execution = ScanExecutionInput.model_validate(execution_data)
            record.state = ScanState.RUNNING
            record.error = None
            self._persist_state(record)
            record.future = self._executor.submit(
                self._run_guided_scan,
                record,
                execution,
                guidance,
            )
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

    def reanalyse(self, scan_id: UUID) -> CheckResult:
        record = self.get_scan(scan_id)
        if record.profile is None or not record.evidence:
            raise ValueError("The scan has no completed evidence to reanalyse")
        evidence = record.evidence[0]
        result = analyse_login_enumeration(
            evidence,
            record.profile,
            record.request.policy,
        )
        record.results.append(result)
        self._store.save_result(result)
        export_scan_reports(self._store, scan_id, record.evidence, record.results)
        return result

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
            asyncio.run(self._run_scan_async(record, execution))
        except Exception as error:
            with self._lock:
                record.state = ScanState.FAILED
                record.error = type(error).__name__
            self._persist_state(record)

    def _run_guided_scan(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        guidance: GuidanceSubmission,
    ) -> None:
        try:
            asyncio.run(self._run_guided_scan_async(record, execution, guidance))
        except ValueError as error:
            with self._lock:
                record.state = ScanState.AWAITING_GUIDANCE
                record.error = str(error)
            self._persist_state(record)
        except Exception as error:
            with self._lock:
                record.state = ScanState.FAILED
                record.error = type(error).__name__
            self._persist_state(record)

    async def _run_scan_async(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
    ) -> None:
        if record.cancel_requested.is_set():
            record.state = ScanState.CANCELLED
            self._persist_state(record)
            return

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
                    record.state = ScanState.AWAITING_GUIDANCE
                    record.error = (
                        f"Saved authentication flow needs guidance: {error}"
                        if saved_profile is not None
                        else str(error)
                    )
                    record.pending_execution = execution
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
            record.pending_execution = None
        finally:
            runtime_secrets.discard_all()

    async def _complete_profile_execution(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        profile_execution: VerifiedLoginExecution,
    ) -> None:
        record.profile = profile_execution.profile
        self._store.save_profile(record.scan_id, profile_execution.profile)
        self._save_events(record, profile_execution.events)

        if record.cancel_requested.is_set():
            record.state = ScanState.CANCELLED
            self._persist_state(record)
            return

        if CheckId.LOGIN_ENUMERATION in record.request.selected_checks:
            check_secrets = RuntimeSecrets(execution.runtime_secrets)
            try:
                run = await run_login_enumeration_check(
                    profile=profile_execution.profile,
                    scan_id=record.scan_id,
                    runtime_secrets=check_secrets,
                    known_identifier_reference=execution.username_reference,
                    nonexistent_identifier_reference=(
                        execution.nonexistent_identifier_reference
                    ),
                    failure_password_reference=execution.failure_password_reference,
                )
            finally:
                check_secrets.discard_all()
            self._save_events(record, run.events)
            record.evidence.append(run.evidence)
            self._store.save_evidence(run.evidence)
            result = analyse_login_enumeration(
                run.evidence,
                profile_execution.profile,
                record.request.policy,
            )
            record.results.append(result)
            self._store.save_result(result)
            export_scan_reports(
                self._store,
                record.scan_id,
                record.evidence,
                record.results,
            )
        record.state = (
            ScanState.CANCELLED
            if record.cancel_requested.is_set()
            else ScanState.COMPLETED
        )
        self._persist_state(record)

    def _save_events(
        self,
        record: ScanRecord,
        events: list[EvidenceEvent],
    ) -> None:
        record.events.extend(events)
        for event in events:
            self._store.append_event(event)

    def _get_scan_locked(self, scan_id: UUID) -> ScanRecord:
        try:
            return self._records[scan_id]
        except KeyError as error:
            raise KeyError(f"Unknown scan '{scan_id}'") from error

    def _persist_state(self, record: ScanRecord) -> None:
        self._store.update_metadata(
            record.scan_id,
            {"state": record.state.value, "error": record.error},
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
                    results=results,
                    profile=self._store.read_profile(scan_id),
                    error=str(error) if error is not None else None,
                )
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
            "results": [result.model_dump(mode="json") for result in record.results],
        }
