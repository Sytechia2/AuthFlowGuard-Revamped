"""Local scan lifecycle orchestration for the first complete check slice."""

import asyncio
from collections.abc import Callable
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
    execute_ai_verified_login_flow,
    execute_guided_verified_login_flow,
    execute_verified_login_flow,
    observe_guidance_page,
    replay_verified_auth_profile,
    revalidate_auth_profile,
)
from authflowguard.automatic_actions import (
    ActionSelectionClient,
)
from authflowguard.bedrock import BedrockActionClient, BedrockConfiguration
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
from authflowguard.config import (
    load_server_settings,
    validate_bedrock_configuration,
)
from authflowguard.evaluation.cost_tracking import (
    CostLedger,
    CostLedgerStore,
    UsageSource,
)
from authflowguard.evidence import EvidenceStore
from authflowguard.models import (
    AuthProfile,
    BrowserAction,
    CheckId,
    CheckResult,
    DiscoveryMode,
    DiscoveryProvenance,
    EvidenceEvent,
    ScanRequest,
    TargetScope,
    TestRunEvidence,
)
from authflowguard.reports import export_scan_reports
from authflowguard.scope import url_without_query_or_fragment
from authflowguard.secrets import RuntimeSecrets

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
    phase: str = "created"
    decision_count: int = 0
    model_request_count: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    unresolved_reservations_usd: float = 0.0
    stop_reason: str | None = None
    provenance: DiscoveryProvenance | None = None
    events: list[EvidenceEvent] = field(default_factory=list)
    evidence: list[TestRunEvidence] = field(default_factory=list)
    results: list[CheckResult] = field(default_factory=list)
    profile: AuthProfile | None = None
    error: str | None = None
    cancel_requested: Event = field(default_factory=Event)
    future: Future[None] | None = None
    pending_execution: ScanExecutionInput | None = None
    cost_ledger: CostLedger | None = None


class ScanManager:
    """Keep one active local scan and persist its nonsecret artifacts."""

    def __init__(
        self,
        data_root: str | Path,
        action_client_factory: Callable[[], ActionSelectionClient] | None = None,
    ) -> None:
        self._store = EvidenceStore(data_root)
        self._action_client_factory = action_client_factory
        self._records: dict[UUID, ScanRecord] = {}
        self._lock = Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="afg-scan"
        )
        self._load_persisted_scans()

    @property
    def has_action_client_factory(self) -> bool:
        return self._action_client_factory is not None

    def create_scan(self, request: ScanRequest) -> ScanRecord:
        provenance = DiscoveryProvenance(
            requested_mode=request.discovery_mode,
            actual_engine=None,
            usage_source="none",
            reused_profile=False,
            guidance_used=False,
            model_id=None,
        )
        record = ScanRecord(
            scan_id=uuid4(),
            request=request,
            provenance=provenance,
        )
        with self._lock:
            self._records[record.scan_id] = record
        self._store.create_scan(
            record.scan_id,
            {
                **request.model_dump(mode="json"),
                "created_at": record.created_at.isoformat(),
                "state": record.state.value,
                "phase": record.phase,
                "provenance": provenance.model_dump(mode="json"),
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
            if record.request.discovery_mode == DiscoveryMode.BEDROCK:
                settings = load_server_settings()
                limits = record.request.limits
                if (
                    limits.maximum_ai_decisions > settings.server_max_decisions
                    or limits.maximum_active_seconds > settings.server_max_seconds
                    or limits.maximum_inference_cost_usd > settings.server_max_cost_usd
                ):
                    raise ValueError(
                        "Requested Bedrock limits exceed server maximum limits"
                    )
                if not self.has_action_client_factory:
                    is_valid, reason = validate_bedrock_configuration()
                    if not is_valid:
                        raise ValueError(
                            f"Bedrock discovery is not configured: {reason}"
                        )
            record.state = ScanState.RUNNING
            record.phase = "running"
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
            record.phase = "cancelled"
            record.stop_reason = "cancelled"
            record.pending_execution = None
            if record.state in {ScanState.CREATED, ScanState.AWAITING_GUIDANCE}:
                record.state = ScanState.CANCELLED
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
            record.phase = "running"
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
            asyncio.run(self._run_scan_async(record, execution))
        except Exception as error:
            with self._lock:
                if record.cancel_requested.is_set():
                    record.state = ScanState.CANCELLED
                    record.phase = "cancelled"
                    record.stop_reason = "cancelled"
                    record.pending_execution = None
                else:
                    record.state = ScanState.FAILED
                    record.phase = "failed"
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
                record.state = (
                    ScanState.CANCELLED
                    if record.cancel_requested.is_set()
                    else ScanState.AWAITING_GUIDANCE
                )
                record.phase = (
                    "cancelled"
                    if record.cancel_requested.is_set()
                    else "awaiting_guidance"
                )
                if record.state is ScanState.CANCELLED:
                    record.pending_execution = None
                record.error = str(error)
            self._persist_state(record)
        except Exception as error:
            with self._lock:
                record.state = ScanState.FAILED
                record.phase = "failed"
                record.error = type(error).__name__
            self._persist_state(record)

    async def _run_scan_async(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
    ) -> None:
        if record.cancel_requested.is_set():
            record.state = ScanState.CANCELLED
            record.phase = "cancelled"
            record.stop_reason = "cancelled"
            self._persist_state(record)
            return

        runtime_secrets = RuntimeSecrets(execution.runtime_secrets)
        try:
            saved_profile: AuthProfile | None = None
            if record.request.reuse_saved_profile:
                saved_profile = self._find_saved_profile(record, execution)

            try:
                if saved_profile is not None:
                    record.phase = "verifying"
                    if record.provenance:
                        record.provenance.reused_profile = True
                        record.provenance.actual_engine = None
                        record.provenance.usage_source = "none"
                    await revalidate_auth_profile(
                        profile=saved_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=runtime_secrets,
                    )
                    profile_execution = await replay_verified_auth_profile(
                        profile=saved_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=runtime_secrets,
                        account_marker_selector=execution.account_marker_selector,
                    )
                elif record.request.discovery_mode == DiscoveryMode.BEDROCK:
                    record.phase = "discovering"
                    settings = load_server_settings()
                    model_id = settings.model_id
                    if self._action_client_factory is not None:
                        client = self._action_client_factory()
                        source = UsageSource.MOCK
                    else:
                        config = BedrockConfiguration(
                            aws_profile=settings.aws_profile,
                            aws_region=settings.aws_region,
                            model_id=settings.model_id,
                            max_output_tokens=settings.max_output_tokens,
                            maximum_estimated_cost_usd=settings.maximum_estimated_cost_usd,
                        )
                        client = BedrockActionClient(config)
                        source = UsageSource.LIVE

                    if record.provenance:
                        record.provenance.actual_engine = "bedrock"
                        record.provenance.usage_source = source.value
                        record.provenance.model_id = model_id

                    ledger_path = (
                        self._store.scan_directory(record.scan_id)
                        / "cost-ledger.ndjson"
                    )
                    ledger_store = CostLedgerStore(ledger_path)
                    record.cost_ledger = ledger_store.load_into()

                    def usage_cb(
                        input_tokens: int | None, output_tokens: int | None
                    ) -> None:
                        with self._lock:
                            if input_tokens is None:
                                record.model_request_count += 1
                            else:
                                record.decision_count += 1
                                record.total_input_tokens += input_tokens
                                record.total_output_tokens += output_tokens or 0
                            if record.cost_ledger:
                                record.estimated_cost_usd = float(
                                    record.cost_ledger.total_observed_cost_usd()
                                )
                                record.unresolved_reservations_usd = float(
                                    record.cost_ledger.total_unresolved_reservations_usd()
                                )
                            self._persist_state(record)

                    def event_sink(events: list[EvidenceEvent]) -> None:
                        with self._lock:
                            self._save_events(record, events)

                    profile_execution = await execute_ai_verified_login_flow(
                        scan_id=record.scan_id,
                        target=record.request.target,
                        runtime_secrets=runtime_secrets,
                        username_reference=execution.username_reference,
                        password_reference=execution.password_reference,
                        second_factor_reference=execution.second_factor_reference,
                        protected_resource=str(execution.protected_resource),
                        account_marker_selector=execution.account_marker_selector,
                        account_marker_description=execution.account_marker_description,
                        action_client=client,
                        limits=record.request.limits,
                        cancel_requested=record.cancel_requested.is_set,
                        usage_callback=usage_cb,
                        event_sink=event_sink,
                        cost_ledger_store=ledger_store,
                        cost_ledger=record.cost_ledger,
                        usage_source=source,
                        model_id=model_id,
                    )
                    if record.cost_ledger:
                        record.estimated_cost_usd = float(
                            record.cost_ledger.total_observed_cost_usd()
                        )
                        record.unresolved_reservations_usd = float(
                            record.cost_ledger.total_unresolved_reservations_usd()
                        )
                else:
                    record.phase = "discovering"
                    if record.provenance:
                        record.provenance.actual_engine = "rules"
                        record.provenance.usage_source = "none"
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
                    if record.cancel_requested.is_set():
                        record.state = ScanState.CANCELLED
                        record.phase = "cancelled"
                        record.stop_reason = "cancelled"
                        record.pending_execution = None
                    else:
                        record.state = ScanState.AWAITING_GUIDANCE
                        record.phase = "awaiting_guidance"
                        record.stop_reason = str(error)
                        record.pending_execution = execution
                        if record.provenance:
                            record.provenance.guidance_used = True
                    record.error = (
                        f"Saved authentication flow needs guidance: {error}"
                        if saved_profile is not None
                        else str(error)
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
            record.phase = "verifying"
            if record.provenance:
                record.provenance.guidance_used = True
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
            record.phase = "cancelled"
            record.stop_reason = "cancelled"
            record.pending_execution = None
            self._persist_state(record)
            return

        record.phase = "checking"
        self._persist_state(record)

        check_order = (
            CheckId.LOGIN_ENUMERATION,
            CheckId.RESET_REQUEST_ENUMERATION,
            CheckId.REGISTRATION_ENUMERATION,
            CheckId.LOGIN_THROTTLING,
            CheckId.SESSION_FIXATION,
            CheckId.LOGOUT_INVALIDATION,
        )
        for check_id in check_order:
            if record.cancel_requested.is_set():
                break
            if check_id not in record.request.selected_checks:
                continue
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
                        profile=profile_execution.profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        known_identifier_reference=execution.username_reference,
                        nonexistent_identifier_reference=execution.nonexistent_identifier_reference,
                        failure_password_reference=execution.failure_password_reference,
                    )
                elif check_id is CheckId.RESET_REQUEST_ENUMERATION:
                    run = await run_reset_request_enumeration_check(
                        profile=profile_execution.profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        known_identifier_reference=execution.username_reference,
                        nonexistent_identifier_reference=execution.nonexistent_identifier_reference,
                        form_url=str(execution.reset_request_url)
                        if execution.reset_request_url
                        else None,
                        cancel_requested=record.cancel_requested.is_set,
                    )
                elif check_id is CheckId.LOGIN_THROTTLING:
                    run = await run_login_throttling_check(
                        profile=profile_execution.profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        username_reference=execution.username_reference,
                        password_reference=execution.password_reference,
                        failure_password_reference=execution.failure_password_reference,
                        expected_lockout_threshold=(
                            record.request.policy.expected_lockout_threshold
                        ),
                        cancel_requested=record.cancel_requested.is_set,
                    )
                elif check_id is CheckId.SESSION_FIXATION:
                    run = await run_session_fixation_check(
                        profile=profile_execution.profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        username_reference=execution.username_reference,
                        password_reference=execution.password_reference,
                        protected_resource=str(execution.protected_resource),
                        account_marker_selector=execution.account_marker_selector,
                        cancel_requested=record.cancel_requested.is_set,
                    )
                elif check_id is CheckId.LOGOUT_INVALIDATION:
                    run = await run_logout_invalidation_check(
                        profile=profile_execution.profile,
                        scan_id=record.scan_id,
                        runtime_secrets=check_secrets,
                        username_reference=execution.username_reference,
                        password_reference=execution.password_reference,
                        protected_resource=str(execution.protected_resource),
                        account_marker_selector=execution.account_marker_selector,
                        cancel_requested=record.cancel_requested.is_set,
                    )
                else:
                    run = await run_registration_enumeration_check(
                        profile=profile_execution.profile,
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
                        cancel_requested=record.cancel_requested.is_set,
                    )
            finally:
                check_secrets.discard_all()
            self._save_events(record, run.events)
            record.evidence.append(run.evidence)
            self._store.save_evidence(run.evidence)
            result = ANALYSERS[check_id](
                run.evidence,
                profile_execution.profile,
                record.request.policy,
            )
            record.results.append(result)
            self._store.save_result(result)

        record.state = (
            ScanState.CANCELLED
            if record.cancel_requested.is_set()
            else ScanState.COMPLETED
        )
        record.phase = "cancelled" if record.cancel_requested.is_set() else "completed"
        if record.state is ScanState.CANCELLED:
            record.stop_reason = "cancelled"
            record.pending_execution = None
        self._persist_state(record)
        if record.evidence:
            export_scan_reports(
                self._store, record.scan_id, record.evidence, record.results
            )

    def _save_events(
        self,
        record: ScanRecord,
        events: list[EvidenceEvent],
    ) -> None:
        existing = {event.event_id for event in record.events}
        for event in events:
            if event.event_id in existing:
                continue
            self._store.append_event(event)
            record.events.append(event)
            existing.add(event.event_id)

    def _get_scan_locked(self, scan_id: UUID) -> ScanRecord:
        try:
            return self._records[scan_id]
        except KeyError as error:
            raise KeyError(f"Unknown scan '{scan_id}'") from error

    def _persist_state(self, record: ScanRecord) -> None:
        metadata: dict[str, Any] = {
            "state": record.state.value,
            "error": record.error,
            "phase": record.phase,
            "decision_count": record.decision_count,
            "model_request_count": record.model_request_count,
            "total_input_tokens": record.total_input_tokens,
            "total_output_tokens": record.total_output_tokens,
            "estimated_cost_usd": record.estimated_cost_usd,
            "unresolved_reservations_usd": record.unresolved_reservations_usd,
            "stop_reason": record.stop_reason,
        }
        if record.provenance:
            metadata["provenance"] = record.provenance.model_dump(mode="json")
        self._store.update_metadata(record.scan_id, metadata)

    def _load_persisted_scans(self) -> None:
        for scan_id in self._store.list_scan_ids():
            try:
                metadata = self._store.read_metadata(scan_id)
                request_data = dict(metadata)
                for key in (
                    "scan_id",
                    "created_at",
                    "state",
                    "error",
                    "phase",
                    "decision_count",
                    "model_request_count",
                    "total_input_tokens",
                    "total_output_tokens",
                    "estimated_cost_usd",
                    "unresolved_reservations_usd",
                    "stop_reason",
                    "provenance",
                ):
                    request_data.pop(key, None)
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

                phase = str(
                    metadata.get(
                        "phase",
                        "completed" if state is ScanState.COMPLETED else state.value,
                    )
                )
                decision_count = int(metadata.get("decision_count", 0))
                model_request_count = int(metadata.get("model_request_count", 0))
                total_input_tokens = int(metadata.get("total_input_tokens", 0))
                total_output_tokens = int(metadata.get("total_output_tokens", 0))
                estimated_cost_usd = float(metadata.get("estimated_cost_usd", 0.0))
                unresolved_reservations_usd = float(
                    metadata.get("unresolved_reservations_usd", 0.0)
                )
                stop_reason = metadata.get("stop_reason")

                raw_prov = metadata.get("provenance")
                provenance: DiscoveryProvenance | None = None
                if raw_prov and isinstance(raw_prov, dict):
                    try:
                        provenance = DiscoveryProvenance.model_validate(raw_prov)
                    except ValueError:
                        pass
                if provenance is None:
                    provenance = DiscoveryProvenance(
                        requested_mode=request.discovery_mode
                    )

                ledger_path = self._store.scan_directory(scan_id) / "cost-ledger.ndjson"
                cost_ledger: CostLedger | None = None
                if ledger_path.exists():
                    try:
                        cost_ledger = CostLedgerStore(ledger_path).load_into()
                        estimated_cost_usd = float(
                            cost_ledger.total_observed_cost_usd()
                        )
                        unresolved_reservations_usd = float(
                            cost_ledger.total_unresolved_reservations_usd()
                        )
                    except (OSError, ValueError):
                        state = ScanState.FAILED
                        phase = "failed"
                        error = "Cost ledger is damaged; usage cannot be reconciled"

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
                    phase=phase,
                    decision_count=decision_count,
                    model_request_count=model_request_count,
                    total_input_tokens=total_input_tokens,
                    total_output_tokens=total_output_tokens,
                    estimated_cost_usd=estimated_cost_usd,
                    unresolved_reservations_usd=unresolved_reservations_usd,
                    stop_reason=stop_reason,
                    provenance=provenance,
                    events=self._store.read_events(scan_id),
                    evidence=self._store.read_all_evidence(scan_id),
                    results=_latest_results(results),
                    profile=self._store.read_profile(scan_id),
                    error=str(error) if error is not None else None,
                    cost_ledger=cost_ledger,
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
            "phase": record.phase,
            "decision_count": record.decision_count,
            "model_request_count": record.model_request_count,
            "total_input_tokens": record.total_input_tokens,
            "total_output_tokens": record.total_output_tokens,
            "estimated_cost_usd": record.estimated_cost_usd,
            "unresolved_reservations_usd": record.unresolved_reservations_usd,
            "stop_reason": record.stop_reason,
            "provenance": (
                record.provenance.model_dump(mode="json") if record.provenance else None
            ),
            "discovery_mode": record.request.discovery_mode.value,
            "reuse_saved_profile": record.request.reuse_saved_profile,
        }
