"""Local scan lifecycle orchestration for the first complete check slice."""

import asyncio
import time
from collections.abc import Callable, Coroutine
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import ROUND_CEILING, Decimal
from enum import StrEnum
from pathlib import Path
from threading import Lock, RLock
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from authflowguard.auth_profiles import login_discovery_source
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
from authflowguard.config import (
    BedrockServerSettings,
    load_server_settings,
    observation_timeout_seconds,
    validate_bedrock_configuration,
    worker_timeout_seconds,
)
from authflowguard.control_roles import (
    LINK_ROLES,
    LOGIN_ROLES,
    ControlRole,
    RoleContext,
    ValidatedRoles,
)
from authflowguard.control_safety import SafeMessageError
from authflowguard.evaluation.cost_tracking import (
    CostLedger,
    CostLedgerStore,
    UsageSource,
)
from authflowguard.evidence import (
    EvidenceStore,
    incremental_event_sink,
    redact_persisted_data,
    transient_secret_redaction,
)
from authflowguard.feature_discovery import (
    FeatureDiscoveryRequest,
    ObservedControls,
    RoleClassifier,
)
from authflowguard.login_suggestions import (
    ClassificationBudget,
    ControlClassificationClient,
    SuggestedControls,
    SuggestionStatus,
    classification_objective,
    classify_within_budget,
    observation_for_classification,
    rules_link_roles,
    rules_suggestion,
    with_link_suggestions,
)
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    CheckId,
    CheckResult,
    Coverage,
    DiscoveryMode,
    DiscoveryProvenance,
    EvidenceEvent,
    EvidenceKind,
    ExecutionLimits,
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
    WorkerProgress,
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


def _usd(value: float) -> str:
    """Format money with the fixed precision the interface and report expect."""

    amount = Decimal(str(value)).quantize(USD_QUANTUM, rounding=ROUND_CEILING)
    return format(amount, "f")


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


USD_QUANTUM = Decimal("0.00000001")

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


class ScanConfigurationError(ScanManagerError):
    code = "invalid_scan_configuration"


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


class ScanDeletionError(ScanManagerError):
    code = "scan_deletion_failed"


class GuidanceObservationError(ScanManagerError):
    code = "guidance_observation_failed"


# The longest the developer waits for a model's control suggestions before
# the observation is returned without them.
CONTROL_SUGGESTION_TIMEOUT_SECONDS = 30.0


def _limits_exceed_server(
    limits: ExecutionLimits, settings: BedrockServerSettings
) -> bool:
    return (
        limits.maximum_ai_decisions > settings.server_max_decisions
        or limits.maximum_active_seconds > settings.server_max_seconds
        or limits.maximum_inference_cost_usd > settings.server_max_cost_usd
    )


def public_failure_message(error: BaseException) -> str:
    """Describe a failed scan without exposing exception text.

    An exception message may contain secrets, so only a ``SafeMessageError``,
    whose message is built from fixed wording, is shown. Any other error shows
    its type alone, which is safe and still makes the failure diagnosable.
    """

    if isinstance(error, SafeMessageError):
        return f"Scan execution failed: {error.safe_message}"
    return f"Scan execution failed ({type(error).__name__})"


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

    def password_references(self) -> frozenset[str]:
        """The references that hold passwords, and only those.

        The browser types these only into password fields and types nothing
        else into a password field. The failure and registration passwords are
        passwords too: the checks type them into password fields.
        """

        references = {self.password_reference, self.failure_password_reference}
        if self.registration_password_reference is not None:
            references.add(self.registration_password_reference)
        return frozenset(references)

    def redact_text(self, value: str) -> str:
        return redact_text(value, self.runtime_secrets.values())

    def discard_runtime_secrets(self) -> None:
        """Release this transient owner's credential references idempotently."""

        for reference_id in list(self.runtime_secrets):
            self.runtime_secrets[reference_id] = ""
        self.runtime_secrets.clear()


ObservedControlId = Annotated[str, Field(pattern=r"^control-[1-9][0-9]{0,5}$")]


class GuidedFeatureLinks(BaseModel):
    """The developer's answers about the login page's other links.

    Each is an observed control id, or None for "no such link". They pass
    the same gate as suggested roles before anything is saved.
    """

    model_config = ConfigDict(extra="forbid")

    registration_link: ObservedControlId | None = None
    reset_link: ObservedControlId | None = None

    def chosen(self) -> dict[ControlRole, str | None]:
        return {
            ControlRole.REGISTRATION_LINK: self.registration_link,
            ControlRole.RESET_LINK: self.reset_link,
        }


class GuidanceSubmission(BaseModel):
    """Transient guided-flow input; actions are sanitized before they are saved."""

    model_config = ConfigDict(extra="forbid")

    actions: list[BrowserAction] = Field(min_length=1)
    protected_resource: HttpUrl | None = None
    account_marker_selector: str | None = None
    account_marker_description: str | None = None
    # Absent from older clients: the links are then looked for by the rules.
    feature_links: GuidedFeatureLinks | None = None


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
    error_code: str | None = None
    state_changed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cancellation: CancellationControl = field(default_factory=CancellationControl)
    future: Future[None] | None = None
    pending_execution: ScanExecutionInput | None = None
    cost_ledger: CostLedger | None = None
    cost_ledger_damaged: bool = False
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
        action_client_factory: Callable[[], ActionSelectionClient] | None = None,
        *,
        worker_backend: Literal["process", "thread", "inline"] = "process",
        cancellation_grace_seconds: float = 3.0,
        worker_timeout: float | None = None,
        observation_timeout: float | None = None,
        suggestion_timeout: float = CONTROL_SUGGESTION_TIMEOUT_SECONDS,
    ) -> None:
        self._store = EvidenceStore(data_root)
        self._suggestion_timeout = suggestion_timeout
        # One classification at a time, so concurrent observations cannot
        # both pass the scan's cost check before either is reserved.
        self._classification_lock = Lock()
        self._data_root = Path(data_root).resolve()
        self._worker_backend = worker_backend
        self._action_client_factory = action_client_factory
        self._worker_timeout = (
            worker_timeout if worker_timeout is not None else worker_timeout_seconds()
        )
        self._observation_timeout = (
            observation_timeout
            if observation_timeout is not None
            else observation_timeout_seconds()
        )
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

    @property
    def has_action_client_factory(self) -> bool:
        return self._action_client_factory is not None

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
                if record.request.discovery_mode == DiscoveryMode.BEDROCK:
                    settings = load_server_settings()
                    if _limits_exceed_server(record.request.limits, settings):
                        raise ScanConfigurationError(
                            "Requested Bedrock limits exceed server maximum limits"
                        )
                    if not self.has_action_client_factory:
                        is_valid, reason = validate_bedrock_configuration()
                        if not is_valid:
                            raise ScanConfigurationError(
                                f"Bedrock discovery is not configured: {reason}"
                            )
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
                            provenance=record.provenance,
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
            record.phase = "cancelled"
            record.stop_reason = "cancelled"
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
        controls = safe_controls if isinstance(safe_controls, list) else []
        page_url = safe_event.redacted_details.get("url")
        page_title = safe_event.redacted_details.get("title")
        suggestions = await self._suggest_login_controls(
            record,
            page_url if isinstance(page_url, str) else "",
            page_title if isinstance(page_title, str) else "",
            [control for control in controls if isinstance(control, dict)],
        )
        return {
            "scan_id": str(record.scan_id),
            "event_id": str(safe_event.event_id),
            "url": page_url,
            "title": page_title,
            "controls": controls,
            "suggested_controls": suggestions.as_response(),
        }

    async def _suggest_login_controls(
        self,
        record: ScanRecord,
        page_url: str,
        page_title: str,
        controls: list[dict[str, Any]],
    ) -> SuggestedControls:
        """Suggest the login controls: the rules first, then a model if allowed.

        The registration and reset links are suggested too: by the rules,
        and by the model only as extra roles in the request made for the
        login controls, never in a request of their own.

        Never raises: a model failure returns the observation without
        suggestions and a status that says why.
        """

        rules_links = ValidatedRoles()
        try:
            context = RoleContext(record.request.target, page_url) if page_url else None
            rules_links = rules_link_roles(controls, context)
            rules = rules_suggestion(controls)
            if rules is not None:
                return with_link_suggestions(rules, rules_links)
            if record.request.discovery_mode != DiscoveryMode.BEDROCK:
                return with_link_suggestions(
                    SuggestedControls(status=SuggestionStatus.NOT_DETECTED),
                    rules_links,
                )
            if record.cancel_requested:
                return with_link_suggestions(
                    SuggestedControls(status=SuggestionStatus.AI_UNAVAILABLE),
                    rules_links,
                )
            prepared = self._prepare_classification(record)
            if isinstance(prepared, SuggestedControls):
                return with_link_suggestions(prepared, rules_links)
            client, budget = prepared
            roles = (
                *LOGIN_ROLES,
                *(role for role in LINK_ROLES if rules_links.control_for(role) is None),
            )
            execution = record.pending_execution
            observation = observation_for_classification(
                page_url=page_url,
                page_title=page_title,
                controls=controls,
                redact=execution.redact_text if execution is not None else str,
                objective=classification_objective(roles),
            )
        except Exception:
            return with_link_suggestions(
                SuggestedControls(status=SuggestionStatus.AI_FAILED), rules_links
            )

        try:
            suggestions = await asyncio.wait_for(
                asyncio.to_thread(
                    classify_within_budget,
                    client,
                    observation,
                    controls,
                    budget,
                    self._classification_lock,
                    roles=roles,
                    context=context,
                ),
                timeout=self._suggestion_timeout,
            )
        except TimeoutError:
            suggestions = SuggestedControls(
                status=SuggestionStatus.AI_TIMED_OUT, model_requests=1
            )
        except Exception:
            suggestions = SuggestedControls(status=SuggestionStatus.AI_FAILED)
        self._record_classification_usage(record, budget, suggestions)
        return with_link_suggestions(suggestions, rules_links)

    def _role_classifier(
        self, record: ScanRecord, execution: ScanExecutionInput
    ) -> RoleClassifier | None:
        """Ask a model for roles during a scan, within its limits and ledger.

        Only a scan using Bedrock discovery gets a classifier. Each request
        is prepared, reserved and reconciled exactly like the observation's
        suggestion request; any limit, failure or timeout answers None.
        """

        if record.request.discovery_mode != DiscoveryMode.BEDROCK:
            return None

        async def classify(
            observed: ObservedControls,
            roles: tuple[ControlRole, ...],
            context: RoleContext,
        ) -> ValidatedRoles | None:
            if record.cancel_requested:
                return None
            try:
                prepared = self._prepare_classification(record)
                if isinstance(prepared, SuggestedControls):
                    return None
                client, budget = prepared
                observation = observation_for_classification(
                    page_url=observed.page_url,
                    page_title=observed.page_title,
                    controls=observed.controls,
                    redact=execution.redact_text,
                    objective=classification_objective(roles),
                )
            except Exception:
                return None
            try:
                suggestions = await asyncio.wait_for(
                    asyncio.to_thread(
                        classify_within_budget,
                        client,
                        observation,
                        observed.controls,
                        budget,
                        self._classification_lock,
                        roles=roles,
                        context=context,
                    ),
                    timeout=self._suggestion_timeout,
                )
            except TimeoutError:
                suggestions = SuggestedControls(
                    status=SuggestionStatus.AI_TIMED_OUT, model_requests=1
                )
            except Exception:
                suggestions = SuggestedControls(status=SuggestionStatus.AI_FAILED)
            self._record_classification_usage(record, budget, suggestions)
            return suggestions.roles

        return classify

    def _feature_discovery(
        self,
        record: ScanRecord,
        execution: ScanExecutionInput,
        guidance: GuidanceSubmission | None = None,
    ) -> FeatureDiscoveryRequest:
        """What to look for after the login, from the checks this scan runs.

        A developer's guided answer about a link is saved whichever checks
        run, and replaces the rules' search for that link.
        """

        selected = set(record.request.selected_checks)
        features: set[AuthFeature] = set()
        if CheckId.REGISTRATION_ENUMERATION in selected:
            features.add(AuthFeature.REGISTRATION)
        if CheckId.RESET_REQUEST_ENUMERATION in selected:
            features.add(AuthFeature.RESET_REQUEST)
        if CheckId.LOGOUT_INVALIDATION in selected:
            features.add(AuthFeature.LOGOUT)
        chosen: dict[ControlRole, str | None] | None = None
        if guidance is not None and guidance.feature_links is not None:
            chosen = guidance.feature_links.chosen()
            if chosen[ControlRole.REGISTRATION_LINK]:
                features.add(AuthFeature.REGISTRATION)
            if chosen[ControlRole.RESET_LINK]:
                features.add(AuthFeature.RESET_REQUEST)
        return FeatureDiscoveryRequest(
            features=frozenset(features),
            classify=self._role_classifier(record, execution),
            chosen_links=chosen,
        )

    def _prepare_classification(
        self, record: ScanRecord
    ) -> tuple[ControlClassificationClient, ClassificationBudget] | SuggestedControls:
        """Decide whether this scan may ask a model, as a scan start does.

        The caller has checked that the scan uses Bedrock discovery. Its
        limits must be within the server's, it must have model requests
        left, and Bedrock must be configured unless a client factory was
        given (tests and offline runs). The budget is checked when the
        request is reserved.
        """

        settings = load_server_settings()
        limits = record.request.limits
        if _limits_exceed_server(limits, settings):
            return SuggestedControls(status=SuggestionStatus.AI_UNAVAILABLE)
        if record.model_request_count >= limits.maximum_ai_decisions:
            return SuggestedControls(status=SuggestionStatus.AI_DECISION_LIMIT_REACHED)
        client: object
        if self._action_client_factory is not None:
            client = self._action_client_factory()
            source = UsageSource.MOCK
        else:
            is_valid, _reason = validate_bedrock_configuration(settings)
            if not is_valid:
                return SuggestedControls(status=SuggestionStatus.AI_UNAVAILABLE)
            client = BedrockActionClient(
                BedrockConfiguration(
                    aws_profile=settings.aws_profile,
                    aws_region=settings.aws_region,
                    model_id=settings.model_id,
                    max_output_tokens=settings.max_output_tokens,
                    maximum_estimated_cost_usd=settings.maximum_estimated_cost_usd,
                )
            )
            source = UsageSource.LIVE
        if not isinstance(client, ControlClassificationClient):
            return SuggestedControls(status=SuggestionStatus.AI_UNAVAILABLE)
        ledger_store = CostLedgerStore(
            self._store.scan_directory(record.scan_id) / "cost-ledger.ndjson"
        )
        try:
            ledger = ledger_store.load_into()
        except (OSError, ValueError):
            # Spending against a ledger that cannot be read could pass the
            # scan's cost limit unnoticed.
            return SuggestedControls(status=SuggestionStatus.AI_UNAVAILABLE)
        return client, ClassificationBudget(
            scan_id=record.scan_id,
            limit_usd=limits.maximum_inference_cost_usd,
            ledger=ledger,
            ledger_store=ledger_store,
            usage_source=source,
            model_id=settings.model_id,
        )

    def _record_classification_usage(
        self,
        record: ScanRecord,
        budget: ClassificationBudget,
        suggestions: SuggestedControls,
    ) -> None:
        """Show a classification request in the scan's usage like any other."""

        with self._lock:
            record.model_request_count += suggestions.model_requests
            if suggestions.answered:
                record.decision_count += 1
                record.total_input_tokens += suggestions.input_tokens
                record.total_output_tokens += suggestions.output_tokens
            record.cost_ledger = budget.ledger
            record.cost_ledger_damaged = False
            record.estimated_cost_usd = float(budget.ledger.total_observed_cost_usd())
            record.unresolved_reservations_usd = float(
                budget.ledger.total_unresolved_reservations_usd()
            )
            if (
                suggestions.model_requests
                and record.provenance is not None
                and record.provenance.usage_source == "none"
            ):
                record.provenance.usage_source = budget.usage_source.value
                record.provenance.model_id = budget.model_id
            self._persist_state(record)

    async def _observe_guidance_in_process(
        self,
        record: ScanRecord,
        command: WorkerCommand,
    ) -> WorkerMessage:
        if self._supervisor is None:
            raise RuntimeError("The process worker supervisor is unavailable")
        result: Future[tuple[WorkerMessage | None, int | None, bool, bool]] = Future()

        def completed(
            message: WorkerMessage | None,
            exit_code: int | None,
            forced: bool,
            timed_out: bool,
        ) -> None:
            if (
                message is not None
                and message.message_type is WorkerMessageType.PROGRESS
            ):
                return
            if not result.done():
                result.set_result((message, exit_code, forced, timed_out))

        supervisor = self._supervisor
        record.future = await asyncio.to_thread(
            lambda: supervisor.start(
                command,
                completed,
                max_runtime_seconds=self._observation_timeout,
            )
        )
        with self._lock:
            self._record_worker_identity(record, command)
        message, exit_code, forced, timed_out = await asyncio.wrap_future(result)
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
        if timed_out:
            raise RuntimeError("The isolated guidance observer timed out")
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
                        provenance=record.provenance,
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

    def delete_scan(self, scan_id: UUID) -> None:
        """Remove an inactive scan with its evidence, results, and reports."""

        with self._lock:
            record = self._records.get(scan_id)
            if record is None and scan_id not in self._recovery_errors:
                raise ScanNotFoundError(f"Scan '{scan_id}' was not found")
            if record is not None and (
                self._is_active(record) or record.state is ScanState.AWAITING_GUIDANCE
            ):
                raise InvalidScanStateError("Cancel the scan before deleting it")
            try:
                self._store.delete_scan(scan_id)
            except OSError:
                raise ScanDeletionError(
                    "The scan files are in use and could not be deleted"
                ) from None
            if record is not None:
                self._discard_pending_execution(record)
            self._records.pop(scan_id, None)
            self._recovery_errors.pop(scan_id, None)

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
            lambda message, exit_code, forced, timed_out: self._apply_process_result(
                record,
                command.worker_generation,
                message,
                exit_code,
                forced,
                timed_out,
            ),
            max_runtime_seconds=self._worker_timeout,
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
        timed_out: bool = False,
    ) -> None:
        export_report = False
        with self._lock:
            if not self._worker_is_current(record, worker_generation):
                return
            if message is not None:
                self._apply_worker_progress(record, message.progress)
            if (
                message is not None
                and message.message_type is WorkerMessageType.PROGRESS
            ):
                self._reload_worker_events(record)
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
            elif timed_out:
                self._discard_pending_execution(record)
                record.active_check = None
                self._transition(
                    record,
                    ScanState.FAILED,
                    error="The scan worker stopped responding and was terminated",
                    error_code="scan_worker_timeout",
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

    def _apply_worker_progress(
        self, record: ScanRecord, progress: WorkerProgress | None
    ) -> None:
        """Mirror the worker's live state so the interface sees real metrics."""

        if progress is None:
            return
        record.active_check = (
            CheckId(progress.active_check) if progress.active_check else None
        )
        record.completed_checks = [
            CheckId(value) for value in progress.completed_checks
        ]
        record.decision_count = progress.decision_count
        record.model_request_count = progress.model_request_count
        record.total_input_tokens = progress.total_input_tokens
        record.total_output_tokens = progress.total_output_tokens
        record.estimated_cost_usd = progress.estimated_cost_usd
        record.unresolved_reservations_usd = progress.unresolved_reservations_usd
        if progress.stop_reason is not None:
            record.stop_reason = progress.stop_reason
        if progress.provenance is not None:
            record.provenance = progress.provenance
        if record.state is ScanState.RUNNING and not record.cancel_requested:
            record.phase = progress.phase

    def _usage_summary(self, record: ScanRecord) -> dict[str, object]:
        """Summarise model usage from the scan's durable cost ledger totals."""

        if record.cost_ledger_damaged:
            return {
                "accounting_error": True,
                "limit_usd": _usd(record.request.limits.maximum_inference_cost_usd),
            }
        ledger = record.cost_ledger
        return {
            "input_tokens": record.total_input_tokens,
            "output_tokens": record.total_output_tokens,
            "settled_cost_usd": _usd(record.estimated_cost_usd),
            "outstanding_reserved_cost_usd": _usd(record.unresolved_reservations_usd),
            "limit_usd": _usd(record.request.limits.maximum_inference_cost_usd),
            "uncertain_requests": (
                len(ledger.unresolved_reservations()) if ledger is not None else 0
            ),
            "usage_source": (
                record.provenance.usage_source if record.provenance else "none"
            ),
        }

    def _load_cost_ledger(self, record: ScanRecord) -> None:
        """Rebuild usage totals from the ledger file the scan owner wrote."""

        ledger_path = self._store.scan_directory(record.scan_id) / "cost-ledger.ndjson"
        if not ledger_path.exists():
            return
        try:
            ledger = CostLedgerStore(ledger_path).load_into()
        except (OSError, ValueError):
            record.cost_ledger = None
            record.cost_ledger_damaged = True
            return
        record.cost_ledger = ledger
        record.cost_ledger_damaged = False
        record.estimated_cost_usd = float(ledger.total_observed_cost_usd())
        record.unresolved_reservations_usd = float(
            ledger.total_unresolved_reservations_usd()
        )
        completed = [entry for entry in ledger if not entry.is_reservation]
        record.total_input_tokens = sum(entry.input_tokens for entry in completed)
        record.total_output_tokens = sum(entry.output_tokens for entry in completed)

    def _reload_worker_events(self, record: ScanRecord) -> None:
        try:
            record.events = self._store.read_events(record.scan_id)
        except (OSError, ValueError):
            # The worker may be mid-append; the next progress update retries.
            pass

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
        self._load_cost_ledger(record)

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
            saved_profile: AuthProfile | None = None
            if record.request.reuse_saved_profile:
                saved_profile = self._find_saved_profile(record, execution)
            feature_discovery = self._feature_discovery(record, execution)

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
                        password_references=execution.password_references(),
                    )
                    profile_execution = await replay_verified_auth_profile(
                        profile=saved_profile,
                        scan_id=record.scan_id,
                        runtime_secrets=runtime_secrets,
                        password_references=execution.password_references(),
                        account_marker_selector=execution.account_marker_selector,
                        feature_discovery=feature_discovery,
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
                        cancel_requested=record.cancellation.is_requested,
                        usage_callback=usage_cb,
                        event_sink=event_sink,
                        cost_ledger_store=ledger_store,
                        cost_ledger=record.cost_ledger,
                        usage_source=source,
                        model_id=model_id,
                        feature_discovery=feature_discovery,
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
                        feature_discovery=feature_discovery,
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
                    if next_state is ScanState.AWAITING_GUIDANCE and record.provenance:
                        record.provenance.guidance_used = True
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
            record.phase = "verifying"
            if record.provenance:
                record.provenance.guidance_used = True
            profile_execution = await execute_guided_verified_login_flow(
                scan_id=record.scan_id,
                target=record.request.target,
                runtime_secrets=runtime_secrets,
                actions=guidance.actions,
                password_references=execution.password_references(),
                protected_resource=str(execution.protected_resource),
                account_marker_selector=execution.account_marker_selector,
                account_marker_description=execution.account_marker_description,
                feature_discovery=self._feature_discovery(record, execution, guidance),
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
                        password_references=execution.password_references(),
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
            record.active_check = None
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
        record.phase = next_state.value
        if next_state is ScanState.CANCELLED:
            record.stop_reason = "cancelled"
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
                public_error = public_failure_message(error)
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
            "usage": self._usage_summary(record),
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
        }
        if record.provenance:
            metadata["provenance"] = record.provenance.model_dump(mode="json")
        self._store.update_metadata(record.scan_id, metadata)

    def _load_persisted_scans(self) -> None:
        self._store.purge_deleted_scans()
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
                    "cancel_requested",
                    "error_code",
                    "state_changed_at",
                    "started_at",
                    "finished_at",
                    "worker_generation",
                    "worker_active",
                    "worker_cleanup",
                    "worker_cleanup_seconds",
                    "worker_pid",
                    "worker_correlation_id",
                    "usage",
                ):
                    request_data.pop(key, None)
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
                cost_ledger_damaged = False
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
                        cost_ledger_damaged = True
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
                    cost_ledger_damaged=cost_ledger_damaged,
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
                source.value
                if record.profile
                and (source := login_discovery_source(record.profile)) is not None
                else None
            ),
            "guidance_required": record.state is ScanState.AWAITING_GUIDANCE,
            "usage": self._usage_summary(record),
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
