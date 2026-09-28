"""Bounded observe-decide-execute orchestration for Bedrock browser actions."""

import asyncio
import json
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from hashlib import sha256
from typing import Protocol
from uuid import UUID, uuid4

from playwright.async_api import Page

from authflowguard.action_executor import ActionExecutionResult, BrowserActionExecutor
from authflowguard.bedrock import (
    BedrockActionDecision,
    BedrockCostLimitError,
    BedrockResponseError,
    ObservedControlForModel,
    PageObservationForModel,
)
from authflowguard.cancellation import cancellation_checkpoint
from authflowguard.control_safety import SafeMessageError
from authflowguard.evaluation.cost_tracking import (
    CostEntry,
    CostLedger,
    CostLedgerStore,
    UsageSource,
    WorkflowPhase,
)
from authflowguard.models import (
    BrowserAction,
    BrowserActionType,
    EvidenceEvent,
    EvidenceKind,
    ExecutionLimits,
    TargetScope,
    TrafficReference,
)
from authflowguard.playwright_worker import PlaywrightWorker, SafeControlDescription
from authflowguard.secrets import RuntimeSecrets

CompletionCheck = Callable[[Page], Awaitable[bool]]
ProgressCallback = Callable[[BedrockActionDecision, ActionExecutionResult], None]
UsageCallback = Callable[[int | None, int | None], None]


class AutomaticActionCancelled(ValueError):
    """An active browser or model wait was interrupted by scan cancellation."""


class ActionSelectionClient(Protocol):
    """The Bedrock operations needed by the automatic action loop."""

    def estimate_maximum_cost(self, observation: PageObservationForModel) -> float:
        """Estimate the maximum cost of the next request."""

    def choose_action(
        self, observation: PageObservationForModel
    ) -> BedrockActionDecision:
        """Return one validated structured action."""


class AutomaticActionStatus(StrEnum):
    COMPLETED = "completed"
    GUIDANCE_REQUIRED = "guidance_required"
    DECISION_LIMIT_REACHED = "decision_limit_reached"
    COST_LIMIT_REACHED = "cost_limit_reached"
    ACTIVE_TIME_LIMIT_REACHED = "active_time_limit_reached"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class AutomaticActionResult:
    status: AutomaticActionStatus
    reason: str
    decisions: list[BedrockActionDecision] = field(default_factory=list)
    executed_actions: list[BrowserAction] = field(default_factory=list)
    events: list[EvidenceEvent] = field(default_factory=list)
    traffic: list[TrafficReference] = field(default_factory=list)
    decision_attempts: int = 0
    failed_attempts: int = 0
    accounted_cost_usd: float = 0.0
    step_control_signatures: list[dict[str, str]] = field(default_factory=list)


class AutomaticBrowserController:
    """Repeatedly ask for and execute one safe structured browser action."""

    def __init__(
        self,
        *,
        page: Page,
        target: TargetScope,
        runtime_secrets: RuntimeSecrets,
        scan_id: UUID,
        action_client: ActionSelectionClient,
        limits: ExecutionLimits,
        credential_references: list[str],
        password_references: frozenset[str],
        progress_callback: ProgressCallback | None = None,
        usage_callback: UsageCallback | None = None,
        event_sink: Callable[[list[EvidenceEvent]], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
        cost_ledger_store: CostLedgerStore | None = None,
        cost_ledger: CostLedger | None = None,
        usage_source: UsageSource | str = UsageSource.NONE,
        model_id: str | None = None,
    ) -> None:
        self._page = page
        self._target = target
        self._runtime_secrets = runtime_secrets
        self._scan_id = scan_id
        self._action_client = action_client
        self._limits = limits
        self._credential_references = credential_references.copy()
        self._progress_callback = progress_callback
        self._usage_callback = usage_callback
        self._event_sink = event_sink
        self._cancel_requested = cancel_requested
        self._cost_ledger_store = cost_ledger_store
        self._cost_ledger = cost_ledger
        self._usage_source = (
            usage_source
            if isinstance(usage_source, UsageSource)
            else UsageSource(usage_source)
        )
        self._model_id = model_id
        self._executor = BrowserActionExecutor(
            page,
            target,
            runtime_secrets,
            scan_id,
            password_references=password_references,
        )
        self._recorder = PlaywrightWorker()

    async def run(self, completion_check: CompletionCheck) -> AutomaticActionResult:
        """Run until the goal is reached or a configured boundary stops work."""

        self._check_cancelled()
        events: list[EvidenceEvent] = []
        self._live_events = events
        traffic: list[TrafficReference] = []
        decisions: list[BedrockActionDecision] = []
        self._executed_actions: list[BrowserAction] = []
        self._executed_signatures: list[dict[str, str]] = []
        step_control_signatures: list[dict[str, str]] = []
        decision_attempts = 0
        consecutive_failures = 0
        total_failures = 0
        accounted_cost = 0.0
        completed_fill_controls: set[str] = set()
        deadline = time.monotonic() + self._limits.maximum_active_seconds

        if self._is_cancelled():
            events.append(self._stop_event("Automatic action cancelled."))
            return self._result(
                AutomaticActionStatus.CANCELLED,
                "Scan cancellation was requested.",
                decisions,
                events,
                traffic,
                decision_attempts,
                total_failures,
                accounted_cost,
                step_control_signatures,
            )

        initial_navigation = BrowserAction(
            action_type=BrowserActionType.NAVIGATE,
            url=self._target.target_url,
            description="Open the configured target before automatic actions",
        )
        try:
            navigation_result = await self._wait_or_cancel(
                self._executor.execute(initial_navigation),
                timeout=self._remaining_seconds(deadline),
            )
        except TimeoutError:
            events.append(self._stop_event("Automatic action time limit reached."))
            return self._result(
                AutomaticActionStatus.ACTIVE_TIME_LIMIT_REACHED,
                "The configured active execution time limit was reached.",
                decisions,
                events,
                traffic,
                decision_attempts,
                total_failures,
                accounted_cost,
                step_control_signatures,
            )
        events.extend(navigation_result.events)
        traffic.extend(navigation_result.traffic)
        self._executed_actions.append(initial_navigation)
        self._executed_signatures.append({})

        initial_controls = await self._recorder.read_controls(self._page)
        step_control_signatures.append(
            {
                self._required(c, "observed_control_id"): self._control_sig(c)
                for c in initial_controls
            }
        )
        last_observed_url = self._page.url

        try:
            initially_complete = await self._wait_or_cancel(
                completion_check(self._page),
                timeout=self._remaining_seconds(deadline),
            )
        except TimeoutError:
            events.append(self._stop_event("Automatic action time limit reached."))
            return self._result(
                AutomaticActionStatus.ACTIVE_TIME_LIMIT_REACHED,
                "The configured active execution time limit was reached.",
                decisions,
                events,
                traffic,
                decision_attempts,
                total_failures,
                accounted_cost,
                step_control_signatures,
            )
        if initially_complete:
            return self._result(
                AutomaticActionStatus.COMPLETED,
                "The completion condition was already satisfied.",
                decisions,
                events,
                traffic,
                decision_attempts,
                total_failures,
                accounted_cost,
                step_control_signatures,
            )

        while True:
            if self._is_cancelled():
                events.append(self._stop_event("Automatic action cancelled."))
                return self._result(
                    AutomaticActionStatus.CANCELLED,
                    "Scan cancellation was requested.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )
            if time.monotonic() >= deadline:
                events.append(self._stop_event("Automatic action time limit reached."))
                return self._result(
                    AutomaticActionStatus.ACTIVE_TIME_LIMIT_REACHED,
                    "The configured active execution time limit was reached.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )
            if decision_attempts >= self._limits.maximum_ai_decisions:
                events.append(
                    self._stop_event("Automatic action decision limit reached.")
                )
                return self._result(
                    AutomaticActionStatus.DECISION_LIMIT_REACHED,
                    "The configured AI decision limit was reached.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )

            if self._page.url != last_observed_url:
                completed_fill_controls.clear()
                last_observed_url = self._page.url

            try:
                observation, current_step_sigs = await self._observe_page(
                    consecutive_failures > 0,
                    completed_fill_controls,
                    timeout_seconds=self._remaining_seconds(deadline),
                )
            except TimeoutError:
                events.append(self._stop_event("Automatic action time limit reached."))
                return self._result(
                    AutomaticActionStatus.ACTIVE_TIME_LIMIT_REACHED,
                    "The configured active execution time limit was reached.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )

            step_control_signatures.append(current_step_sigs)
            self._check_cancelled()
            reserved_cost = self._action_client.estimate_maximum_cost(observation)
            current_committed = (
                float(self._cost_ledger.total_budget_committed_usd())
                if self._cost_ledger is not None
                else accounted_cost
            )
            if (
                current_committed + reserved_cost
                > self._limits.maximum_inference_cost_usd
            ):
                events.append(self._stop_event("Automatic action cost limit reached."))
                return self._result(
                    AutomaticActionStatus.COST_LIMIT_REACHED,
                    "The next model request would exceed the scan cost limit.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )

            request_id = uuid4()
            reserved_cost_decimal = Decimal(str(reserved_cost))
            if self._cost_ledger is not None:
                reservation = self._cost_ledger.record_reservation(
                    request_id=request_id,
                    run_id=str(self._scan_id),
                    workflow="login_discovery",
                    phase=WorkflowPhase.ACTION_SELECTION,
                    model_id=self._model_id or "unknown",
                    source=self._usage_source,
                    reserved_cost_usd=reserved_cost_decimal,
                    scan_id=self._scan_id,
                )
                if self._cost_ledger_store is not None:
                    try:
                        self._cost_ledger_store.append(reservation)
                    except Exception:
                        if reservation in self._cost_ledger._entries:
                            self._cost_ledger._entries.remove(reservation)
                        raise
            elif self._cost_ledger_store is not None:
                reservation = CostEntry(
                    request_id=request_id,
                    run_id=str(self._scan_id),
                    scan_id=self._scan_id,
                    workflow="login_discovery",
                    phase=WorkflowPhase.ACTION_SELECTION,
                    model_id=self._model_id or "unknown",
                    source=self._usage_source,
                    input_tokens=0,
                    output_tokens=0,
                    reserved_cost_usd=reserved_cost_decimal,
                    is_reservation=True,
                )
                self._cost_ledger_store.append(reservation)

            if self._is_cancelled():
                events.append(self._stop_event("Scan cancellation requested."))
                return self._result(
                    AutomaticActionStatus.CANCELLED,
                    "Scan cancellation was requested.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )

            decision_attempts += 1
            if self._usage_callback is not None:
                self._usage_callback(None, None)
            decision: BedrockActionDecision | None = None
            failure_phase = "model_selection"
            try:
                decision = await self._wait_or_cancel(
                    asyncio.to_thread(
                        self._action_client.choose_action,
                        observation,
                    ),
                    timeout=self._remaining_seconds(deadline),
                )
                decisions.append(decision)
                accounted_cost += decision.actual_cost_usd

                if self._cost_ledger is not None:
                    reconciliation = self._cost_ledger.record_reconciliation(
                        request_id=request_id,
                        run_id=str(self._scan_id),
                        workflow="login_discovery",
                        phase=WorkflowPhase.ACTION_SELECTION,
                        model_id=self._model_id or "unknown",
                        source=self._usage_source,
                        input_tokens=decision.input_tokens,
                        output_tokens=decision.output_tokens,
                        reserved_cost_usd=reserved_cost_decimal,
                        scan_id=self._scan_id,
                    )
                    if self._cost_ledger_store is not None:
                        try:
                            self._cost_ledger_store.append(reconciliation)
                        except OSError:
                            self._cost_ledger._entries.remove(reconciliation)
                            raise
                elif self._cost_ledger_store is not None:
                    reconciliation = CostEntry(
                        request_id=request_id,
                        run_id=str(self._scan_id),
                        scan_id=self._scan_id,
                        workflow="login_discovery",
                        phase=WorkflowPhase.ACTION_SELECTION,
                        model_id=self._model_id or "unknown",
                        source=self._usage_source,
                        input_tokens=decision.input_tokens,
                        output_tokens=decision.output_tokens,
                        reserved_cost_usd=reserved_cost_decimal,
                        is_reservation=False,
                        reconciled=True,
                    )
                    self._cost_ledger_store.append(reconciliation)

                if self._usage_callback is not None:
                    self._usage_callback(decision.input_tokens, decision.output_tokens)

                if self._is_cancelled():
                    events.append(self._stop_event("Scan cancellation requested."))
                    return self._result(
                        AutomaticActionStatus.CANCELLED,
                        "Scan cancellation was requested.",
                        decisions,
                        events,
                        traffic,
                        decision_attempts,
                        total_failures,
                        accounted_cost,
                        step_control_signatures,
                    )

                failure_phase = "browser_execution"
                execution = await self._wait_or_cancel(
                    self._executor.execute(decision.action),
                    timeout=self._remaining_seconds(deadline),
                )
                events.extend(execution.events)
                traffic.extend(execution.traffic)
                # Saved with the fingerprint of the control it acted on, so a
                # replay finds that control even if the page shifts.
                self._executed_actions.append(execution.recorded(decision.action))
                self._executed_signatures.append(current_step_sigs)
                if (
                    decision.action.action_type is BrowserActionType.FILL
                    and decision.action.observed_control_id is not None
                ):
                    completed_fill_controls.add(decision.action.observed_control_id)
                elif (
                    execution.page_changes.changed
                    or self._page.url != last_observed_url
                ):
                    completed_fill_controls.clear()
                    last_observed_url = self._page.url
                if self._progress_callback is not None:
                    self._progress_callback(decision, execution)
            except TimeoutError:
                if decision is None:
                    accounted_cost += reserved_cost
                events.append(self._stop_event("Automatic action time limit reached."))
                return self._result(
                    AutomaticActionStatus.ACTIVE_TIME_LIMIT_REACHED,
                    "The configured active execution time limit was reached.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )
            except BedrockCostLimitError:
                events.append(
                    self._stop_event("The Bedrock request cost limit was reached.")
                )
                return self._result(
                    AutomaticActionStatus.COST_LIMIT_REACHED,
                    "The Bedrock client rejected the request before execution.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )
            except AutomaticActionCancelled:
                raise
            except Exception as error:
                if isinstance(error, OSError):
                    raise
                if isinstance(error, BedrockResponseError):
                    if error.input_tokens > 0 or error.actual_cost_usd > 0:
                        accounted_cost += error.actual_cost_usd
                        if self._cost_ledger is not None:
                            reconciliation = self._cost_ledger.record_reconciliation(
                                request_id=request_id,
                                run_id=str(self._scan_id),
                                workflow="login_discovery",
                                phase=WorkflowPhase.ACTION_SELECTION,
                                model_id=self._model_id or "unknown",
                                source=self._usage_source,
                                input_tokens=error.input_tokens,
                                output_tokens=error.output_tokens,
                                reserved_cost_usd=reserved_cost_decimal,
                                scan_id=self._scan_id,
                            )
                            if self._cost_ledger_store is not None:
                                try:
                                    self._cost_ledger_store.append(reconciliation)
                                except OSError:
                                    self._cost_ledger._entries.remove(reconciliation)
                                    raise
                        elif self._cost_ledger_store is not None:
                            reconciliation = CostEntry(
                                request_id=request_id,
                                run_id=str(self._scan_id),
                                scan_id=self._scan_id,
                                workflow="login_discovery",
                                phase=WorkflowPhase.ACTION_SELECTION,
                                model_id=self._model_id or "unknown",
                                source=self._usage_source,
                                input_tokens=error.input_tokens,
                                output_tokens=error.output_tokens,
                                reserved_cost_usd=reserved_cost_decimal,
                                is_reservation=False,
                                reconciled=True,
                            )
                            self._cost_ledger_store.append(reconciliation)
                        if self._usage_callback is not None:
                            self._usage_callback(
                                error.input_tokens, error.output_tokens
                            )
                elif decision is None:
                    accounted_cost += reserved_cost

                consecutive_failures += 1
                total_failures += 1
                error_details: dict[str, object] = {
                    "attempt": decision_attempts,
                    "error_type": type(error).__name__,
                    "failure_phase": failure_phase,
                }
                if isinstance(error, BedrockResponseError):
                    error_details["safe_reason"] = str(error)
                elif isinstance(error, SafeMessageError):
                    error_details["safe_reason"] = error.safe_message
                if decision is not None:
                    error_details["action_type"] = decision.action.action_type.value
                    error_details["observed_control_id"] = (
                        decision.action.observed_control_id
                    )
                events.append(
                    EvidenceEvent(
                        event_id=uuid4(),
                        scan_id=self._scan_id,
                        kind=EvidenceKind.ERROR,
                        summary="An automatic browser action attempt failed.",
                        redacted_details=error_details,
                    )
                )
                if consecutive_failures > self._limits.maximum_action_retries:
                    events.append(
                        self._stop_event(
                            "Automatic action retries exhausted; guidance is required."
                        )
                    )
                    return self._result(
                        AutomaticActionStatus.GUIDANCE_REQUIRED,
                        "Automatic execution failed after the configured retries.",
                        decisions,
                        events,
                        traffic,
                        decision_attempts,
                        total_failures,
                        accounted_cost,
                        step_control_signatures,
                    )
                continue

            consecutive_failures = 0
            try:
                completed = await self._wait_or_cancel(
                    completion_check(self._page),
                    timeout=self._remaining_seconds(deadline),
                )
            except TimeoutError:
                events.append(self._stop_event("Automatic action time limit reached."))
                return self._result(
                    AutomaticActionStatus.ACTIVE_TIME_LIMIT_REACHED,
                    "The configured active execution time limit was reached.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )
            if completed:
                return self._result(
                    AutomaticActionStatus.COMPLETED,
                    "The completion condition was satisfied.",
                    decisions,
                    events,
                    traffic,
                    decision_attempts,
                    total_failures,
                    accounted_cost,
                    step_control_signatures,
                )

    def _is_cancelled(self) -> bool:
        return self._cancel_requested is not None and self._cancel_requested()

    async def _wait_or_cancel[Result](
        self, operation: Awaitable[Result], timeout: float
    ) -> Result:
        task = asyncio.ensure_future(operation)
        end = time.monotonic() + timeout
        try:
            while True:
                if self._is_cancelled():
                    if self._event_sink is not None:
                        self._event_sink(self._live_events)
                    raise AutomaticActionCancelled("Scan cancellation was requested.")
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                done, _ = await asyncio.wait({task}, timeout=min(0.1, remaining))
                if done:
                    return task.result()
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def _observe_page(
        self,
        previous_attempt_failed: bool,
        completed_fill_controls: set[str],
        timeout_seconds: float | None = None,
    ) -> tuple[PageObservationForModel, dict[str, str]]:
        if timeout_seconds is None:
            timeout_seconds = self._limits.maximum_active_seconds
        controls = await self._wait_or_cancel(
            self._recorder.read_controls(self._page),
            timeout=timeout_seconds,
        )
        current_step_sigs: dict[str, str] = {}
        model_controls: list[ObservedControlForModel] = []
        for control in controls:
            control_id = self._required(control, "observed_control_id")
            current_step_sigs[control_id] = self._control_sig(control)
            if control["visible"] and control_id not in completed_fill_controls:
                raw_text = control.get("text")
                redacted_text = (
                    self._runtime_secrets.redact_text(str(raw_text))
                    if raw_text is not None
                    else None
                )
                model_controls.append(
                    ObservedControlForModel(
                        observed_control_id=control_id,
                        tag=self._required(control, "tag"),
                        name=self._redact(control.get("name")),
                        control_type=control.get("type"),
                        placeholder=self._redact(control.get("placeholder")),
                        autocomplete=self._redact(control.get("autocomplete")),
                        aria_label=self._redact(control.get("aria_label")),
                        text=redacted_text,
                        role=(
                            control.get("role")
                            if isinstance(control.get("role"), str)
                            else None
                        ),
                        form_action=(
                            self._redact(control.get("form_action"))
                            if isinstance(control.get("form_action"), str)
                            else None
                        ),
                        value_present=control.get("value_present"),
                        visible=control["visible"],
                        allowed_actions=self._allowed_actions(control),
                    )
                )
        model_controls.sort(key=self._control_priority)
        raw_title = await self._wait_or_cancel(
            self._page.title(),
            timeout=timeout_seconds,
        )
        page_title = self._runtime_secrets.redact_text(raw_title)
        observation = PageObservationForModel(
            page_url=self._runtime_secrets.redact_text(self._page.url),
            page_title=page_title,
            objective=(
                "Complete the authentication flow using only the supplied "
                "credential references."
            ),
            controls=model_controls,
            credential_references=self._credential_references,
            completed_fill_controls=sorted(completed_fill_controls),
            previous_attempt_failed=previous_attempt_failed,
        )
        return observation, current_step_sigs

    @staticmethod
    def _control_sig(control: SafeControlDescription | Mapping[str, object]) -> str:
        metadata = {
            key: control.get(key)
            for key in (
                "tag",
                "id",
                "name",
                "type",
                "placeholder",
                "autocomplete",
                "aria_label",
            )
        }
        serialized = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        return sha256(serialized.encode("utf-8")).hexdigest()

    def _redact(self, value: object) -> str | None:
        return (
            self._runtime_secrets.redact_text(value) if isinstance(value, str) else None
        )

    def _allowed_actions(
        self, control: Mapping[str, object]
    ) -> list[BrowserActionType]:
        tag = control.get("tag")
        control_type = control.get("type")
        if tag == "select":
            return [BrowserActionType.SELECT]
        if tag == "textarea":
            return [BrowserActionType.FILL, BrowserActionType.PRESS_KEY]
        if tag == "input" and control_type not in {
            "button",
            "checkbox",
            "radio",
            "reset",
            "submit",
        }:
            return [BrowserActionType.FILL, BrowserActionType.PRESS_KEY]
        return [BrowserActionType.CLICK]

    def _control_priority(self, control: ObservedControlForModel) -> tuple[int, str]:
        if BrowserActionType.FILL in control.allowed_actions:
            return (0, control.observed_control_id)
        if control.control_type == "submit":
            return (1, control.observed_control_id)
        return (2, control.observed_control_id)

    def _remaining_seconds(self, deadline: float) -> float:
        return max(deadline - time.monotonic(), 0.0)

    def _check_cancelled(self) -> None:
        cancellation_checkpoint()
        if self._is_cancelled():
            raise asyncio.CancelledError("Automatic browser execution cancelled")

    def _required(self, control: Mapping[str, object], key: str) -> str:
        value = control.get(key)
        if not isinstance(value, str):
            raise ValueError(f"Observed control is missing {key}")
        return value

    def _redact_optional(self, value: object) -> str | None:
        if value is None:
            return None
        return self._runtime_secrets.redact_text(str(value))

    def _stop_event(self, summary: str) -> EvidenceEvent:
        return EvidenceEvent(
            event_id=uuid4(),
            scan_id=self._scan_id,
            kind=EvidenceKind.ERROR,
            summary=summary,
        )

    def _result(
        self,
        status: AutomaticActionStatus,
        reason: str,
        decisions: list[BedrockActionDecision],
        events: list[EvidenceEvent],
        traffic: list[TrafficReference],
        decision_attempts: int,
        failed_attempts: int,
        accounted_cost_usd: float,
        step_control_signatures: list[dict[str, str]] | None = None,
    ) -> AutomaticActionResult:
        return AutomaticActionResult(
            status=status,
            reason=reason,
            decisions=decisions,
            executed_actions=self._executed_actions.copy(),
            events=events,
            traffic=traffic,
            decision_attempts=decision_attempts,
            failed_attempts=failed_attempts,
            accounted_cost_usd=accounted_cost_usd,
            step_control_signatures=self._executed_signatures.copy(),
        )
