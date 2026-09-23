"""Bounded observe-decide-execute orchestration for Bedrock browser actions."""

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
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
from authflowguard.models import (
    BrowserAction,
    BrowserActionType,
    EvidenceEvent,
    EvidenceKind,
    ExecutionLimits,
    TargetScope,
    TrafficReference,
)
from authflowguard.playwright_worker import PlaywrightWorker
from authflowguard.secrets import RuntimeSecrets

CompletionCheck = Callable[[Page], Awaitable[bool]]
ProgressCallback = Callable[[BedrockActionDecision, ActionExecutionResult], None]


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


@dataclass(frozen=True)
class AutomaticActionResult:
    status: AutomaticActionStatus
    reason: str
    decisions: list[BedrockActionDecision] = field(default_factory=list)
    events: list[EvidenceEvent] = field(default_factory=list)
    traffic: list[TrafficReference] = field(default_factory=list)
    decision_attempts: int = 0
    failed_attempts: int = 0
    accounted_cost_usd: float = 0.0


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
        progress_callback: ProgressCallback | None = None,
        cancel_requested: Callable[[], bool] = lambda: False,
    ) -> None:
        self._page = page
        self._target = target
        self._scan_id = scan_id
        self._action_client = action_client
        self._limits = limits
        self._credential_references = credential_references.copy()
        self._progress_callback = progress_callback
        self._cancel_requested = cancel_requested
        self._executor = BrowserActionExecutor(
            page,
            target,
            runtime_secrets,
            scan_id,
        )
        self._recorder = PlaywrightWorker()

    async def run(self, completion_check: CompletionCheck) -> AutomaticActionResult:
        """Run until the goal is reached or a configured boundary stops work."""

        self._check_cancelled()
        events: list[EvidenceEvent] = []
        traffic: list[TrafficReference] = []
        decisions: list[BedrockActionDecision] = []
        decision_attempts = 0
        consecutive_failures = 0
        total_failures = 0
        accounted_cost = 0.0
        completed_fill_controls: set[str] = set()
        deadline = time.monotonic() + self._limits.maximum_active_seconds

        initial_navigation = BrowserAction(
            action_type=BrowserActionType.NAVIGATE,
            url=self._target.target_url,
            description="Open the configured target before automatic actions",
        )
        try:
            navigation_result = await asyncio.wait_for(
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
            )
        events.extend(navigation_result.events)
        traffic.extend(navigation_result.traffic)

        try:
            initially_complete = await asyncio.wait_for(
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
            )

        while True:
            self._check_cancelled()
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
                )

            observation = await self._observe_page(
                consecutive_failures > 0,
                completed_fill_controls,
            )
            self._check_cancelled()
            reserved_cost = self._action_client.estimate_maximum_cost(observation)
            if accounted_cost + reserved_cost > self._limits.maximum_inference_cost_usd:
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
                )

            decision_attempts += 1
            decision: BedrockActionDecision | None = None
            failure_phase = "model_selection"
            try:
                decision = await asyncio.wait_for(
                    # Task cancellation stops this await, but Python cannot kill an
                    # SDK call that is already running in the helper thread.
                    asyncio.to_thread(
                        self._action_client.choose_action,
                        observation,
                    ),
                    timeout=self._remaining_seconds(deadline),
                )
                self._check_cancelled()
                decisions.append(decision)
                accounted_cost += decision.actual_cost_usd
                failure_phase = "browser_execution"
                execution = await asyncio.wait_for(
                    self._executor.execute(decision.action),
                    timeout=self._remaining_seconds(deadline),
                )
                events.extend(execution.events)
                traffic.extend(execution.traffic)
                if (
                    decision.action.action_type is BrowserActionType.FILL
                    and decision.action.observed_control_id is not None
                ):
                    completed_fill_controls.add(decision.action.observed_control_id)
                elif execution.page_changes.changed:
                    completed_fill_controls.clear()
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
                )
            except Exception as error:
                if decision is None:
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
                    )
                continue

            consecutive_failures = 0
            try:
                completed = await asyncio.wait_for(
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
                )

    async def _observe_page(
        self,
        previous_attempt_failed: bool,
        completed_fill_controls: set[str],
    ) -> PageObservationForModel:
        controls = await self._recorder.read_controls(self._page)
        model_controls = [
            ObservedControlForModel(
                observed_control_id=self._required(control, "observed_control_id"),
                tag=self._required(control, "tag"),
                name=control.get("name"),
                control_type=control.get("type"),
                placeholder=control.get("placeholder"),
                autocomplete=control.get("autocomplete"),
                aria_label=control.get("aria_label"),
                value_present=control.get("value_present"),
                visible=control["visible"],
                allowed_actions=self._allowed_actions(control),
            )
            for control in controls
            if control["visible"]
            and control["observed_control_id"] not in completed_fill_controls
        ]
        model_controls.sort(key=self._control_priority)
        return PageObservationForModel(
            page_url=self._page.url,
            page_title=await self._page.title(),
            objective=(
                "Complete the authentication flow using only the supplied "
                "credential references."
            ),
            controls=model_controls,
            credential_references=self._credential_references,
            completed_fill_controls=sorted(completed_fill_controls),
            previous_attempt_failed=previous_attempt_failed,
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
        if self._cancel_requested():
            raise asyncio.CancelledError("Automatic browser execution cancelled")

    def _required(self, control: Mapping[str, object], key: str) -> str:
        value = control.get(key)
        if not isinstance(value, str):
            raise ValueError(f"Observed control is missing {key}")
        return value

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
    ) -> AutomaticActionResult:
        return AutomaticActionResult(
            status=status,
            reason=reason,
            decisions=decisions,
            events=events,
            traffic=traffic,
            decision_attempts=decision_attempts,
            failed_attempts=failed_attempts,
            accounted_cost_usd=accounted_cost_usd,
        )
