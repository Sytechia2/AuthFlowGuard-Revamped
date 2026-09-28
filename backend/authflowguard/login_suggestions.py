"""Suggest a page's login controls for the developer to confirm.

The rules are asked first. Only when they do not find a complete, valid set,
and the scan allows AI discovery, is a model asked which controls are the
username, password and submit. Both answers pass through the same gate,
``validate_role_suggestions``: the suggestion only proposes meaning, the code
decides what is allowed, the developer confirms it once, and the verified
login that follows proves it worked.

A model failure never blocks the observation: the developer gets the page's
controls without suggestions and a status saying why.
"""

import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from authflowguard.bedrock import (
    BedrockClassificationDecision,
    BedrockCostLimitError,
    BedrockResponseError,
    ObservedControlForModel,
    PageObservationForModel,
)
from authflowguard.control_roles import (
    LOGIN_ROLES,
    ValidatedRoles,
    rules_role_suggestions,
    validate_role_suggestions,
)
from authflowguard.evaluation.cost_tracking import (
    CostEntry,
    CostLedger,
    CostLedgerStore,
    UsageSource,
    WorkflowPhase,
)

Control = Mapping[str, object]
Redact = Callable[[str], str]

# A login page rarely has this many visible controls; the cap keeps a
# cluttered page's request inside the per-request cost limit.
MAXIMUM_CONTROLS_FOR_CLASSIFICATION = 80
CLASSIFICATION_WORKFLOW = "login_discovery"


class SuggestionSource(StrEnum):
    RULES = "rules"
    AI = "ai"


class SuggestionStatus(StrEnum):
    """What happened when suggesting controls, as fixed wording."""

    RULES_DETECTED = "rules_detected"
    AI_SUGGESTED = "ai_suggested"
    # The rules found no complete set and the scan does not use AI discovery.
    NOT_DETECTED = "not_detected"
    AI_UNAVAILABLE = "ai_unavailable"
    AI_NO_VALID_ROLES = "ai_no_valid_roles"
    AI_COST_LIMIT_REACHED = "ai_cost_limit_reached"
    AI_DECISION_LIMIT_REACHED = "ai_decision_limit_reached"
    AI_FAILED = "ai_failed"
    AI_TIMED_OUT = "ai_timed_out"


@dataclass(frozen=True)
class SuggestedControls:
    """Validated suggestions, and the model usage spent finding them."""

    status: SuggestionStatus
    source: SuggestionSource | None = None
    roles: ValidatedRoles = field(default_factory=ValidatedRoles)
    model_requests: int = 0
    answered: bool = False
    input_tokens: int = 0
    output_tokens: int = 0

    def as_response(self) -> dict[str, object]:
        """The API shape: one control id or None per login role."""

        response: dict[str, object] = {
            role.value: self.roles.control_for(role) for role in LOGIN_ROLES
        }
        response["source"] = self.source.value if self.source else None
        response["status"] = self.status.value
        response["rejected"] = [
            rejection.as_dict() for rejection in self.roles.rejected
        ]
        return response


@runtime_checkable
class ControlClassificationClient(Protocol):
    """The model operations needed to classify a page's controls."""

    def estimate_classification_cost(
        self, observation: PageObservationForModel
    ) -> float:
        """Estimate the maximum cost of one classification request."""

    def classify_controls(
        self, observation: PageObservationForModel
    ) -> BedrockClassificationDecision:
        """Return the roles the model assigned from the fixed list."""


@dataclass
class ClassificationBudget:
    """Where a classification request is accounted, and its limit."""

    scan_id: UUID
    limit_usd: float
    ledger: CostLedger
    ledger_store: CostLedgerStore | None
    usage_source: UsageSource
    model_id: str


def _login_roles_only(roles: ValidatedRoles) -> ValidatedRoles:
    """Keep the accepted login roles; other roles are not offered yet."""

    return ValidatedRoles(
        accepted={
            role: control_id
            for role, control_id in roles.accepted.items()
            if role in LOGIN_ROLES
        },
        rejected=roles.rejected,
    )


def rules_suggestion(controls: Sequence[Control]) -> SuggestedControls | None:
    """The rules' complete, valid login set, or None when they have none."""

    validated = validate_role_suggestions(controls, rules_role_suggestions(controls))
    if not validated.has_login_set:
        return None
    return SuggestedControls(
        status=SuggestionStatus.RULES_DETECTED,
        source=SuggestionSource.RULES,
        roles=ValidatedRoles(
            accepted={role: validated.accepted[role] for role in LOGIN_ROLES}
        ),
    )


def _optional_text(control: Control, key: str, redact: Redact) -> str | None:
    value = control.get(key)
    return redact(value) if isinstance(value, str) else None


def observation_for_classification(
    *,
    page_url: str,
    page_title: str,
    controls: Sequence[Control],
    redact: Redact,
) -> PageObservationForModel:
    """Describe the visible controls for a model, without any field values."""

    model_controls: list[ObservedControlForModel] = []
    for control in controls:
        control_id = control.get("observed_control_id")
        tag = control.get("tag")
        if control.get("visible") is not True:
            continue
        if not isinstance(control_id, str) or not isinstance(tag, str):
            continue
        form_index = control.get("form_index")
        model_controls.append(
            ObservedControlForModel(
                observed_control_id=control_id,
                tag=tag,
                name=_optional_text(control, "name", redact),
                control_type=_optional_text(control, "type", redact),
                placeholder=_optional_text(control, "placeholder", redact),
                autocomplete=_optional_text(control, "autocomplete", redact),
                aria_label=_optional_text(control, "aria_label", redact),
                text=_optional_text(control, "text", redact),
                role=_optional_text(control, "role", redact),
                form_index=(
                    form_index
                    if isinstance(form_index, int) and not isinstance(form_index, bool)
                    else None
                ),
                visible=True,
            )
        )
        if len(model_controls) >= MAXIMUM_CONTROLS_FOR_CLASSIFICATION:
            break
    return PageObservationForModel(
        page_url=redact(page_url) or "about:blank",
        page_title=redact(page_title),
        objective=(
            "Identify the username, password and submit controls of the login form."
        ),
        controls=model_controls,
    )


def _persist(budget: ClassificationBudget, entry: CostEntry) -> None:
    """Write an entry the ledger just recorded, or take it back out."""

    if budget.ledger_store is None:
        return
    try:
        budget.ledger_store.append(entry)
    except Exception:
        if entry in budget.ledger._entries:
            budget.ledger._entries.remove(entry)
        raise


def classify_within_budget(
    client: ControlClassificationClient,
    observation: PageObservationForModel,
    controls: Sequence[Control],
    budget: ClassificationBudget,
    lock: threading.Lock | None = None,
) -> SuggestedControls:
    """Reserve, send and reconcile one classification request, then validate.

    The reservation is written before the request, as for every model
    request, so a crash cannot spend the same budget twice. A request that
    fails without reporting its usage keeps its reservation, because it may
    still have been charged.
    """

    with lock if lock is not None else nullcontext():
        reserved_cost = client.estimate_classification_cost(observation)
        committed = float(budget.ledger.total_budget_committed_usd())
        if committed + reserved_cost > budget.limit_usd:
            return SuggestedControls(status=SuggestionStatus.AI_COST_LIMIT_REACHED)

        request_id = uuid4()
        reserved = Decimal(str(reserved_cost))

        def reconcile(input_tokens: int, output_tokens: int) -> None:
            _persist(
                budget,
                budget.ledger.record_reconciliation(
                    request_id=request_id,
                    run_id=str(budget.scan_id),
                    workflow=CLASSIFICATION_WORKFLOW,
                    phase=WorkflowPhase.FIELD_DETECTION,
                    model_id=budget.model_id,
                    source=budget.usage_source,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    reserved_cost_usd=reserved,
                    scan_id=budget.scan_id,
                ),
            )

        _persist(
            budget,
            budget.ledger.record_reservation(
                request_id=request_id,
                run_id=str(budget.scan_id),
                workflow=CLASSIFICATION_WORKFLOW,
                phase=WorkflowPhase.FIELD_DETECTION,
                model_id=budget.model_id,
                source=budget.usage_source,
                reserved_cost_usd=reserved,
                scan_id=budget.scan_id,
            ),
        )

        decision: BedrockClassificationDecision
        try:
            decision = client.classify_controls(observation)
        except BedrockCostLimitError:
            # Refused before anything was sent.
            reconcile(0, 0)
            return SuggestedControls(status=SuggestionStatus.AI_COST_LIMIT_REACHED)
        except BedrockResponseError as error:
            answered = error.input_tokens > 0 or error.output_tokens > 0
            if answered:
                reconcile(error.input_tokens, error.output_tokens)
            return SuggestedControls(
                status=SuggestionStatus.AI_FAILED,
                model_requests=1,
                answered=answered,
                input_tokens=error.input_tokens,
                output_tokens=error.output_tokens,
            )
        except Exception:
            return SuggestedControls(
                status=SuggestionStatus.AI_FAILED, model_requests=1
            )

        reconcile(decision.input_tokens, decision.output_tokens)

    validated = _login_roles_only(
        validate_role_suggestions(controls, decision.suggestions)
    )
    return SuggestedControls(
        status=(
            SuggestionStatus.AI_SUGGESTED
            if validated.accepted
            else SuggestionStatus.AI_NO_VALID_ROLES
        ),
        source=SuggestionSource.AI if validated.accepted else None,
        roles=validated,
        model_requests=1,
        answered=True,
        input_tokens=decision.input_tokens,
        output_tokens=decision.output_tokens,
    )
