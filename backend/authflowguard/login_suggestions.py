"""Suggest a page's login controls for the developer to confirm.

The rules are asked first. Only when they do not find a complete, valid set,
and the scan allows AI discovery, is a model asked which controls are the
username, password and submit. Both answers pass through the same gate,
``validate_role_suggestions``: the suggestion only proposes meaning, the code
decides what is allowed, the developer confirms it once, and the verified
login that follows proves it worked.

The same observation also suggests the links that open the registration and
password-reset forms: the rules first, and the model only as extra roles in
the classification request that is made anyway, never in a request of its
own.

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
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from authflowguard.bedrock import (
    BedrockClassificationDecision,
    BedrockCostLimitError,
    BedrockResponseError,
    ObservedControlForModel,
    PageObservationForModel,
)
from authflowguard.control_roles import (
    LINK_ROLES,
    LOGIN_ROLES,
    ControlRole,
    RoleContext,
    ValidatedRoles,
    rules_link_suggestions,
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
from authflowguard.scope import url_without_query_keeping_route

Control = Mapping[str, object]
Redact = Callable[[str], str]

# A login page rarely has this many visible controls; the cap keeps a
# cluttered page's request inside the per-request cost limit.
MAXIMUM_CONTROLS_FOR_CLASSIFICATION = 80
LINK_PATH_LIMIT = 200
CLASSIFICATION_WORKFLOW = "login_discovery"
LOGIN_OBJECTIVE = (
    "Identify the username, password and submit controls of the login form."
)
# What each role means, sent with the roles a request asks for. Naming a role
# alone was not enough: in a live measurement the model never assigned a
# link role it was asked for, because nothing said links count.
ROLE_DESCRIPTIONS = {
    ControlRole.USERNAME: "the field that takes the username or email address",
    ControlRole.PASSWORD: "the password field",
    ControlRole.SUBMIT: (
        "the button that sends this step of the login; never a control listed "
        "in used_controls"
    ),
    ControlRole.VERIFICATION_CODE: "the field that takes a one-time code",
    ControlRole.REGISTRATION_LINK: (
        "the link or button that opens the sign-up page, for example "
        "'Register', 'Sign up', 'Create account' or 'Not yet a customer?'; it "
        "is often outside the login form"
    ),
    ControlRole.RESET_LINK: (
        "the link or button that opens the forgotten-password page, for "
        "example 'Forgot your password?' or 'Reset password'; it is often "
        "outside the login form"
    ),
    ControlRole.LOGOUT: "the control that signs the user out",
    ControlRole.ACCOUNT_MENU: "the button that opens the menu holding logout",
}


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
    """Validated suggestions, and the model usage spent finding them.

    ``roles`` holds the accepted roles that were asked for. ``links`` holds
    the registration and reset links suggested for the same page, each with
    where it came from, since the rules may find a link when the model
    suggested the login controls, and the other way round.
    """

    status: SuggestionStatus
    source: SuggestionSource | None = None
    roles: ValidatedRoles = field(default_factory=ValidatedRoles)
    model_requests: int = 0
    answered: bool = False
    input_tokens: int = 0
    output_tokens: int = 0
    links: Mapping[ControlRole, tuple[str, SuggestionSource]] = field(
        default_factory=dict
    )

    def as_response(self) -> dict[str, object]:
        """The API shape: one control id or None per login and link role."""

        response: dict[str, object] = {
            role.value: self.roles.control_for(role) for role in LOGIN_ROLES
        }
        response["source"] = self.source.value if self.source else None
        response["status"] = self.status.value
        response["rejected"] = [
            rejection.as_dict() for rejection in self.roles.rejected
        ]
        for role in LINK_ROLES:
            link = self.links.get(role)
            response[role.value] = link[0] if link else None
        response["link_sources"] = {
            role.value: link[1].value
            for role in LINK_ROLES
            if (link := self.links.get(role)) is not None
        }
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


def _requested_roles_only(
    roles: ValidatedRoles, requested: Sequence[ControlRole]
) -> ValidatedRoles:
    """Keep the accepted and rejected roles that were asked for."""

    return ValidatedRoles(
        accepted={
            role: control_id
            for role, control_id in roles.accepted.items()
            if role in requested
        },
        rejected=tuple(
            rejection for rejection in roles.rejected if rejection.role in requested
        ),
    )


def classification_objective(roles: Sequence[ControlRole]) -> str:
    """Tell the model which roles, from the fixed list, to look for."""

    if tuple(roles) == LOGIN_ROLES:
        return LOGIN_OBJECTIVE
    described = "; ".join(
        f"{role.value}: {ROLE_DESCRIPTIONS[role]}"
        if role in ROLE_DESCRIPTIONS
        else role.value
        for role in roles
    )
    return (
        "Assign each of these roles to its control whenever the page has one, "
        f"and only these roles: {described}."
    )


def rules_link_roles(
    controls: Sequence[Control], context: RoleContext | None
) -> ValidatedRoles:
    """The registration and reset links the rules find and the gate accepts."""

    return _requested_roles_only(
        validate_role_suggestions(
            controls, rules_link_suggestions(controls), context=context
        ),
        LINK_ROLES,
    )


def with_link_suggestions(
    suggested: SuggestedControls, rules_links: ValidatedRoles
) -> SuggestedControls:
    """Split a suggestion into its login controls and its links.

    The rules' link wins; a model's link for the same role is used only when
    the rules found none. The status and source describe the login controls.
    """

    links: dict[ControlRole, tuple[str, SuggestionSource]] = {}
    for role in LINK_ROLES:
        rules_id = rules_links.control_for(role)
        # The rules' login suggestion holds login roles only, so a link role
        # in ``suggested`` came from a model's answer.
        model_id = suggested.roles.control_for(role)
        if rules_id is not None:
            links[role] = (rules_id, SuggestionSource.RULES)
        elif model_id is not None:
            links[role] = (model_id, SuggestionSource.AI)
    login = _requested_roles_only(suggested.roles, LOGIN_ROLES)
    status = suggested.status
    source = suggested.source
    if status is SuggestionStatus.AI_SUGGESTED and not login.accepted:
        status = SuggestionStatus.AI_NO_VALID_ROLES
        source = None
    return SuggestedControls(
        status=status,
        source=source,
        roles=login,
        model_requests=suggested.model_requests,
        answered=suggested.answered,
        input_tokens=suggested.input_tokens,
        output_tokens=suggested.output_tokens,
        links=links,
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


def _link_path(control: Control, redact: Redact) -> str | None:
    """A link's path and client-side route, without origin, query or token."""

    href = control.get("href")
    if not isinstance(href, str):
        return None
    parts = urlsplit(url_without_query_keeping_route(href))
    if parts.scheme not in {"http", "https"}:
        return None
    path = (parts.path or "/") + (f"#{parts.fragment}" if parts.fragment else "")
    return redact(path)[:LINK_PATH_LIMIT]


def observation_for_classification(
    *,
    page_url: str,
    page_title: str,
    controls: Sequence[Control],
    redact: Redact,
    objective: str = LOGIN_OBJECTIVE,
    used_controls: Sequence[str] = (),
) -> PageObservationForModel:
    """Describe the visible controls for a model, without any field values.

    A link's destination is sent as its path and client-side route only
    (``link_path``), so the model can tell a sign-up link from a help link
    without seeing a query string.
    """

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
                link_path=_link_path(control, redact),
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
        objective=objective,
        controls=model_controls,
        used_controls=list(used_controls),
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
    *,
    roles: Sequence[ControlRole] = LOGIN_ROLES,
    context: RoleContext | None = None,
    used_controls: Sequence[str] = (),
) -> SuggestedControls:
    """Reserve, send and reconcile one classification request, then validate.

    The reservation is written before the request, as for every model
    request, so a crash cannot spend the same budget twice. A request that
    fails without reporting its usage keeps its reservation, because it may
    still have been charged.

    Every role the model answered passes the gate, with ``context`` for the
    roles that lead elsewhere; only the ``roles`` that were asked for are
    kept.
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

    validated = _requested_roles_only(
        validate_role_suggestions(
            controls,
            decision.suggestions,
            context=context,
            used_controls=used_controls,
        ),
        roles,
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
