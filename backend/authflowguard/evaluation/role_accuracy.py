"""Measures how accurately, and at what cost, controls are given their roles.

The truth comes from ``evaluation/cases/control_role_ground_truth.json``,
written from the fixtures' source and Juice Shop's markup, never from what
AuthFlowGuard answered. It names each control by stable attributes (id,
name, type, label, text), not by its ``control-N`` number, so it survives a
change of layout.

Each page is opened in a real browser, its controls are read the way a scan
reads them, and the classifier is asked for the page's roles several times.
Every answer is scored twice, as the model gave it and after the validation
gate, so the report shows how often the gate catches a mistake. The login
roles it accepts are then replayed through the guided verified-login flow,
which proves whether they sign in.

``--discovery-mode bedrock`` uses the offline deterministic double unless
``--confirm-live-calls`` is given, and a live run also needs
``--max-evaluation-cost-usd``. Every request is reserved in the run's cost
ledger before it is sent, and the run stops before a reservation would pass
the cap. ``--discovery-mode rules`` scores the rules alone, for comparison.
"""

import asyncio
import json
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page, async_playwright

from authflowguard.authentication import execute_guided_verified_login_flow
from authflowguard.bedrock import (
    BedrockActionClient,
    BedrockClassificationDecision,
    BedrockConfiguration,
    PageObservationForModel,
)
from authflowguard.config import (
    BedrockServerSettings,
    load_server_settings,
    validate_bedrock_configuration,
)
from authflowguard.control_roles import (
    ControlRole,
    RoleContext,
    RoleSuggestion,
    rules_account_menu_suggestions,
    rules_link_suggestions,
    rules_logout_suggestions,
    rules_role_suggestions,
)
from authflowguard.evaluation.case_runner import (
    TargetUnavailableError,
    ensure_reachable,
    external_origin,
    fixture_for,
    serve,
)
from authflowguard.evaluation.cost_model import USD_PLACES
from authflowguard.evaluation.cost_tracking import (
    CostLedger,
    CostLedgerStore,
    UsageSource,
    format_usd,
    report_to_dict,
)
from authflowguard.evaluation.model_double import DeterministicModelDouble
from authflowguard.evaluation.tables import markdown_table
from authflowguard.login_suggestions import (
    ClassificationBudget,
    ControlClassificationClient,
    SuggestionStatus,
    classification_objective,
    classify_within_budget,
    observation_for_classification,
)
from authflowguard.models import BrowserAction, BrowserActionType, TargetScope
from authflowguard.playwright_worker import PlaywrightWorker
from authflowguard.scope import url_without_query_keeping_route
from authflowguard.secrets import RuntimeSecrets

DEFAULT_REPETITIONS = 3
DEFAULT_GROUND_TRUTH = Path("evaluation/cases/control_role_ground_truth.json")
STEP_TIMEOUT_MS = 10_000
OPTIONAL_STEP_TIMEOUT_MS = 2_000
SETTLE_TIMEOUT_MS = 5_000

Control = Mapping[str, object]

# Keys a matcher may compare, as the page observation names them.
MATCHER_ATTRIBUTES = frozenset(
    {"tag", "id", "name", "type", "text", "aria_label", "role", "autocomplete"}
    | {"placeholder"}
)
STEP_KINDS = ("goto", "fill", "click", "click_if_present", "wait_for", "wait_for_url")
# The credential each login role is filled with, by its key in the truth.
FILLED_ROLES = (
    (ControlRole.USERNAME, "known"),
    (ControlRole.PASSWORD, "password"),
    (ControlRole.VERIFICATION_CODE, "second_factor"),
)


class GroundTruthError(ValueError):
    """The ground-truth file does not describe the pages consistently."""


class LiveCallsNotConfirmedError(RuntimeError):
    """A live Bedrock run was asked for without explicit confirmation."""


# --- Ground truth -----------------------------------------------------------


def _normalise(text: str) -> str:
    return " ".join(text.split()).casefold()


@dataclass(frozen=True)
class ControlMatcher:
    """Stable attributes that identify one control, whatever its position."""

    attributes: tuple[tuple[str, str], ...]
    href_endswith: str | None = None

    @classmethod
    def parse(cls, raw: object) -> "ControlMatcher":
        if not isinstance(raw, Mapping) or not raw:
            raise GroundTruthError("A matcher must be a non-empty object")
        unknown = set(raw) - MATCHER_ATTRIBUTES - {"href_endswith"}
        if unknown:
            raise GroundTruthError(f"Unknown matcher keys: {sorted(unknown)}")
        href = raw.get("href_endswith")
        return cls(
            attributes=tuple(
                sorted(
                    (str(key), str(value))
                    for key, value in raw.items()
                    if key != "href_endswith"
                )
            ),
            href_endswith=str(href) if href is not None else None,
        )

    def matches(self, control: Control) -> bool:
        for key, expected in self.attributes:
            actual = control.get(key)
            if not isinstance(actual, str):
                return False
            if key == "text":
                if _normalise(actual) != _normalise(expected):
                    return False
            elif actual != expected:
                return False
        if self.href_endswith is not None:
            href = control.get("href")
            if not isinstance(href, str) or not href.endswith(self.href_endswith):
                return False
        return True

    def describe(self) -> str:
        parts = [f"{key}={value!r}" for key, value in self.attributes]
        if self.href_endswith is not None:
            parts.append(f"href ends {self.href_endswith!r}")
        return ", ".join(parts)


@dataclass(frozen=True)
class SetupStep:
    """One browser step that brings a page into the state being measured."""

    kind: str
    target: str
    value: str | None = None

    @classmethod
    def parse(cls, raw: object) -> "SetupStep":
        if not isinstance(raw, Mapping):
            raise GroundTruthError("A step must be an object")
        kinds = [kind for kind in STEP_KINDS if kind in raw]
        if len(kinds) != 1:
            raise GroundTruthError(f"A step needs exactly one of {STEP_KINDS}")
        kind = kinds[0]
        value = raw.get("value")
        if kind == "fill" and not isinstance(value, str):
            raise GroundTruthError("A fill step names the credential in 'value'")
        return cls(kind, str(raw[kind]), value if isinstance(value, str) else None)


@dataclass(frozen=True)
class PageTruth:
    """Which control plays each requested role on one page.

    A role mapped to no matchers has no control on the page.
    """

    page_id: str
    path: str
    requires_sign_in: bool
    steps: tuple[SetupStep, ...]
    requested_roles: tuple[ControlRole, ...]
    roles: Mapping[ControlRole, tuple[ControlMatcher, ...]]
    derivation: str = ""


@dataclass(frozen=True)
class ApplicationTruth:
    application: str
    name: str
    verified: bool
    credentials: Mapping[str, str]
    password_references: frozenset[str]
    protected_resource_path: str
    marker_selector: str
    sign_in: tuple[SetupStep, ...]
    login_sequence: tuple[str, ...]
    pages: tuple[PageTruth, ...]

    def page(self, page_id: str) -> PageTruth:
        for page in self.pages:
            if page.page_id == page_id:
                return page
        raise KeyError(page_id)


def _parse_role(value: object) -> ControlRole:
    try:
        role = ControlRole(str(value))
    except ValueError as error:
        raise GroundTruthError(f"Unknown role {value!r}") from error
    if role is ControlRole.OTHER:
        raise GroundTruthError("'other' is not a measured role")
    return role


def _parse_page(raw: Mapping[str, Any]) -> PageTruth:
    page_id = str(raw["page_id"])
    requested = tuple(_parse_role(role) for role in raw["requested_roles"])
    roles: dict[ControlRole, tuple[ControlMatcher, ...]] = {}
    for key, matchers in dict(raw["roles"]).items():
        role = _parse_role(key)
        if matchers is None:
            roles[role] = ()
        elif isinstance(matchers, list):
            roles[role] = tuple(ControlMatcher.parse(m) for m in matchers)
        else:
            roles[role] = (ControlMatcher.parse(matchers),)
    if set(roles) != set(requested):
        raise GroundTruthError(
            f"{page_id}: every requested role, and only those, needs a truth "
            "entry (null when the page has no such control)"
        )
    return PageTruth(
        page_id=page_id,
        path=str(raw["path"]),
        requires_sign_in=bool(raw.get("requires_sign_in", False)),
        steps=tuple(SetupStep.parse(step) for step in raw.get("steps", [])),
        requested_roles=requested,
        roles=roles,
        derivation=str(raw.get("derivation", "")),
    )


def load_ground_truth(path: Path) -> dict[str, ApplicationTruth]:
    """Read and check the ground-truth file."""

    document = json.loads(path.read_text(encoding="utf-8"))
    applications: dict[str, ApplicationTruth] = {}
    for application, raw in dict(document["applications"]).items():
        pages = tuple(_parse_page(page) for page in raw["pages"])
        page_ids = [page.page_id for page in pages]
        if len(set(page_ids)) != len(page_ids):
            raise GroundTruthError(f"{application}: duplicate page ids")
        login_sequence = tuple(str(page) for page in raw.get("login_sequence", []))
        if not set(login_sequence) <= set(page_ids):
            raise GroundTruthError(f"{application}: unknown page in login_sequence")
        applications[application] = ApplicationTruth(
            application=application,
            name=str(raw.get("name", application)),
            verified=bool(raw.get("verified", False)),
            credentials={str(k): str(v) for k, v in raw["credentials"].items()},
            password_references=frozenset(raw.get("password_references", [])),
            protected_resource_path=str(raw["protected_resource_path"]),
            marker_selector=str(raw["marker_selector"]),
            sign_in=tuple(SetupStep.parse(step) for step in raw.get("sign_in", [])),
            login_sequence=login_sequence,
            pages=pages,
        )
    return applications


def resolve_truth(
    page: PageTruth, controls: Sequence[Control]
) -> tuple[dict[ControlRole, str | None], dict[ControlRole, str]]:
    """Find each role's true control among the observed ones.

    Returns the control id per role (None when the page has none), and, for
    a role whose matchers do not pick exactly one control, why it cannot be
    scored.
    """

    expected: dict[ControlRole, str | None] = {}
    unresolved: dict[ControlRole, str] = {}
    for role in page.requested_roles:
        matchers = page.roles[role]
        if not matchers:
            expected[role] = None
            continue
        found = sorted(
            {
                control_id
                for control in controls
                if any(matcher.matches(control) for matcher in matchers)
                and isinstance(control_id := control.get("observed_control_id"), str)
            }
        )
        if len(found) == 1:
            expected[role] = found[0]
        else:
            described = " or ".join(matcher.describe() for matcher in matchers)
            unresolved[role] = f"{len(found)} controls match {described}"
    return expected, unresolved


# --- Scoring ----------------------------------------------------------------


class Outcome(StrEnum):
    CORRECT = "correct"
    WRONG = "wrong_control"
    MISSED = "missed"
    EXTRA = "extra"
    ABSENT = "correctly_absent"


OUTCOME_ORDER = (
    Outcome.CORRECT,
    Outcome.WRONG,
    Outcome.MISSED,
    Outcome.EXTRA,
    Outcome.ABSENT,
)


def score_role(expected: str | None, answered: Collection[str]) -> Outcome:
    """Score one role's answer against the true control.

    Naming the true control together with another is a wrong answer: the
    flow could not tell which to use.
    """

    chosen = set(answered)
    if expected is None:
        return Outcome.EXTRA if chosen else Outcome.ABSENT
    if not chosen:
        return Outcome.MISSED
    return Outcome.CORRECT if chosen == {expected} else Outcome.WRONG


def is_right(outcome: Outcome) -> bool:
    return outcome in (Outcome.CORRECT, Outcome.ABSENT)


@dataclass
class ClassificationRecord:
    """One classification of one page, scored before and after the gate."""

    application: str
    page_id: str
    repetition: int
    status: str
    raw: dict[ControlRole, tuple[str, ...]]
    gated: dict[ControlRole, str | None]
    rejected: list[dict[str, str]]
    raw_outcomes: dict[ControlRole, Outcome]
    gated_outcomes: dict[ControlRole, Outcome]
    unrequested_answers: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: Decimal = Decimal("0")
    reserved_usd: Decimal = Decimal("0")

    def as_dict(self) -> dict[str, Any]:
        return {
            "application": self.application,
            "page_id": self.page_id,
            "repetition": self.repetition,
            "status": self.status,
            "raw": {role.value: list(ids) for role, ids in self.raw.items()},
            "gated": {role.value: value for role, value in self.gated.items()},
            "rejected": self.rejected,
            "raw_outcomes": {r.value: o.value for r, o in self.raw_outcomes.items()},
            "gated_outcomes": {
                r.value: o.value for r, o in self.gated_outcomes.items()
            },
            "unrequested_answers": self.unrequested_answers,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": str(self.cost_usd),
            "reserved_usd": str(self.reserved_usd),
        }


def summarise_accuracy(records: Sequence[ClassificationRecord]) -> dict[str, Any]:
    """Count outcomes per role and overall, before and after the gate."""

    def tally(stage: str) -> dict[str, Any]:
        per_role: dict[str, Counter[str]] = {}
        overall: Counter[str] = Counter()
        for record in records:
            outcomes = record.raw_outcomes if stage == "raw" else record.gated_outcomes
            for role, outcome in outcomes.items():
                per_role.setdefault(role.value, Counter())[outcome.value] += 1
                overall[outcome.value] += 1
        return {
            "per_role": {
                role: _with_accuracy(counts)
                for role, counts in sorted(per_role.items())
            },
            "overall": _with_accuracy(overall),
        }

    return {"raw": tally("raw"), "gated": tally("gated")}


def _with_accuracy(counts: Counter[str]) -> dict[str, Any]:
    scored = sum(counts.values())
    right = counts[Outcome.CORRECT.value] + counts[Outcome.ABSENT.value]
    result: dict[str, Any] = {o.value: counts[o.value] for o in OUTCOME_ORDER}
    result["scored"] = scored
    result["accuracy"] = round(right / scored, 4) if scored else None
    return result


def summarise_gate(records: Sequence[ClassificationRecord]) -> dict[str, Any]:
    """How the gate changed each answer.

    ``caught``: a wrong or extra raw answer the gate removed. ``let_through``:
    a wrong or extra answer that survived it. ``dropped_correct``: a correct
    raw answer the gate removed.
    """

    per_role: dict[str, Counter[str]] = {}
    for record in records:
        for role, raw in record.raw_outcomes.items():
            gated = record.gated_outcomes[role]
            counts = per_role.setdefault(role.value, Counter())
            if raw in (Outcome.WRONG, Outcome.EXTRA):
                if gated in (Outcome.MISSED, Outcome.ABSENT):
                    counts["caught"] += 1
                elif gated is Outcome.CORRECT:
                    # Several raw controls, one of them right, narrowed to it.
                    counts["corrected"] += 1
                else:
                    counts["let_through"] += 1
            elif raw is Outcome.CORRECT and gated is not Outcome.CORRECT:
                counts["dropped_correct"] += 1
    keys = ("caught", "corrected", "let_through", "dropped_correct")
    totals = Counter[str]()
    for counts in per_role.values():
        totals.update(counts)
    return {
        "per_role": {
            role: {key: counts[key] for key in keys}
            for role, counts in sorted(per_role.items())
        },
        "overall": {key: totals[key] for key in keys},
    }


def summarise_consistency(records: Sequence[ClassificationRecord]) -> dict[str, Any]:
    """Whether repeated classifications of a page gave the same answer."""

    by_page: dict[str, list[ClassificationRecord]] = {}
    for record in records:
        by_page.setdefault(record.page_id, []).append(record)
    per_role: dict[str, Counter[str]] = {}
    pages: dict[str, dict[str, Any]] = {}
    for page_id, page_records in sorted(by_page.items()):
        if len(page_records) < 2:
            continue
        roles = page_records[0].raw_outcomes.keys()
        page_entry: dict[str, Any] = {}
        for role in roles:
            raw_answers = {tuple(sorted(r.raw.get(role, ()))) for r in page_records}
            gated_answers = {r.gated.get(role) for r in page_records}
            counts = per_role.setdefault(role.value, Counter())
            counts["pages"] += 1
            counts["raw_consistent"] += len(raw_answers) == 1
            counts["gated_consistent"] += len(gated_answers) == 1
            page_entry[role.value] = {
                "repetitions": len(page_records),
                "distinct_raw_answers": len(raw_answers),
                "distinct_accepted_answers": len(gated_answers),
            }
        pages[page_id] = page_entry
    return {
        "per_role": {role: dict(counts) for role, counts in sorted(per_role.items())},
        "pages": pages,
    }


# --- Classifiers ------------------------------------------------------------


class RecordingClassifier:
    """Passes requests through and keeps the last raw model answer."""

    def __init__(self, inner: ControlClassificationClient) -> None:
        self.inner = inner
        self.last: BedrockClassificationDecision | None = None

    def estimate_classification_cost(
        self, observation: PageObservationForModel
    ) -> float:
        return self.inner.estimate_classification_cost(observation)

    def classify_controls(
        self, observation: PageObservationForModel
    ) -> BedrockClassificationDecision:
        self.last = None
        decision = self.inner.classify_controls(observation)
        self.last = decision
        return decision


class RulesClassifier:
    """The rules, asked the way a model is, as a free baseline."""

    def __init__(self) -> None:
        self.controls: Sequence[Control] = ()
        self.roles: tuple[ControlRole, ...] = ()

    def estimate_classification_cost(
        self, observation: PageObservationForModel
    ) -> float:
        return 0.0

    def classify_controls(
        self, observation: PageObservationForModel
    ) -> BedrockClassificationDecision:
        suggestions: list[RoleSuggestion] = [
            *rules_role_suggestions(self.controls),
            *rules_link_suggestions(self.controls),
            *rules_logout_suggestions(self.controls),
            *rules_account_menu_suggestions(self.controls),
        ]
        return BedrockClassificationDecision(
            suggestions=tuple(s for s in suggestions if s.role in self.roles),
            discarded_count=0,
            input_tokens=0,
            output_tokens=0,
            actual_cost_usd=0.0,
            reserved_cost_usd=0.0,
        )


class _OfflineRuntime:
    """Stands in for AWS when a request is only priced, never sent."""

    def converse(self, **request: Any) -> dict[str, Any]:
        raise RuntimeError("Only the request's cost is estimated; nothing is sent")


def build_classifier(
    discovery_mode: str,
    confirm_live_calls: bool,
    settings: BedrockServerSettings,
) -> tuple[ControlClassificationClient, UsageSource]:
    """The classifier to measure, and where its usage figures come from.

    Bedrock is only contacted when live calls are confirmed; otherwise the
    offline double answers and its usage is labelled mock.
    """

    if discovery_mode == "rules":
        return RulesClassifier(), UsageSource.NONE
    if not confirm_live_calls:
        return DeterministicModelDouble(), UsageSource.MOCK
    return live_classifier(settings, confirm_live_calls), UsageSource.LIVE


def live_classifier(
    settings: BedrockServerSettings, confirm_live_calls: bool
) -> BedrockActionClient:
    """Build the real Bedrock client, only when live calls are confirmed."""

    if not confirm_live_calls:
        raise LiveCallsNotConfirmedError("Live Bedrock calls need --confirm-live-calls")
    is_valid, reason = validate_bedrock_configuration(settings)
    if not is_valid:
        raise LiveCallsNotConfirmedError(f"Bedrock is not configured: {reason}")
    return BedrockActionClient(_bedrock_configuration(settings))


def _bedrock_configuration(settings: BedrockServerSettings) -> BedrockConfiguration:
    return BedrockConfiguration(
        aws_profile=settings.aws_profile,
        aws_region=settings.aws_region,
        model_id=settings.model_id,
        max_output_tokens=settings.max_output_tokens,
        maximum_estimated_cost_usd=settings.maximum_estimated_cost_usd,
    )


def live_reservation_usd(
    observation: PageObservationForModel, settings: BedrockServerSettings
) -> Decimal:
    """What one live classification of this page would reserve.

    The production estimate counts every request character as a token, so
    this is an upper bound on the real charge.
    """

    client = BedrockActionClient(
        _bedrock_configuration(settings), runtime_client=_OfflineRuntime()
    )
    return Decimal(str(client.estimate_classification_cost(observation))).quantize(
        USD_PLACES
    )


# --- Observing pages --------------------------------------------------------


@dataclass
class ObservedPage:
    page_id: str
    url: str
    title: str
    controls: list[dict[str, Any]]
    error: str | None = None


async def _run_steps(
    page: Page,
    steps: Iterable[SetupStep],
    origin: str,
    credentials: Mapping[str, str],
) -> None:
    for step in steps:
        if step.kind == "goto":
            await page.goto(origin + step.target, wait_until="domcontentloaded")
        elif step.kind == "fill":
            await page.fill(
                step.target, credentials[step.value or ""], timeout=STEP_TIMEOUT_MS
            )
        elif step.kind == "click":
            await page.click(step.target, timeout=STEP_TIMEOUT_MS)
        elif step.kind == "click_if_present":
            try:
                await page.click(step.target, timeout=OPTIONAL_STEP_TIMEOUT_MS)
            except PlaywrightError:
                pass
        elif step.kind == "wait_for":
            await page.wait_for_selector(
                step.target, state="visible", timeout=STEP_TIMEOUT_MS
            )
        elif step.kind == "wait_for_url":
            await page.wait_for_url(step.target, timeout=STEP_TIMEOUT_MS)


async def observe_application(
    application: ApplicationTruth, origin: str
) -> dict[str, ObservedPage]:
    """Open each page in a fresh context and read its controls."""

    secrets = RuntimeSecrets(dict(application.credentials))
    observed: dict[str, ObservedPage] = {}
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            for truth in application.pages:
                context = await browser.new_context()
                try:
                    page = await context.new_page()
                    steps = (
                        *(application.sign_in if truth.requires_sign_in else ()),
                        SetupStep("goto", truth.path),
                        *truth.steps,
                    )
                    await _run_steps(page, steps, origin, application.credentials)
                    try:
                        await page.wait_for_load_state(
                            "networkidle", timeout=SETTLE_TIMEOUT_MS
                        )
                    except PlaywrightError:
                        pass
                    controls = await PlaywrightWorker().read_controls(page)
                    observed[truth.page_id] = ObservedPage(
                        page_id=truth.page_id,
                        url=url_without_query_keeping_route(page.url),
                        title=await page.title(),
                        controls=[dict(control) for control in controls],
                    )
                except (PlaywrightError, KeyError) as error:
                    first_line = (str(error).splitlines() or [""])[0]
                    observed[truth.page_id] = ObservedPage(
                        page_id=truth.page_id,
                        url=origin + truth.path,
                        title="",
                        controls=[],
                        error=secrets.redact_text(
                            f"{type(error).__name__}: {first_line}"
                        )[:200],
                    )
                finally:
                    await context.close()
        finally:
            await browser.close()
    return observed


# --- Classifying ------------------------------------------------------------


@dataclass
class PageRun:
    """What one page's observation and classifications produced."""

    application: str
    page_id: str
    url: str
    control_count: int
    visible_control_count: int
    expected: dict[ControlRole, str | None] = field(default_factory=dict)
    unresolved: dict[ControlRole, str] = field(default_factory=dict)
    live_reservation_usd: Decimal | None = None
    error: str | None = None
    verified_truth: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "application": self.application,
            "page_id": self.page_id,
            "url": self.url,
            "control_count": self.control_count,
            "visible_control_count": self.visible_control_count,
            "expected": {role.value: cid for role, cid in self.expected.items()},
            "unresolved_truth": {r.value: why for r, why in self.unresolved.items()},
            "live_reservation_usd": (
                str(self.live_reservation_usd)
                if self.live_reservation_usd is not None
                else None
            ),
            "error": self.error,
            "verified_truth": self.verified_truth,
        }


def _new_entries_cost(ledger: CostLedger, since: int) -> tuple[Decimal, Decimal]:
    """The observed and reserved cost of entries recorded after ``since``."""

    cost = Decimal("0")
    reserved = Decimal("0")
    for entry in ledger.entries[since:]:
        if entry.is_reservation:
            reserved += entry.reserved_cost_usd or Decimal("0")
        else:
            cost += ledger.entry_cost_usd(entry)
    return cost, reserved


def classify_page(
    *,
    application: str,
    truth: PageTruth,
    observed: ObservedPage,
    expected: Mapping[ControlRole, str | None],
    origin: str,
    classifier: RecordingClassifier,
    budget: ClassificationBudget,
    repetition: int,
    redact: Callable[[str], str] = str,
) -> ClassificationRecord | None:
    """Classify one page once and score it; None when the cost cap is reached.

    Only roles whose truth resolved are scored.
    """

    roles = truth.requested_roles
    observation = observation_for_classification(
        page_url=observed.url,
        page_title=observed.title,
        controls=observed.controls,
        redact=redact,
        objective=classification_objective(roles),
    )
    if isinstance(classifier.inner, RulesClassifier):
        classifier.inner.controls = observed.controls
        classifier.inner.roles = roles
    context = RoleContext(
        TargetScope.model_validate(
            {"target_url": origin + truth.path, "permitted_origins": [origin]}
        ),
        observed.url,
    )
    before = len(budget.ledger)
    classifier.last = None
    suggested = classify_within_budget(
        classifier, observation, observed.controls, budget, roles=roles, context=context
    )
    decision = classifier.last
    if (
        suggested.status is SuggestionStatus.AI_COST_LIMIT_REACHED
        and decision is None
        and float(budget.ledger.total_budget_committed_usd())
        + classifier.estimate_classification_cost(observation)
        > budget.limit_usd
    ):
        return None

    raw: dict[ControlRole, tuple[str, ...]] = {}
    unrequested = 0
    answered: tuple[RoleSuggestion, ...] = (
        decision.suggestions if decision is not None else ()
    )
    for suggestion in answered:
        if suggestion.role in roles:
            raw[suggestion.role] = (
                *raw.get(suggestion.role, ()),
                suggestion.observed_control_id,
            )
        elif suggestion.role is not ControlRole.OTHER:
            unrequested += 1
    gated = {role: suggested.roles.control_for(role) for role in roles}
    scored = [role for role in roles if role in expected]
    cost, reserved = _new_entries_cost(budget.ledger, before)
    return ClassificationRecord(
        application=application,
        page_id=truth.page_id,
        repetition=repetition,
        status=suggested.status.value,
        raw={role: tuple(sorted(set(raw.get(role, ())))) for role in roles},
        gated=gated,
        rejected=[rejection.as_dict() for rejection in suggested.roles.rejected],
        raw_outcomes={
            role: score_role(expected[role], raw.get(role, ())) for role in scored
        },
        gated_outcomes={
            role: score_role(
                expected[role],
                () if gated[role] is None else (str(gated[role]),),
            )
            for role in scored
        },
        unrequested_answers=unrequested,
        input_tokens=suggested.input_tokens,
        output_tokens=suggested.output_tokens,
        cost_usd=cost,
        reserved_usd=reserved,
    )


# --- Verified login ---------------------------------------------------------


@dataclass
class LoginAttempt:
    application: str
    repetition: int
    attempted: bool
    verified: bool
    detail: str
    reused: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "application": self.application,
            "repetition": self.repetition,
            "attempted": self.attempted,
            "verified": self.verified,
            "detail": self.detail,
            "reused_identical_flow": self.reused,
        }


def login_actions(
    application: ApplicationTruth,
    origin: str,
    records: Mapping[str, ClassificationRecord],
) -> list[BrowserAction] | str:
    """Turn the accepted login roles into a guided flow, or say what is missing.

    Each page in the login sequence must have an accepted control for every
    login role its truth names; roles accepted beyond those are not used.
    """

    first = application.page(application.login_sequence[0])
    actions = [
        BrowserAction(
            action_type=BrowserActionType.NAVIGATE,
            url=origin + first.path,
            description="Open the login page",
        )
    ]
    for page_id in application.login_sequence:
        truth = application.page(page_id)
        record = records.get(page_id)
        if record is None:
            return f"{page_id} was not classified"
        for role, reference in FILLED_ROLES:
            if not truth.roles.get(role):
                continue
            control_id = record.gated.get(role)
            if control_id is None:
                return f"{page_id}: no accepted {role.value}"
            actions.append(
                BrowserAction(
                    action_type=BrowserActionType.FILL,
                    observed_control_id=control_id,
                    value_reference=reference,
                    description=f"Fill the {role.value}",
                )
            )
        if truth.roles.get(ControlRole.SUBMIT):
            submit = record.gated.get(ControlRole.SUBMIT)
            if submit is None:
                return f"{page_id}: no accepted submit"
            actions.append(
                BrowserAction(
                    action_type=BrowserActionType.CLICK,
                    observed_control_id=submit,
                    description="Submit",
                )
            )
    return actions


def verify_login(
    application: ApplicationTruth, origin: str, actions: list[BrowserAction]
) -> tuple[bool, str]:
    """Replay the flow through the guided verified-login path."""

    secrets = RuntimeSecrets(dict(application.credentials))
    first = application.page(application.login_sequence[0])
    target = TargetScope.model_validate(
        {"target_url": origin + first.path, "permitted_origins": [origin]}
    )
    try:
        asyncio.run(
            execute_guided_verified_login_flow(
                scan_id=uuid4(),
                target=target,
                runtime_secrets=secrets,
                actions=actions,
                password_references=application.password_references,
                protected_resource=origin + application.protected_resource_path,
                account_marker_selector=application.marker_selector,
                account_marker_description="Authenticated account marker",
            )
        )
    except Exception as error:  # noqa: BLE001 - the outcome being measured
        first_line = (str(error).splitlines() or [""])[0]
        return False, secrets.redact_text(f"{type(error).__name__}: {first_line}")[:200]
    return True, "Verified login"


# --- The run ----------------------------------------------------------------


@dataclass(frozen=True)
class RunOptions:
    run_id: str
    applications: tuple[str, ...]
    repetitions: int = DEFAULT_REPETITIONS
    discovery_mode: str = "bedrock"
    live: bool = False
    max_cost_usd: float = 1.0
    fixture_mode: str = "secure"
    verify_login: bool = True


@dataclass
class RunResult:
    options: RunOptions
    usage_source: UsageSource
    model_id: str
    ledger: CostLedger
    pages: list[PageRun] = field(default_factory=list)
    records: list[ClassificationRecord] = field(default_factory=list)
    logins: list[LoginAttempt] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    stopped_by_cost_cap: bool = False

    @property
    def source_label(self) -> str:
        if self.options.discovery_mode == "rules":
            return "rules"
        return "live_bedrock" if self.usage_source is UsageSource.LIVE else "double"

    def cost_summary(self) -> dict[str, Any]:
        per_page: dict[str, dict[str, Any]] = {}
        for record in self.records:
            entry = per_page.setdefault(
                record.page_id,
                {
                    "classifications": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_usd": Decimal("0"),
                },
            )
            entry["classifications"] += 1
            entry["input_tokens"] += record.input_tokens
            entry["output_tokens"] += record.output_tokens
            entry["cost_usd"] += record.cost_usd
        total = sum((r.cost_usd for r in self.records), Decimal("0"))
        count = len(self.records)
        reservations = [
            page.live_reservation_usd
            for page in self.pages
            if page.live_reservation_usd is not None
        ]
        upper_bound = sum(reservations, Decimal("0")) * self.options.repetitions
        return {
            "usage_source": self.usage_source.value,
            "model_id": self.model_id,
            "classifications": count,
            "input_tokens": sum(r.input_tokens for r in self.records),
            "output_tokens": sum(r.output_tokens for r in self.records),
            "total_cost_usd": total,
            "cost_per_classification_usd": (
                (total / count).quantize(USD_PLACES) if count else None
            ),
            "cost_per_page_usd": (
                (total / len(per_page)).quantize(USD_PLACES) if per_page else None
            ),
            "per_page": per_page,
            "cap_usd": self.options.max_cost_usd,
            "committed_usd": self.ledger.total_budget_committed_usd(),
            "live_upper_bound_for_this_run_usd": upper_bound,
            "live_upper_bound_note": (
                "Sum over measured pages of the production reservation for one "
                "classification (every request character counted as a token), "
                "times the repetitions. Real charges are lower."
            ),
        }

    def summary(self) -> dict[str, Any]:
        by_application: dict[str, dict[str, int]] = {}
        for attempt in self.logins:
            counts = by_application.setdefault(
                attempt.application, {"repetitions": 0, "attempted": 0, "verified": 0}
            )
            counts["repetitions"] += 1
            counts["attempted"] += attempt.attempted
            counts["verified"] += attempt.verified
        return {
            "accuracy": summarise_accuracy(self.records),
            "gate": summarise_gate(self.records),
            "consistency": summarise_consistency(self.records),
            "verified_login": by_application,
        }

    def as_dict(self) -> dict[str, Any]:
        report = report_to_dict(self.ledger.build_report()) if len(self.ledger) else {}
        document: dict[str, Any] = _jsonable(
            {
                "run_id": self.options.run_id,
                "generated_at": datetime.now(UTC).isoformat(),
                "source": self.source_label,
                "discovery_mode": self.options.discovery_mode,
                "usage_source": self.usage_source.value,
                "model_id": self.model_id,
                "repetitions": self.options.repetitions,
                "fixture_mode": self.options.fixture_mode,
                "applications": list(self.options.applications),
                "stopped_by_cost_cap": self.stopped_by_cost_cap,
                "skipped": self.skipped,
                "pages": [page.as_dict() for page in self.pages],
                "classifications": [record.as_dict() for record in self.records],
                "verified_logins": [attempt.as_dict() for attempt in self.logins],
                "summary": self.summary(),
                "cost": self.cost_summary(),
                "cost_ledger_report": report,
            }
        )
        return document


def _jsonable(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(item) for item in value]
    return value


def run_evaluation(
    truth: Mapping[str, ApplicationTruth],
    options: RunOptions,
    run_directory: Path,
    *,
    client: ControlClassificationClient | None = None,
    usage_source: UsageSource | None = None,
    settings: BedrockServerSettings | None = None,
) -> RunResult:
    """Observe, classify and score every page of the chosen applications."""

    settings = settings or load_server_settings()
    if client is None:
        client, usage_source = build_classifier(
            options.discovery_mode, options.live, settings
        )
    source = usage_source or UsageSource.MOCK
    ledger_store = (
        CostLedgerStore(run_directory / "cost-ledger.ndjson")
        if source is not UsageSource.NONE
        else None
    )
    ledger = ledger_store.load_into() if ledger_store is not None else CostLedger()
    budget = ClassificationBudget(
        scan_id=uuid4(),
        limit_usd=options.max_cost_usd,
        ledger=ledger,
        ledger_store=ledger_store,
        usage_source=source,
        model_id=settings.model_id,
    )
    classifier = RecordingClassifier(client)
    result = RunResult(
        options=options, usage_source=source, model_id=settings.model_id, ledger=ledger
    )

    for application in options.applications:
        app_truth = truth.get(application)
        if app_truth is None:
            result.skipped.append({"application": application, "reason": "no truth"})
            continue
        if result.stopped_by_cost_cap:
            result.skipped.append(
                {"application": application, "reason": "cost cap reached"}
            )
            continue
        origin = external_origin(application)
        if origin is not None:
            try:
                ensure_reachable(application, origin)
            except TargetUnavailableError as error:
                print(f"Skipping application {application}: {error}", flush=True)
                result.skipped.append(
                    {"application": application, "reason": str(error)}
                )
                continue
            _measure_application(
                app_truth, origin, options, classifier, budget, result, settings
            )
        else:
            with serve(fixture_for(application, options.fixture_mode)) as served:
                _measure_application(
                    app_truth, served, options, classifier, budget, result, settings
                )
    return result


def _measure_application(
    app_truth: ApplicationTruth,
    origin: str,
    options: RunOptions,
    classifier: RecordingClassifier,
    budget: ClassificationBudget,
    result: RunResult,
    settings: BedrockServerSettings | None = None,
) -> None:
    settings = settings or load_server_settings()
    application = app_truth.application
    print(f"Application {application} at {origin}: observing pages...", flush=True)
    observed_pages = asyncio.run(observe_application(app_truth, origin))
    redact = RuntimeSecrets(dict(app_truth.credentials)).redact_text
    by_page: dict[int, dict[str, ClassificationRecord]] = {}

    for truth in app_truth.pages:
        observed = observed_pages[truth.page_id]
        page_run = PageRun(
            application=application,
            page_id=truth.page_id,
            url=observed.url,
            control_count=len(observed.controls),
            visible_control_count=sum(
                1 for c in observed.controls if c.get("visible") is True
            ),
            error=observed.error,
            verified_truth=app_truth.verified,
        )
        result.pages.append(page_run)
        if observed.error is not None:
            print(f"  {truth.page_id}: not observed ({observed.error})", flush=True)
            continue
        page_run.expected, page_run.unresolved = resolve_truth(truth, observed.controls)
        page_run.live_reservation_usd = live_reservation_usd(
            observation_for_classification(
                page_url=observed.url,
                page_title=observed.title,
                controls=observed.controls,
                redact=redact,
                objective=classification_objective(truth.requested_roles),
            ),
            settings,
        )
        for repetition in range(1, options.repetitions + 1):
            if result.stopped_by_cost_cap:
                break
            record = classify_page(
                application=application,
                truth=truth,
                observed=observed,
                expected=page_run.expected,
                origin=origin,
                classifier=classifier,
                budget=budget,
                repetition=repetition,
                redact=redact,
            )
            if record is None:
                result.stopped_by_cost_cap = True
                print("  Cost cap reached: stopping before the next request.")
                break
            result.records.append(record)
            by_page.setdefault(repetition, {})[truth.page_id] = record
            gated = ", ".join(
                f"{role.value}={outcome.value}"
                for role, outcome in record.gated_outcomes.items()
            )
            print(f"  {truth.page_id} #{repetition}: {gated}", flush=True)

    if not options.verify_login or not app_truth.login_sequence:
        return
    verified_flows: dict[tuple[tuple[str, str | None], ...], tuple[bool, str]] = {}
    for repetition in range(1, options.repetitions + 1):
        records = by_page.get(repetition, {})
        if not all(page in records for page in app_truth.login_sequence):
            continue
        actions = login_actions(app_truth, origin, records)
        if isinstance(actions, str):
            result.logins.append(
                LoginAttempt(application, repetition, False, False, actions)
            )
            continue
        key = tuple((a.action_type.value, a.observed_control_id) for a in actions)
        reused = key in verified_flows
        if not reused:
            verified_flows[key] = verify_login(app_truth, origin, actions)
        verified, detail = verified_flows[key]
        result.logins.append(
            LoginAttempt(application, repetition, True, verified, detail, reused)
        )
        print(f"  login #{repetition}: {detail}", flush=True)


# --- Report -----------------------------------------------------------------

SOURCE_BANNERS = {
    "double": (
        "> **Source: the offline deterministic model double, not Amazon "
        "Bedrock.** These numbers measure the double's fixed heuristics and "
        "say nothing about the model's accuracy. Token counts and costs are "
        "mock figures (`usage_source: mock`), not AWS charges."
    ),
    "live_bedrock": (
        "> **Source: live Amazon Bedrock ({model}).** Token counts were "
        "reported by AWS (`usage_source: live`)."
    ),
    "rules": (
        "> **Source: the rule-based suggestions, no model.** A baseline for "
        "the model's numbers; no tokens were used."
    ),
}


def _percent(value: object) -> str:
    return f"{float(value) * 100:.0f}%" if isinstance(value, int | float) else "-"


def render(result: RunResult) -> str:
    summary = result.summary()
    cost = result.cost_summary()
    options = result.options
    lines = [
        "# Control-role classification: accuracy and cost",
        "",
        SOURCE_BANNERS[result.source_label].format(model=result.model_id),
        "",
        f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} for run "
        f"`{options.run_id}`: {options.repetitions} classification(s) per page, "
        f"fixture mode `{options.fixture_mode}`, applications "
        f"{', '.join(options.applications)}.",
        "",
        "Each answer is scored against "
        "`evaluation/cases/control_role_ground_truth.json`: *correct* names the "
        "true control, *wrong control* names another (or several), *missed* "
        "names none where one exists, *extra* names one where the page has "
        "none, and *correctly absent* names none where there is none. Accuracy "
        "counts correct and correctly absent.",
        "",
    ]
    if result.stopped_by_cost_cap:
        lines += [
            f"**The run stopped at the ${options.max_cost_usd} cost cap;** the "
            "pages after it were not classified.",
            "",
        ]
    headers = ["Role", *(o.value.replace("_", " ") for o in OUTCOME_ORDER)]
    headers += ["Scored", "Accuracy"]
    for stage, title in (
        ("gated", "Accuracy after the validation gate (what a scan uses)"),
        ("raw", "Raw answers, before the gate"),
    ):
        tally = summary["accuracy"][stage]
        rows = [
            [role, *(c[o.value] for o in OUTCOME_ORDER), c["scored"]]
            + [_percent(c["accuracy"])]
            for role, c in tally["per_role"].items()
        ]
        overall = tally["overall"]
        rows.append(
            ["**all**", *(overall[o.value] for o in OUTCOME_ORDER), overall["scored"]]
            + [_percent(overall["accuracy"])]
        )
        lines += [f"## {title}", "", markdown_table(headers, rows), ""]

    gate = summary["gate"]
    lines += [
        "## What the gate changed",
        "",
        "*Caught*: a wrong or extra raw answer the gate removed. *Let through*: "
        "one it kept. *Dropped correct*: a correct raw answer it removed.",
        "",
        markdown_table(
            ["Role", "Caught", "Corrected", "Let through", "Dropped correct"],
            [
                [role, c["caught"], c["corrected"], c["let_through"]]
                + [c["dropped_correct"]]
                for role, c in [*gate["per_role"].items(), ("**all**", gate["overall"])]
            ],
        ),
        "",
        "## Consistency across repetitions",
        "",
    ]
    consistency = summary["consistency"]["per_role"]
    if consistency:
        lines.append(
            markdown_table(
                ["Role", "Pages", "Identical raw answers", "Identical accepted"],
                [
                    [role, c["pages"], c["raw_consistent"], c["gated_consistent"]]
                    for role, c in consistency.items()
                ],
            )
        )
    else:
        lines.append("Only one repetition per page: consistency not measured.")
    lines += ["", "## Verified login from the accepted suggestions", ""]
    if result.logins:
        lines.append(
            markdown_table(
                ["Application", "Repetition", "Attempted", "Verified", "Detail"],
                [
                    [a.application, a.repetition, "yes" if a.attempted else "no"]
                    + ["yes" if a.verified else "no"]
                    + [a.detail + (" (same flow as before)" if a.reused else "")]
                    for a in result.logins
                ],
            )
        )
        lines.append("")
        lines.append(
            markdown_table(
                ["Application", "Repetitions", "Attempted", "Verified"],
                [
                    [app, c["repetitions"], c["attempted"], c["verified"]]
                    for app, c in sorted(summary["verified_login"].items())
                ],
            )
        )
    else:
        lines.append("No login was replayed.")
    lines += ["", "## Cost", ""]
    if result.source_label == "rules":
        lines.append("The rules make no model requests.")
    else:
        lines += [
            f"Usage source: **{cost['usage_source']}**, model `{cost['model_id']}`.",
            "",
            markdown_table(
                ["Page", "Classifications", "Input tokens", "Output tokens"]
                + ["Cost (USD)"],
                [
                    [page, c["classifications"], c["input_tokens"]]
                    + [c["output_tokens"], format_usd(c["cost_usd"])]
                    for page, c in sorted(cost["per_page"].items())
                ],
            ),
            "",
            f"**Total:** {cost['classifications']} classifications, "
            f"{cost['input_tokens']} input and {cost['output_tokens']} output "
            f"tokens, {format_usd(cost['total_cost_usd'])}; "
            f"{_usd_or_dash(cost['cost_per_classification_usd'])} per "
            f"classification, {_usd_or_dash(cost['cost_per_page_usd'])} per page. "
            f"Cap ${options.max_cost_usd}; committed "
            f"{format_usd(cost['committed_usd'])}.",
        ]
        if len(result.ledger):
            lines += ["", result.ledger.build_report().provenance_note()]
    lines += [
        "",
        f"**Live cost ceiling for this run:** at most "
        f"{format_usd(cost['live_upper_bound_for_this_run_usd'])} on "
        f"`{result.model_id}` ({cost['live_upper_bound_note']})",
        "",
        "## Pages",
        "",
        markdown_table(
            ["Application", "Page", "Controls (visible)", "Truth verified"]
            + ["Unresolved truth / error"],
            [
                [p.application, p.page_id]
                + [f"{p.control_count} ({p.visible_control_count})"]
                + ["yes" if p.verified_truth else "**no — to confirm**"]
                + [
                    p.error
                    or "; ".join(f"{r.value}: {why}" for r, why in p.unresolved.items())
                    or "-"
                ]
                for p in result.pages
            ],
        ),
        "",
    ]
    if result.skipped:
        lines += [
            "## Skipped",
            "",
            markdown_table(
                ["Application", "Reason"],
                [[s["application"], s["reason"]] for s in result.skipped],
            ),
            "",
        ]
    return "\n".join(lines)


def _usd_or_dash(value: Decimal | None) -> str:
    return format_usd(value) if value is not None else "-"


def write_results(result: RunResult, run_directory: Path) -> tuple[Path, Path]:
    run_directory.mkdir(parents=True, exist_ok=True)
    json_path = run_directory / "role-accuracy.json"
    markdown_path = run_directory / "role-accuracy.md"
    json_path.write_text(
        json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render(result), encoding="utf-8")
    return json_path, markdown_path


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH)
    parser.add_argument("--applications", default="A,B,C,J")
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument(
        "--fixture-mode", choices=["secure", "vulnerable"], default="secure"
    )
    parser.add_argument(
        "--run-id", default=datetime.now(UTC).strftime("role-accuracy-%Y%m%d-%H%M%S")
    )
    parser.add_argument("--results-root", type=Path, default=Path("evaluation/results"))
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--discovery-mode",
        choices=["rules", "bedrock"],
        default="bedrock",
        help="Measure the model's classification ('bedrock') or the rules.",
    )
    parser.add_argument(
        "--confirm-live-calls",
        action="store_true",
        default=False,
        help="Allow live Bedrock API calls. Defaults to false (offline double).",
    )
    parser.add_argument(
        "--max-evaluation-cost-usd",
        type=float,
        default=None,
        help="Cost cap for the whole run; required with --confirm-live-calls.",
    )
    parser.add_argument(
        "--no-login-check",
        action="store_true",
        default=False,
        help="Skip replaying the accepted login roles.",
    )
    arguments = parser.parse_args(argv)

    if arguments.repetitions < 1:
        parser.error("--repetitions must be at least 1")
    if arguments.confirm_live_calls and arguments.discovery_mode != "bedrock":
        parser.error("--confirm-live-calls applies only to --discovery-mode bedrock")
    if arguments.confirm_live_calls and arguments.max_evaluation_cost_usd is None:
        parser.error("A live run needs a cost cap: --max-evaluation-cost-usd")
    cap = arguments.max_evaluation_cost_usd
    if cap is not None and cap <= 0:
        parser.error("--max-evaluation-cost-usd must be positive")

    settings = load_server_settings()
    live = arguments.discovery_mode == "bedrock" and arguments.confirm_live_calls
    if cap is None:
        cap = 1.0
    if live:
        cap = min(cap, settings.server_max_cost_usd)
    options = RunOptions(
        run_id=arguments.run_id,
        applications=tuple(
            name.strip() for name in arguments.applications.split(",") if name.strip()
        ),
        repetitions=arguments.repetitions,
        discovery_mode=arguments.discovery_mode,
        live=live,
        max_cost_usd=cap,
        fixture_mode=arguments.fixture_mode,
        verify_login=not arguments.no_login_check,
    )
    try:
        client, usage_source = build_classifier(
            options.discovery_mode, options.live, settings
        )
    except LiveCallsNotConfirmedError as error:
        print(f"Refusing to run: {error}")
        return 2

    truth = load_ground_truth(arguments.ground_truth)
    run_directory = arguments.results_root / arguments.run_id
    result = run_evaluation(
        truth,
        options,
        run_directory,
        client=client,
        usage_source=usage_source,
        settings=settings,
    )
    json_path, markdown_path = write_results(result, run_directory)
    rendered = render(result)
    print()
    print(rendered)
    print(f"Written: {json_path}")
    print(f"Written: {markdown_path}")
    if arguments.out:
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(rendered, encoding="utf-8")
        print(f"Written: {arguments.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
