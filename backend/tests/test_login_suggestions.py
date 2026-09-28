"""Suggested login controls: rules first, then a validated model answer.

No test here reaches AWS. Model answers come from the deterministic double
or from fakes in this file, and the boto3 session is replaced so that a
mistake fails loudly instead of sending a request.
"""

import asyncio
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from uuid import uuid4

import pytest
from authflowguard.app import create_app
from authflowguard.authentication import GuidedPageObservation
from authflowguard.bedrock import (
    BedrockActionDecision,
    BedrockClassificationDecision,
    BedrockResponseError,
    PageObservationForModel,
)
from authflowguard.control_roles import ControlRole, RoleSuggestion
from authflowguard.evaluation.cost_tracking import (
    CostLedgerStore,
    UsageSource,
    WorkflowPhase,
)
from authflowguard.evaluation.model_double import DeterministicModelDouble
from authflowguard.login_suggestions import (
    ClassificationBudget,
    SuggestionStatus,
    classify_within_budget,
    observation_for_classification,
)
from authflowguard.models import (
    CheckId,
    DiscoveryMode,
    EvidenceEvent,
    EvidenceKind,
    ExecutionLimits,
    ScanRequest,
)
from authflowguard.scan_manager import (
    ScanExecutionInput,
    ScanManager,
    ScanRecord,
    ScanState,
)
from fastapi.testclient import TestClient

PASSWORD = "live-password-canary"


@pytest.fixture(autouse=True)
def no_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail at once if anything tries to open a real Bedrock session."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("A test tried to create a real AWS session")

    monkeypatch.setattr("authflowguard.bedrock.boto3.Session", refuse)


def control(
    control_id: str,
    tag: str = "input",
    control_type: str | None = None,
    *,
    visible: bool = True,
    form_index: int | None = None,
    **attributes: Any,
) -> dict[str, Any]:
    described: dict[str, Any] = {
        "observed_control_id": control_id,
        "tag": tag,
        "id": None,
        "name": None,
        "type": control_type,
        "placeholder": None,
        "autocomplete": None,
        "aria_label": None,
        "text": None,
        "role": None,
        "value_present": None,
        "visible": visible,
        "form_index": form_index,
    }
    described.update(attributes)
    return described


CONVENTIONAL = [
    control("control-1", "input", "email", name="email", autocomplete="username"),
    control("control-2", "input", "password", autocomplete="current-password"),
    control("control-3", "button", "submit", text="Sign in"),
]

JUICE_SHOP_LIKE = [
    control("control-1", "button", text="Me want it!"),
    control("control-2", "input", "text", aria_label="Search"),
    control("control-3", "button", text="Add to Basket"),
    control("control-4", "button", text="Delete account"),
    control("control-5", "input", None, id="email", aria_label="Login email"),
    control("control-6", "input", "password", id="password"),
    control("control-7", "button", "submit", id="loginButton", text="Login"),
]


class ScriptedClassifier:
    """A classification client whose answer or failure a test chooses."""

    def __init__(
        self,
        answer: list[RoleSuggestion] | BaseException | None = None,
        *,
        reserved_cost_usd: float = 0.001,
        delay_seconds: float = 0.0,
    ) -> None:
        self.answer = answer if answer is not None else []
        self.reserved_cost_usd = reserved_cost_usd
        self.delay_seconds = delay_seconds
        self.observations: list[PageObservationForModel] = []

    def estimate_classification_cost(
        self, observation: PageObservationForModel
    ) -> float:
        return self.reserved_cost_usd

    def classify_controls(
        self, observation: PageObservationForModel
    ) -> BedrockClassificationDecision:
        self.observations.append(observation)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return BedrockClassificationDecision(
            suggestions=tuple(self.answer),
            discarded_count=0,
            input_tokens=300,
            output_tokens=20,
            actual_cost_usd=0.0000133,
            reserved_cost_usd=self.reserved_cost_usd,
        )

    # The scan manager's factory also serves the action loop.
    def estimate_maximum_cost(self, observation: PageObservationForModel) -> float:
        return self.reserved_cost_usd

    def choose_action(
        self, observation: PageObservationForModel
    ) -> BedrockActionDecision:
        raise AssertionError("The action loop is not used here")


class ActionOnlyClient:
    """A client that can choose actions but cannot classify controls."""

    def estimate_maximum_cost(self, observation: PageObservationForModel) -> float:
        return 0.001

    def choose_action(
        self, observation: PageObservationForModel
    ) -> BedrockActionDecision:
        raise AssertionError("not used")


MALICIOUS_ANSWER = [
    RoleSuggestion("control-3", ControlRole.USERNAME),  # "Add to Basket"
    RoleSuggestion("control-2", ControlRole.PASSWORD),  # the search box
    RoleSuggestion("control-4", ControlRole.SUBMIT),  # "Delete account"
]


def make_manager(
    tmp_path: Path,
    client_factory: Callable[[], object] | None = None,
    **options: Any,
) -> ScanManager:
    return ScanManager(
        tmp_path,
        action_client_factory=client_factory,  # type: ignore[arg-type]
        worker_backend="thread",
        **options,
    )


def awaiting_scan(
    manager: ScanManager,
    mode: DiscoveryMode,
    *,
    target_url: str = "https://app.example/#/login",
    origin: str = "https://app.example",
    limits: ExecutionLimits | None = None,
) -> ScanRecord:
    record = manager.create_scan(
        ScanRequest(
            target={"target_url": target_url, "permitted_origins": [origin]},
            selected_checks=[CheckId.LOGIN_ENUMERATION],
            discovery_mode=mode,
            limits=limits or ExecutionLimits(),
        )
    )
    record.state = ScanState.AWAITING_GUIDANCE
    record.pending_execution = ScanExecutionInput(
        runtime_secrets={"username": "developer@example.test", "password": PASSWORD},
        username_reference="username",
        password_reference="password",
        nonexistent_identifier_reference="username",
        failure_password_reference="password",
        protected_resource=f"{origin}/account",
        account_marker_selector="#marker",
        account_marker_description="Account marker",
    )
    manager._persist_state(record)
    return record


def patch_observation(
    monkeypatch: pytest.MonkeyPatch, controls: list[dict[str, Any]]
) -> None:
    async def fake_observation(**kwargs: Any) -> GuidedPageObservation:
        event = EvidenceEvent(
            event_id=uuid4(),
            scan_id=kwargs["scan_id"],
            kind=EvidenceKind.PAGE_STATE,
            summary="Observed controls",
            redacted_details={
                "url": "https://app.example/#/login",
                "title": "Login",
                "controls": controls,
            },
        )
        return GuidedPageObservation(event=event, controls=controls)  # type: ignore[arg-type]

    monkeypatch.setattr(
        "authflowguard.scan_manager.observe_guidance_page", fake_observation
    )


def observe(manager: ScanManager, record: ScanRecord) -> dict[str, Any]:
    try:
        return asyncio.run(manager.observe_guidance(record.scan_id))
    finally:
        manager.shutdown()


def ledger_entries(tmp_path: Path, record: ScanRecord) -> list[Any]:
    path = tmp_path / str(record.scan_id) / "cost-ledger.ndjson"
    return CostLedgerStore(path).load()


def test_rules_suggestion_makes_no_model_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    double = DeterministicModelDouble()
    manager = make_manager(tmp_path, lambda: double)
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, CONVENTIONAL)

    observed = observe(manager, record)

    assert observed["suggested_controls"] == {
        "username": "control-1",
        "password": "control-2",
        "submit": "control-3",
        "source": "rules",
        "status": "rules_detected",
        "rejected": [],
    }
    assert double.classify_calls == 0
    assert ledger_entries(tmp_path, record) == []


def test_ai_suggestion_is_validated_and_counted_in_the_scan_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    double = DeterministicModelDouble()
    manager = make_manager(tmp_path, lambda: double)
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    observed = observe(manager, record)

    assert observed["suggested_controls"] == {
        "username": "control-5",
        "password": "control-6",
        "submit": "control-7",
        "source": "ai",
        "status": "ai_suggested",
        "rejected": [],
    }
    assert len(observed["controls"]) == len(JUICE_SHOP_LIKE)
    assert double.classify_calls == 1
    sent = double.observations[0]
    assert PASSWORD not in sent.model_dump_json()
    assert sent.credential_references == []

    entries = ledger_entries(tmp_path, record)
    assert [entry.is_reservation for entry in entries] == [True, False]
    assert {entry.phase for entry in entries} == {WorkflowPhase.FIELD_DETECTION}
    assert {entry.source for entry in entries} == {UsageSource.MOCK}
    assert entries[0].request_id == entries[1].request_id
    assert entries[1].input_tokens == double.input_tokens
    assert record.model_request_count == 1
    assert record.decision_count == 1
    assert record.total_input_tokens == double.input_tokens
    assert record.estimated_cost_usd > 0
    assert record.unresolved_reservations_usd == 0
    assert record.provenance is not None
    assert record.provenance.usage_source == "mock"
    assert manager._usage_summary(record)["uncertain_requests"] == 0


def test_rules_mode_never_asks_a_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    double = DeterministicModelDouble()
    manager = make_manager(tmp_path, lambda: double)
    record = awaiting_scan(manager, DiscoveryMode.RULES)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    observed = observe(manager, record)

    assert observed["suggested_controls"] == {
        "username": None,
        "password": None,
        "submit": None,
        "source": None,
        "status": "not_detected",
        "rejected": [],
    }
    assert double.classify_calls == 0
    assert ledger_entries(tmp_path, record) == []


def test_a_malicious_answer_is_rejected_with_fixed_reasons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = make_manager(tmp_path, lambda: ScriptedClassifier(MALICIOUS_ANSWER))
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    suggested = observe(manager, record)["suggested_controls"]

    assert suggested["username"] is None
    assert suggested["password"] is None
    assert suggested["submit"] is None
    assert suggested["source"] is None
    assert suggested["status"] == "ai_no_valid_roles"
    assert suggested["rejected"] == [
        {
            "observed_control_id": "control-3",
            "role": "username",
            "reason": "not_text_field",
        },
        {
            "observed_control_id": "control-2",
            "role": "password",
            "reason": "not_password_field",
        },
        {
            "observed_control_id": "control-4",
            "role": "submit",
            "reason": "irreversible_action",
        },
    ]


def test_a_partly_valid_answer_suggests_only_the_valid_roles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    answer = [
        RoleSuggestion("control-5", ControlRole.USERNAME),
        RoleSuggestion("control-6", ControlRole.PASSWORD),
        RoleSuggestion("control-4", ControlRole.SUBMIT),
    ]
    manager = make_manager(tmp_path, lambda: ScriptedClassifier(answer))
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    suggested = observe(manager, record)["suggested_controls"]

    assert suggested["username"] == "control-5"
    assert suggested["password"] == "control-6"
    assert suggested["submit"] is None
    assert suggested["source"] == "ai"


def test_a_model_error_returns_the_observation_without_suggestions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = make_manager(
        tmp_path, lambda: ScriptedClassifier(RuntimeError("connection reset"))
    )
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    observed = observe(manager, record)

    assert len(observed["controls"]) == len(JUICE_SHOP_LIKE)
    assert observed["suggested_controls"]["status"] == "ai_failed"
    assert observed["suggested_controls"]["username"] is None
    assert "connection reset" not in str(observed)
    # The request may have been charged, so its reservation stays counted.
    entries = ledger_entries(tmp_path, record)
    assert [entry.is_reservation for entry in entries] == [True]
    assert record.unresolved_reservations_usd == pytest.approx(0.001)
    assert record.model_request_count == 1


def test_an_invalid_model_answer_is_reconciled_with_its_usage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = BedrockResponseError(
        "Bedrock returned an invalid role list", input_tokens=250, output_tokens=9
    )
    manager = make_manager(tmp_path, lambda: ScriptedClassifier(error))
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    observed = observe(manager, record)

    assert observed["suggested_controls"]["status"] == "ai_failed"
    entries = ledger_entries(tmp_path, record)
    assert [entry.is_reservation for entry in entries] == [True, False]
    assert entries[1].input_tokens == 250
    assert record.total_input_tokens == 250


def test_a_slow_model_times_out_without_blocking_the_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    classifier = ScriptedClassifier(MALICIOUS_ANSWER, delay_seconds=1.0)
    manager = make_manager(tmp_path, lambda: classifier, suggestion_timeout=0.05)
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    async def timed_observation() -> tuple[dict[str, Any], float]:
        # Timed inside the event loop, as the server answers: asyncio.run
        # itself waits for the abandoned model thread when it closes.
        started = time.monotonic()
        observed = await manager.observe_guidance(record.scan_id)
        return observed, time.monotonic() - started

    try:
        observed, elapsed = asyncio.run(timed_observation())
    finally:
        manager.shutdown()

    assert elapsed < 0.9
    assert observed["suggested_controls"]["status"] == "ai_timed_out"
    assert observed["suggested_controls"]["username"] is None


def test_the_scan_cost_limit_stops_the_request_before_it_is_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    classifier = ScriptedClassifier(MALICIOUS_ANSWER, reserved_cost_usd=0.001)
    manager = make_manager(tmp_path, lambda: classifier)
    record = awaiting_scan(
        manager,
        DiscoveryMode.BEDROCK,
        limits=ExecutionLimits(maximum_inference_cost_usd=0.0005),
    )
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    observed = observe(manager, record)

    assert observed["suggested_controls"]["status"] == "ai_cost_limit_reached"
    assert classifier.observations == []
    assert ledger_entries(tmp_path, record) == []


def test_the_scan_decision_limit_stops_the_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    classifier = ScriptedClassifier(MALICIOUS_ANSWER)
    manager = make_manager(tmp_path, lambda: classifier)
    record = awaiting_scan(
        manager,
        DiscoveryMode.BEDROCK,
        limits=ExecutionLimits(maximum_ai_decisions=2),
    )
    record.model_request_count = 2
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    observed = observe(manager, record)

    assert observed["suggested_controls"]["status"] == "ai_decision_limit_reached"
    assert classifier.observations == []


def test_a_client_that_cannot_classify_gives_no_suggestions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = make_manager(tmp_path, ActionOnlyClient)
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    observed = observe(manager, record)

    assert observed["suggested_controls"]["status"] == "ai_unavailable"


def test_unconfigured_bedrock_is_never_contacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "authflowguard.scan_manager.validate_bedrock_configuration",
        lambda settings=None: (False, "not configured"),
    )
    manager = make_manager(tmp_path)
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    observed = observe(manager, record)

    assert observed["suggested_controls"]["status"] == "ai_unavailable"
    assert ledger_entries(tmp_path, record) == []


def test_observe_api_returns_suggestions_beside_the_existing_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    double = DeterministicModelDouble()
    application = create_app(
        frontend_dist=tmp_path / "missing-dist",
        data_root=tmp_path,
        action_client_factory=lambda: double,
    )
    manager = application.state.scan_manager
    record = awaiting_scan(manager, DiscoveryMode.BEDROCK)
    patch_observation(monkeypatch, JUICE_SHOP_LIKE)

    with TestClient(application) as client:
        response = client.post(f"/api/scans/{record.scan_id}/guidance/observe")

    assert response.status_code == 200
    body = response.json()
    assert {"scan_id", "event_id", "url", "title", "controls"} <= set(body)
    assert body["suggested_controls"]["source"] == "ai"
    assert body["suggested_controls"]["password"] == "control-6"
    assert PASSWORD not in response.text


def test_the_budget_is_checked_against_reservations_already_outstanding(
    tmp_path: Path,
) -> None:
    store = CostLedgerStore(tmp_path / "cost-ledger.ndjson")
    ledger = store.load_into()
    scan_id = uuid4()
    ledger.record_reservation(
        request_id=uuid4(),
        run_id=str(scan_id),
        workflow="login_discovery",
        phase=WorkflowPhase.ACTION_SELECTION,
        model_id="amazon.nova-micro-v1:0",
        source=UsageSource.MOCK,
        reserved_cost_usd=Decimal("0.0045"),
        scan_id=scan_id,
    )
    classifier = ScriptedClassifier(MALICIOUS_ANSWER, reserved_cost_usd=0.001)
    budget = ClassificationBudget(
        scan_id=scan_id,
        limit_usd=0.005,
        ledger=ledger,
        ledger_store=store,
        usage_source=UsageSource.MOCK,
        model_id="amazon.nova-micro-v1:0",
    )
    observation = observation_for_classification(
        page_url="https://app.example/login",
        page_title="Login",
        controls=JUICE_SHOP_LIKE,
        redact=str,
    )

    result = classify_within_budget(classifier, observation, JUICE_SHOP_LIKE, budget)

    assert result.status is SuggestionStatus.AI_COST_LIMIT_REACHED
    assert classifier.observations == []


def test_the_classification_observation_holds_visible_controls_only() -> None:
    controls = [
        *JUICE_SHOP_LIKE,
        control("control-8", "input", "hidden", visible=False, name="csrf"),
        control("control-9", "input", "text", placeholder=f"Hi {PASSWORD}"),
    ]

    observation = observation_for_classification(
        page_url="https://app.example/login?next=/account",
        page_title="Login",
        controls=controls,
        redact=lambda text: text.replace(PASSWORD, "[redacted]"),
    )

    ids = [model_control.observed_control_id for model_control in observation.controls]
    assert "control-8" not in ids
    assert ids[:7] == [c["observed_control_id"] for c in JUICE_SHOP_LIKE]
    assert PASSWORD not in observation.model_dump_json()
    assert observation.controls[-1].placeholder == "Hi [redacted]"


# A page shaped like OWASP Juice Shop's login: a cookie banner, a search box
# and product buttons come before the form; the email field has neither an
# email type nor autocomplete; nothing is inside a <form>, except a
# newsletter form at the bottom.
JUICE_SHOP_PAGE = """<!doctype html>
<html>
<head><title>OWASP Juice Shop</title></head>
<body>
  <div class="cookie-banner">
    This website uses fruit cookies.
    <button>Me want it!</button>
  </div>
  <nav>
    <input id="searchQuery" type="text" aria-label="Search">
    <a href="/#/basket">Your Basket</a>
  </nav>
  <section>
    <button aria-label="Add to Basket">Add to Basket</button>
    <button aria-label="Add to Basket">Add to Basket</button>
    <button>Delete account</button>
  </section>
  <div class="login">
    <input id="email" aria-label="Text field for the login email">
    <input id="password" type="password"
           aria-label="Text field for the login password">
    <button id="loginButton" type="submit" aria-label="Login">Login</button>
  </div>
  <form id="newsletter">
    <input type="email" name="newsletter" aria-label="Newsletter email">
    <input type="submit" value="Subscribe">
  </form>
</body>
</html>"""


class JuiceShopLikeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = JUICE_SHOP_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def juice_shop_like_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), JuiceShopLikeHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def control_with(controls: list[dict[str, Any]], **attributes: Any) -> dict[str, Any]:
    matches = [
        observed
        for observed in controls
        if all(observed.get(key) == value for key, value in attributes.items())
    ]
    assert len(matches) == 1, attributes
    return matches[0]


def test_real_browser_juice_shop_like_page_gets_the_right_suggestions(
    tmp_path: Path,
) -> None:
    double = DeterministicModelDouble()
    with juice_shop_like_server() as origin:
        manager = make_manager(tmp_path, lambda: double)
        record = awaiting_scan(
            manager,
            DiscoveryMode.BEDROCK,
            target_url=f"{origin}/#/login",
            origin=origin,
        )
        observed = observe(manager, record)

    controls = observed["controls"]
    email = control_with(controls, id="email")
    password = control_with(controls, id="password")
    login = control_with(controls, id="loginButton")
    assert observed["suggested_controls"] == {
        "username": email["observed_control_id"],
        "password": password["observed_control_id"],
        "submit": login["observed_control_id"],
        "source": "ai",
        "status": "ai_suggested",
        "rejected": [],
    }
    assert double.classify_calls == 1
    # Form membership and a button input's label are read from the page.
    assert email["form_index"] is None
    assert control_with(controls, name="newsletter")["form_index"] == 0
    subscribe = control_with(controls, type="submit", tag="input")
    assert subscribe["text"] == "Subscribe"
    assert subscribe["form_index"] == 0


def test_real_browser_juice_shop_like_page_rejects_a_malicious_answer(
    tmp_path: Path,
) -> None:
    class PageAwareMaliciousClassifier(ScriptedClassifier):
        """Answers as a model steered by the page might."""

        def classify_controls(
            self, observation: PageObservationForModel
        ) -> BedrockClassificationDecision:
            def first(**attributes: str) -> str:
                return next(
                    model_control.observed_control_id
                    for model_control in observation.controls
                    if all(
                        getattr(model_control, key) == value
                        for key, value in attributes.items()
                    )
                )

            self.answer = [
                RoleSuggestion(first(aria_label="Add to Basket"), ControlRole.USERNAME),
                RoleSuggestion(first(aria_label="Search"), ControlRole.PASSWORD),
                RoleSuggestion(first(text="Delete account"), ControlRole.SUBMIT),
            ]
            return super().classify_controls(observation)

    classifier = PageAwareMaliciousClassifier()
    with juice_shop_like_server() as origin:
        manager = make_manager(tmp_path, lambda: classifier)
        record = awaiting_scan(
            manager,
            DiscoveryMode.BEDROCK,
            target_url=f"{origin}/#/login",
            origin=origin,
        )
        observed = observe(manager, record)

    suggested = observed["suggested_controls"]
    assert suggested["username"] is None
    assert suggested["password"] is None
    assert suggested["submit"] is None
    assert suggested["status"] == "ai_no_valid_roles"
    assert [rejection["reason"] for rejection in suggested["rejected"]] == [
        "not_text_field",
        "not_password_field",
        "irreversible_action",
    ]
