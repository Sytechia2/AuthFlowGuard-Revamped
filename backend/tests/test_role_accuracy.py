"""Tests for the control-role accuracy and cost measurement.

Everything here runs offline: the boto3 session is replaced so that any
attempt to reach AWS fails the test, and the model is the deterministic
double or a fake.
"""

import json
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from authflowguard.config import load_server_settings
from authflowguard.control_roles import ControlRole
from authflowguard.evaluation import role_accuracy
from authflowguard.evaluation.cost_model import cost_usd
from authflowguard.evaluation.cost_tracking import CostLedger, UsageSource
from authflowguard.evaluation.model_double import DeterministicModelDouble
from authflowguard.evaluation.role_accuracy import (
    DEFAULT_GROUND_TRUTH,
    ClassificationRecord,
    ControlMatcher,
    ObservedPage,
    Outcome,
    PageTruth,
    RecordingClassifier,
    RunOptions,
    RunResult,
    build_classifier,
    classify_page,
    load_ground_truth,
    resolve_truth,
    score_role,
    summarise_accuracy,
    summarise_consistency,
    summarise_gate,
)
from authflowguard.login_suggestions import ClassificationBudget

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
USERNAME = ControlRole.USERNAME
PASSWORD = ControlRole.PASSWORD
SUBMIT = ControlRole.SUBMIT
LOGOUT = ControlRole.LOGOUT


@pytest.fixture(autouse=True)
def no_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail at once if anything tries to open a real Bedrock session."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("A test tried to create a real AWS session")

    monkeypatch.setattr("authflowguard.bedrock.boto3.Session", refuse)


def control(control_id: str, tag: str, **attributes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "observed_control_id": control_id,
        "tag": tag,
        "id": None,
        "name": None,
        "type": None,
        "placeholder": None,
        "autocomplete": None,
        "aria_label": None,
        "text": None,
        "role": None,
        "value_present": None,
        "visible": True,
        "form_index": 0,
        "href": None,
        "has_popup": False,
    }
    base.update(attributes)
    return base


LOGIN_CONTROLS = [
    control("control-1", "input", name="q", type="search", form_index=0),
    control("control-2", "input", name="member_id", form_index=1),
    control("control-3", "input", name="passphrase", type="password", form_index=1),
    control("control-4", "button", text="Open my bookings", form_index=1),
]


def login_page() -> PageTruth:
    return PageTruth(
        page_id="X-login",
        path="/entry",
        requires_sign_in=False,
        steps=(),
        requested_roles=(USERNAME, PASSWORD, SUBMIT, ControlRole.REGISTRATION_LINK),
        roles={
            USERNAME: (ControlMatcher.parse({"tag": "input", "name": "member_id"}),),
            PASSWORD: (ControlMatcher.parse({"name": "passphrase"}),),
            SUBMIT: (ControlMatcher.parse({"text": "open  MY bookings"}),),
            ControlRole.REGISTRATION_LINK: (),
        },
    )


# --- Scoring ----------------------------------------------------------------


def test_score_role_distinguishes_every_outcome() -> None:
    assert score_role("control-2", ["control-2"]) is Outcome.CORRECT
    assert score_role("control-2", ["control-1"]) is Outcome.WRONG
    assert score_role("control-2", ["control-2", "control-1"]) is Outcome.WRONG
    assert score_role("control-2", []) is Outcome.MISSED
    assert score_role(None, ["control-1"]) is Outcome.EXTRA
    assert score_role(None, []) is Outcome.ABSENT


def record(
    page_id: str,
    repetition: int,
    raw: dict[ControlRole, tuple[str, ...]],
    gated: dict[ControlRole, str | None],
    expected: dict[ControlRole, str | None],
) -> ClassificationRecord:
    return ClassificationRecord(
        application="X",
        page_id=page_id,
        repetition=repetition,
        status="ai_suggested",
        raw=raw,
        gated=gated,
        rejected=[],
        raw_outcomes={r: score_role(e, raw.get(r, ())) for r, e in expected.items()},
        gated_outcomes={
            r: score_role(e, () if gated.get(r) is None else (str(gated[r]),))
            for r, e in expected.items()
        },
    )


def test_gate_counts_caught_let_through_and_dropped_mistakes() -> None:
    expected: dict[ControlRole, str | None] = {
        USERNAME: "control-2",
        PASSWORD: "control-3",
        LOGOUT: None,
    }
    records = [
        # A wrong username the gate removed; a correct password kept.
        record(
            "X-login",
            1,
            {USERNAME: ("control-1",), PASSWORD: ("control-3",)},
            {USERNAME: None, PASSWORD: "control-3", LOGOUT: None},
            expected,
        ),
        # An extra logout the gate let through; a correct password dropped.
        record(
            "X-login",
            2,
            {USERNAME: ("control-2",), PASSWORD: ("control-3",), LOGOUT: ("c-9",)},
            {USERNAME: "control-2", PASSWORD: None, LOGOUT: "c-9"},
            expected,
        ),
    ]

    gate = summarise_gate(records)
    assert gate["per_role"]["username"]["caught"] == 1
    assert gate["per_role"]["logout"]["let_through"] == 1
    assert gate["per_role"]["password"]["dropped_correct"] == 1
    assert gate["overall"] == {
        "caught": 1,
        "corrected": 0,
        "let_through": 1,
        "dropped_correct": 1,
    }

    accuracy = summarise_accuracy(records)
    assert accuracy["raw"]["per_role"]["username"]["wrong_control"] == 1
    assert accuracy["gated"]["per_role"]["username"]["missed"] == 1
    assert accuracy["gated"]["per_role"]["logout"]["extra"] == 1
    assert accuracy["gated"]["per_role"]["logout"]["correctly_absent"] == 1
    assert accuracy["gated"]["overall"]["scored"] == 6
    # Correct: username #2, password #1; correctly absent: logout #1.
    assert accuracy["gated"]["overall"]["accuracy"] == 0.5

    consistency = summarise_consistency(records)["per_role"]
    assert consistency["password"] == {
        "pages": 1,
        "raw_consistent": 1,
        "gated_consistent": 0,
    }
    assert consistency["username"]["raw_consistent"] == 0


# --- Ground truth -----------------------------------------------------------


def test_truth_is_matched_by_attributes_not_by_position() -> None:
    expected, unresolved = resolve_truth(login_page(), LOGIN_CONTROLS)
    assert expected == {
        USERNAME: "control-2",
        PASSWORD: "control-3",
        SUBMIT: "control-4",
        ControlRole.REGISTRATION_LINK: None,
    }
    assert unresolved == {}

    # The same controls behind a new banner keep their truth.
    shifted = [
        {**item, "observed_control_id": f"control-{index + 2}"}
        for index, item in enumerate(LOGIN_CONTROLS)
    ]
    shifted.insert(0, control("control-1", "a", text="Offers", href="/offers"))
    expected, _ = resolve_truth(login_page(), shifted)
    assert expected[USERNAME] == "control-3"
    assert expected[SUBMIT] == "control-5"


def test_truth_that_matches_several_controls_is_not_scored() -> None:
    duplicated = [*LOGIN_CONTROLS, control("control-5", "input", name="member_id")]
    expected, unresolved = resolve_truth(login_page(), duplicated)
    assert USERNAME not in expected
    assert "2 controls match" in unresolved[USERNAME]


def test_href_matcher_uses_the_end_of_the_address() -> None:
    matcher = ControlMatcher.parse({"tag": "a", "href_endswith": "#/register"})
    assert matcher.matches(
        control("c", "a", href="http://127.0.0.1:3000/#/register", form_index=None)
    )
    assert not matcher.matches(control("c", "a", href="http://x/#/login"))


def test_ground_truth_file_loads_and_flags_juice_shop_as_unverified() -> None:
    truth = load_ground_truth(REPOSITORY_ROOT / DEFAULT_GROUND_TRUTH)
    assert set(truth) == {"A", "B", "C", "J"}
    assert all(truth[app].verified for app in "ABC")
    assert not truth["J"].verified
    for application in truth.values():
        for page in application.pages:
            assert set(page.roles) == set(page.requested_roles)
    b_code = truth["B"].page("B-code")
    assert b_code.roles[ControlRole.VERIFICATION_CODE]


def test_ground_truth_rejects_a_requested_role_without_truth(tmp_path: Path) -> None:
    document = json.loads(
        (REPOSITORY_ROOT / DEFAULT_GROUND_TRUTH).read_text(encoding="utf-8")
    )
    del document["applications"]["A"]["pages"][0]["roles"]["reset_link"]
    path = tmp_path / "truth.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(role_accuracy.GroundTruthError):
        load_ground_truth(path)


# --- Cost -------------------------------------------------------------------


def budget_for(ledger: CostLedger, limit: float) -> ClassificationBudget:
    return ClassificationBudget(
        scan_id=uuid4(),
        limit_usd=limit,
        ledger=ledger,
        ledger_store=None,
        usage_source=UsageSource.MOCK,
        model_id=load_server_settings().model_id,
    )


def classify_until_stopped(
    double: DeterministicModelDouble, ledger: CostLedger, limit: float
) -> list[ClassificationRecord]:
    page = login_page()
    observed = ObservedPage("X-login", "http://127.0.0.1:9/entry", "", LOGIN_CONTROLS)
    expected, _ = resolve_truth(page, LOGIN_CONTROLS)
    classifier = RecordingClassifier(double)
    budget = budget_for(ledger, limit)
    records: list[ClassificationRecord] = []
    for repetition in range(1, 10):
        classified = classify_page(
            application="X",
            truth=page,
            observed=observed,
            expected=expected,
            origin="http://127.0.0.1:9",
            classifier=classifier,
            budget=budget,
            repetition=repetition,
        )
        if classified is None:
            break
        records.append(classified)
    return records


def test_cost_cap_stops_the_run_before_it_is_exceeded() -> None:
    # Each request reserves $0.001 and costs 20000 input tokens.
    model_id = load_server_settings().model_id
    one_request = cost_usd(model_id, 20_000, 30)
    double = DeterministicModelDouble(input_tokens=20_000, reserved_cost_usd=0.001)
    ledger = CostLedger()
    limit = float(one_request) + 0.0011

    records = classify_until_stopped(double, ledger, limit)

    assert len(records) == 2
    assert double.classify_calls == 2
    assert ledger.total_budget_committed_usd() <= Decimal(str(limit))
    assert all(r.cost_usd == one_request for r in records)
    assert all(r.reserved_usd == Decimal("0.001") for r in records)

    result = RunResult(
        options=RunOptions(run_id="t", applications=("X",), repetitions=2),
        usage_source=UsageSource.MOCK,
        model_id=model_id,
        ledger=ledger,
        records=records,
    )
    cost = result.cost_summary()
    assert cost["usage_source"] == "mock"
    assert cost["classifications"] == 2
    assert cost["input_tokens"] == 40_000
    assert cost["total_cost_usd"] == 2 * one_request
    assert cost["cost_per_classification_usd"] == one_request
    assert cost["cost_per_page_usd"] == 2 * one_request


def test_double_classification_is_scored_raw_and_after_the_gate() -> None:
    records = classify_until_stopped(DeterministicModelDouble(), CostLedger(), 1.0)
    first = records[0]
    assert first.gated_outcomes == {
        USERNAME: Outcome.CORRECT,
        PASSWORD: Outcome.CORRECT,
        SUBMIT: Outcome.CORRECT,
        ControlRole.REGISTRATION_LINK: Outcome.ABSENT,
    }
    assert first.raw_outcomes == first.gated_outcomes


# --- Live calls -------------------------------------------------------------


def test_bedrock_mode_uses_the_double_unless_live_calls_are_confirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("A live client was built without confirmation")

    monkeypatch.setattr(role_accuracy, "BedrockActionClient", refuse)
    client, source = build_classifier("bedrock", False, load_server_settings())
    assert isinstance(client, DeterministicModelDouble)
    assert source is UsageSource.MOCK
    with pytest.raises(role_accuracy.LiveCallsNotConfirmedError):
        role_accuracy.live_classifier(load_server_settings(), False)


def test_live_run_needs_confirmation_and_a_cost_cap(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("The run started")

    monkeypatch.setattr(role_accuracy, "run_evaluation", refuse)
    with pytest.raises(SystemExit):
        role_accuracy.main(["--confirm-live-calls"])
    assert "--max-evaluation-cost-usd" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        role_accuracy.main(
            [
                "--discovery-mode",
                "rules",
                "--confirm-live-calls",
                "--max-evaluation-cost-usd",
                "0.05",
            ]
        )


# --- End to end -------------------------------------------------------------


def test_double_run_against_the_controlled_application(tmp_path: Path) -> None:
    exit_code = role_accuracy.main(
        [
            "--ground-truth",
            str(REPOSITORY_ROOT / DEFAULT_GROUND_TRUTH),
            "--applications",
            "A",
            "--repetitions",
            "1",
            "--results-root",
            str(tmp_path),
            "--run-id",
            "double-a",
        ]
    )
    assert exit_code == 0

    run_directory = tmp_path / "double-a"
    document = json.loads((run_directory / "role-accuracy.json").read_text("utf-8"))
    assert document["source"] == "double"
    assert document["usage_source"] == "mock"
    assert document["stopped_by_cost_cap"] is False
    pages = {page["page_id"]: page for page in document["pages"]}
    assert set(pages) == {"A-login", "A-account"}
    assert all(not page["unresolved_truth"] for page in pages.values())
    assert all(page["error"] is None for page in pages.values())

    by_page = {r["page_id"]: r for r in document["classifications"]}
    assert set(by_page["A-login"]["gated_outcomes"].values()) == {"correct"}
    assert by_page["A-account"]["gated_outcomes"] == {
        "logout": "correct",
        "account_menu": "correctly_absent",
    }
    assert document["verified_logins"] == [
        {
            "application": "A",
            "repetition": 1,
            "attempted": True,
            "verified": True,
            "detail": "Verified login",
            "reused_identical_flow": False,
        }
    ]
    assert document["cost"]["classifications"] == 2
    assert Decimal(document["cost"]["live_upper_bound_for_this_run_usd"]) > 0

    report = (run_directory / "role-accuracy.md").read_text("utf-8")
    assert "offline deterministic model double, not Amazon Bedrock" in report
    assert "`usage_source: mock`" in report
    assert (run_directory / "cost-ledger.ndjson").is_file()
