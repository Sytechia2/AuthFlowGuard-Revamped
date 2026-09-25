"""Tests for Bedrock cost measurement.

These cover the properties a published cost claim depends on: prices trace to a
stated source, totals are exact and repeatable, mock usage stays labelled, and
a ledger survives a restart.
"""

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
from authflowguard.bedrock import (
    MODEL_PRICES_USD_PER_1000_TOKENS,
    BedrockActionDecision,
)
from authflowguard.evaluation.cost_model import (
    DEFAULT_PRICE_BOOK,
    ImageTokenPolicy,
    PriceBookError,
    UnknownModelPriceError,
    calibrate_image_tokens,
    cost_usd,
    load_price_book,
    price_for,
)
from authflowguard.evaluation.cost_tracking import (
    CostLedger,
    CostLedgerStore,
    UsageSource,
    WorkflowPhase,
    format_usd,
    report_to_dict,
)
from authflowguard.models import BrowserAction, BrowserActionType

MICRO = "amazon.nova-micro-v1:0"
FIXED_TIME = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)


def fixed_clock() -> datetime:
    return FIXED_TIME


def build_ledger() -> CostLedger:
    return CostLedger(clock=fixed_clock)


def test_default_price_book_matches_the_production_table() -> None:
    """Measurement must price models exactly as live scans are charged."""

    for model_id, (
        input_price,
        output_price,
    ) in MODEL_PRICES_USD_PER_1000_TOKENS.items():
        price = DEFAULT_PRICE_BOOK[model_id]
        assert price.input_usd_per_1000_tokens == Decimal(str(input_price))
        assert price.output_usd_per_1000_tokens == Decimal(str(output_price))


def test_every_price_states_where_it_came_from() -> None:
    for model_id, price in DEFAULT_PRICE_BOOK.items():
        assert price.price_source.strip(), f"{model_id} has no price source"


def test_cost_matches_the_production_calculation() -> None:
    """The recorded cost of a request agrees with the live client's own maths."""

    input_price, output_price = MODEL_PRICES_USD_PER_1000_TOKENS[MICRO]
    expected = (652 / 1000) * input_price + (51 / 1000) * output_price

    measured = cost_usd(MICRO, input_tokens=652, output_tokens=51)

    assert float(measured) == pytest.approx(expected, rel=1e-9)


def test_unknown_model_is_refused_rather_than_priced_at_zero() -> None:
    with pytest.raises(UnknownModelPriceError) as error:
        cost_usd("made.up-model-v9:0", input_tokens=10, output_tokens=10)

    assert "No configured price" in str(error.value)


def test_negative_token_counts_are_refused() -> None:
    with pytest.raises(ValueError):
        cost_usd(MICRO, input_tokens=-1, output_tokens=0)


def test_totals_do_not_drift_across_many_small_entries() -> None:
    """Many sub-cent requests must still sum to the single-shot figure."""

    ledger = build_ledger()
    for _ in range(1000):
        ledger.record(
            run_id="run-1",
            workflow="login",
            phase=WorkflowPhase.ACTION_SELECTION,
            model_id=MICRO,
            source=UsageSource.MOCK,
            input_tokens=652,
            output_tokens=51,
        )

    report = ledger.build_report()

    assert report.total_cost_usd == cost_usd(
        MICRO, input_tokens=652 * 1000, output_tokens=51 * 1000
    )


def test_report_is_identical_for_identical_input() -> None:
    """A benchmark table has to be repeatable to be quotable."""

    first = report_to_dict(build_sample_ledger().build_report())
    second = report_to_dict(build_sample_ledger().build_report())

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def build_sample_ledger() -> CostLedger:
    ledger = build_ledger()
    ledger.record(
        run_id="run-1",
        workflow="login",
        phase=WorkflowPhase.FIELD_DETECTION,
        model_id=MICRO,
        source=UsageSource.MOCK,
        input_tokens=1200,
        output_tokens=80,
        image_count=1,
    )
    ledger.record(
        run_id="run-2",
        workflow="login",
        phase=WorkflowPhase.ACTION_SELECTION,
        model_id=MICRO,
        source=UsageSource.MOCK,
        input_tokens=600,
        output_tokens=40,
    )
    ledger.record(
        run_id="run-1",
        workflow="logout",
        phase=WorkflowPhase.STATE_ANALYSIS,
        model_id=MICRO,
        source=UsageSource.MOCK,
        input_tokens=300,
        output_tokens=20,
    )
    return ledger


def test_cost_per_run_divides_by_distinct_runs_not_requests() -> None:
    report = build_sample_ledger().build_report()
    login_row = next(row for row in report.rows if row.workflow == "login")

    assert login_row.requests == 2
    assert login_row.runs == 2
    assert login_row.cost_per_run_usd == (login_row.total_cost_usd / 2).quantize(
        Decimal("0.00000001")
    )


def test_rows_are_sorted_so_the_table_order_is_stable() -> None:
    report = build_sample_ledger().build_report()

    assert [row.workflow for row in report.rows] == ["login", "logout"]


def test_mock_usage_is_labelled_as_not_being_an_aws_charge() -> None:
    report = build_sample_ledger().build_report()

    assert report.contains_mock_usage
    assert not report.contains_live_usage
    assert "MOCK ONLY" in report.provenance_note()
    assert all(row.is_mock_only for row in report.rows)


def test_mixed_sources_are_announced() -> None:
    ledger = build_sample_ledger()
    ledger.record(
        run_id="run-3",
        workflow="login",
        phase=WorkflowPhase.ACTION_SELECTION,
        model_id=MICRO,
        source=UsageSource.LIVE,
        input_tokens=10,
        output_tokens=10,
    )

    assert "MIXED" in ledger.build_report().provenance_note()


def test_cost_by_phase_attributes_spend() -> None:
    by_phase = build_sample_ledger().cost_by_phase()

    assert set(by_phase) == {
        WorkflowPhase.FIELD_DETECTION,
        WorkflowPhase.ACTION_SELECTION,
        WorkflowPhase.STATE_ANALYSIS,
    }
    assert by_phase[WorkflowPhase.FIELD_DETECTION] > Decimal("0")


def test_agent_decisions_can_be_recorded_directly() -> None:
    """Cost figures should come from the same object the agent loop produces."""

    decision = BedrockActionDecision(
        action=BrowserAction(
            action_type=BrowserActionType.CLICK,
            observed_control_id="control-7",
            description="Submit the login form",
        ),
        input_tokens=652,
        output_tokens=51,
        actual_cost_usd=0.00002996,
        reserved_cost_usd=0.00006828,
    )
    ledger = build_ledger()

    entry = ledger.record_bedrock_decision(
        decision,
        run_id="run-1",
        workflow="login",
        model_id=MICRO,
        source=UsageSource.LIVE,
    )

    assert entry.input_tokens == 652
    assert entry.reserved_cost_usd == Decimal("0.00006828")
    assert float(ledger.entry_cost_usd(entry)) == pytest.approx(
        decision.actual_cost_usd, rel=1e-6
    )


def test_recording_an_unpriced_model_fails_immediately() -> None:
    with pytest.raises(UnknownModelPriceError):
        build_ledger().record(
            run_id="run-1",
            workflow="login",
            phase=WorkflowPhase.OTHER,
            model_id="made.up-model-v9:0",
            source=UsageSource.MOCK,
            input_tokens=1,
            output_tokens=1,
        )


def test_budget_comparison_uses_measured_spend() -> None:
    ledger = build_sample_ledger()

    assert not ledger.exceeds_budget(Decimal("0.25"))
    assert ledger.exceeds_budget(Decimal("0.00000001"))


def test_ledger_survives_a_restart(tmp_path: Path) -> None:
    store = CostLedgerStore(tmp_path / "runs" / "cost-ledger.ndjson")
    store.append_all(build_sample_ledger().entries)

    reloaded = CostLedgerStore(store.ledger_path).load_into(clock=fixed_clock)

    assert report_to_dict(reloaded.build_report()) == report_to_dict(
        build_sample_ledger().build_report()
    )


def test_reloading_keeps_every_decimal_place(tmp_path: Path) -> None:
    store = CostLedgerStore(tmp_path / "cost-ledger.ndjson")
    ledger = build_ledger()
    entry = ledger.record(
        run_id="run-1",
        workflow="login",
        phase=WorkflowPhase.OTHER,
        model_id=MICRO,
        source=UsageSource.LIVE,
        input_tokens=1,
        output_tokens=1,
        reserved_cost_usd=Decimal("0.00006828"),
        scan_id=uuid4(),
    )
    store.append(entry)

    assert store.load()[0].reserved_cost_usd == Decimal("0.00006828")


def test_a_corrupt_ledger_line_names_the_line(tmp_path: Path) -> None:
    ledger_path = tmp_path / "cost-ledger.ndjson"
    ledger_path.write_text('{"not": "an entry"}\n', encoding="utf-8")

    with pytest.raises(ValueError) as error:
        CostLedgerStore(ledger_path).load()

    assert "line 1" in str(error.value)


def test_missing_ledger_reads_as_empty(tmp_path: Path) -> None:
    assert CostLedgerStore(tmp_path / "absent.ndjson").load() == []


def test_price_book_override_is_used_for_costs(tmp_path: Path) -> None:
    price_book_path = tmp_path / "prices.json"
    price_book_path.write_text(
        json.dumps(
            {
                MICRO: {
                    "input_usd_per_1000_tokens": "1",
                    "output_usd_per_1000_tokens": "2",
                    "price_source": "Invoice 2026-09-20",
                }
            }
        ),
        encoding="utf-8",
    )
    price_book = load_price_book(price_book_path)

    ledger = CostLedger(price_book=price_book, clock=fixed_clock)
    ledger.record(
        run_id="run-1",
        workflow="login",
        phase=WorkflowPhase.OTHER,
        model_id=MICRO,
        source=UsageSource.LIVE,
        input_tokens=1000,
        output_tokens=1000,
    )
    report = ledger.build_report()

    assert report.total_cost_usd == Decimal("3.00000000")
    assert report.price_sources == ("Invoice 2026-09-20",)


def test_price_book_rejects_incomplete_entries(tmp_path: Path) -> None:
    price_book_path = tmp_path / "prices.json"
    price_book_path.write_text(
        json.dumps({MICRO: {"input_usd_per_1000_tokens": "1"}}), encoding="utf-8"
    )

    with pytest.raises(PriceBookError) as error:
        load_price_book(price_book_path)

    assert "missing" in str(error.value)


def test_price_book_rejects_a_price_that_is_not_a_number(tmp_path: Path) -> None:
    price_book_path = tmp_path / "prices.json"
    price_book_path.write_text(
        json.dumps(
            {
                MICRO: {
                    "input_usd_per_1000_tokens": "cheap",
                    "output_usd_per_1000_tokens": "1",
                    "price_source": "guess",
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PriceBookError):
        load_price_book(price_book_path)


def test_image_tokens_are_flagged_until_they_are_measured() -> None:
    policy = ImageTokenPolicy.uncalibrated()

    assert not policy.calibrated
    assert policy.estimate_image_tokens(2) == policy.tokens_per_image * 2


def test_image_tokens_are_derived_from_observed_usage() -> None:
    policy = calibrate_image_tokens(
        text_only_input_tokens=650,
        with_image_input_tokens=2150,
        image_count=1,
    )

    assert policy.calibrated
    assert policy.tokens_per_image == 1500
    assert "650" in policy.note


def test_calibration_refuses_observations_that_show_no_image_cost() -> None:
    with pytest.raises(ValueError):
        calibrate_image_tokens(
            text_only_input_tokens=650,
            with_image_input_tokens=650,
            image_count=1,
        )


def test_money_is_formatted_without_losing_small_amounts() -> None:
    """Reproduces the FND-008 figure recorded in the execution plan.

    That task recorded 652 input and 51 output tokens costing $0.00002996 on
    Nova Micro. Measurement code that cannot reproduce an already published
    number should not be trusted to produce new ones.
    """

    assert format_usd(cost_usd(MICRO, 652, 51)) == "$0.00002996"


def test_vision_models_are_marked_for_field_detection() -> None:
    assert price_for("amazon.nova-pro-v1:0").supports_vision
    assert not price_for(MICRO).supports_vision
