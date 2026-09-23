"""Durable reservation and model-call accounting tests."""

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from authflowguard.bedrock import (
    BedrockActionClient,
    BedrockCostLimitError,
    BedrockResponseError,
)
from authflowguard.usage_ledger import (
    DurableUsageLedger,
    UsageBudgetExceeded,
    UsageLedgerError,
)
from test_bedrock import (
    FakeBedrockRuntimeClient,
    make_configuration,
    make_observation,
)

SCAN_ID = UUID("00000000-0000-0000-0000-000000000025")


def reserve(ledger: DurableUsageLedger, attempt_id: UUID, cost: float = 0.01) -> None:
    ledger.reserve(
        attempt_id=attempt_id,
        model_id="amazon.nova-micro-v1:0",
        region="us-east-1",
        reserved_cost_usd=cost,
        input_price_usd_per_1000_tokens=0.000035,
        output_price_usd_per_1000_tokens=0.00014,
    )


def test_settled_usage_survives_restart_and_releases_unused_reservation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "usage.ndjson"
    attempt_id = uuid4()
    ledger = DurableUsageLedger(path, SCAN_ID, 0.25)
    reserve(ledger, attempt_id, 0.1)
    ledger.mark_dispatched(attempt_id)
    ledger.settle(
        attempt_id,
        input_tokens=100,
        output_tokens=20,
        actual_cost_usd=0.02,
    )

    restored = DurableUsageLedger(path, SCAN_ID, 0.25).summary()
    assert restored.input_tokens == 100
    assert restored.output_tokens == 20
    assert str(restored.settled_cost_usd) == "0.02000000"
    assert restored.outstanding_reserved_cost_usd == 0


def test_dispatched_request_remains_uncertain_and_consumes_budget_after_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "usage.ndjson"
    attempt_id = uuid4()
    ledger = DurableUsageLedger(path, SCAN_ID, 0.01)
    reserve(ledger, attempt_id)
    ledger.mark_dispatched(attempt_id)

    restored = DurableUsageLedger(path, SCAN_ID, 0.01)
    assert restored.summary().uncertain_requests == 1
    with pytest.raises(UsageBudgetExceeded):
        reserve(restored, uuid4(), 0.00000001)


def test_concurrent_reservations_are_serialized_at_the_limit(tmp_path: Path) -> None:
    ledger = DurableUsageLedger(tmp_path / "usage.ndjson", SCAN_ID, 0.01)

    def attempt() -> bool:
        try:
            reserve(ledger, uuid4(), 0.006)
        except UsageBudgetExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        accepted = list(executor.map(lambda _: attempt(), range(2)))
    assert sorted(accepted) == [False, True]


def test_replayed_settlement_is_idempotent_and_corruption_blocks_loading(
    tmp_path: Path,
) -> None:
    path = tmp_path / "usage.ndjson"
    attempt_id = uuid4()
    ledger = DurableUsageLedger(path, SCAN_ID, 1)
    reserve(ledger, attempt_id)
    ledger.mark_dispatched(attempt_id)
    ledger.settle(attempt_id, input_tokens=1, output_tokens=2, actual_cost_usd=0.001)
    ledger.settle(attempt_id, input_tokens=1, output_tokens=2, actual_cost_usd=0.001)
    assert ledger.summary().settled_cost_usd == Decimal("0.00100000")

    path.write_text(path.read_text(encoding="utf-8") + "not-json\n", encoding="utf-8")
    with pytest.raises(UsageLedgerError, match="corrupt"):
        DurableUsageLedger(path, SCAN_ID, 1)


def test_invalid_action_still_settles_provider_reported_usage(tmp_path: Path) -> None:
    response = {
        "usage": {"inputTokens": 100, "outputTokens": 30},
        "output": {"message": {"content": [{"text": "not a tool call"}]}},
        "stopReason": "end_turn",
    }
    runtime = FakeBedrockRuntimeClient(response)
    ledger = DurableUsageLedger(tmp_path / "usage.ndjson", SCAN_ID, 1)
    client = BedrockActionClient(make_configuration(), runtime, usage_accountant=ledger)

    with pytest.raises(BedrockResponseError):
        client.choose_action(make_observation())

    summary = ledger.summary()
    assert summary.input_tokens == 100
    assert summary.output_tokens == 30
    assert summary.outstanding_reserved_cost_usd == 0


def test_ledger_rejects_over_budget_request_before_provider_dispatch(
    tmp_path: Path,
) -> None:
    runtime = FakeBedrockRuntimeClient(
        {
            "usage": {"inputTokens": 1, "outputTokens": 1},
            "output": {"message": {"content": []}},
        }
    )
    ledger = DurableUsageLedger(tmp_path / "usage.ndjson", SCAN_ID, 0)
    client = BedrockActionClient(make_configuration(), runtime, usage_accountant=ledger)

    with pytest.raises(BedrockCostLimitError, match="budget"):
        client.choose_action(make_observation())

    assert runtime.requests == []
