"""Durable, conservative accounting for billable model requests."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import ROUND_CEILING, Decimal
from pathlib import Path
from typing import Final, Literal, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

USD_QUANTUM = Decimal("0.00000001")
LEDGER_SCHEMA_VERSION: Final[Literal[1]] = 1
PRICING_SOURCE = "https://aws.amazon.com/bedrock/pricing/"
PRICING_VERIFIED_ON = date(2026, 9, 23)


def money(value: Decimal | float | str) -> Decimal:
    """Normalize money conservatively to fixed eight-decimal USD units."""

    return Decimal(str(value)).quantize(USD_QUANTUM, rounding=ROUND_CEILING)


class UsageLedgerError(RuntimeError):
    """Raised when accounting cannot safely authorize another request."""


class UsageBudgetExceeded(UsageLedgerError):
    """Raised before dispatch when a reservation would exceed the limit."""


class UsageEvent(BaseModel):
    """One append-only transition; it contains no prompt or response content."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = LEDGER_SCHEMA_VERSION
    event: Literal["reserved", "dispatched", "settled", "released"]
    scan_id: UUID
    attempt_id: UUID
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    model_id: str
    region: str
    pricing_source: str
    pricing_verified_on: date
    pricing_effective_date: date | None = None
    input_price_usd_per_1000_tokens: Decimal
    output_price_usd_per_1000_tokens: Decimal
    reserved_cost_usd: Decimal
    actual_cost_usd: Decimal | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    safe_reason: str | None = None
    estimator_violation: bool = False


@dataclass(frozen=True)
class UsageSummary:
    input_tokens: int
    output_tokens: int
    settled_cost_usd: Decimal
    outstanding_reserved_cost_usd: Decimal
    limit_usd: Decimal
    uncertain_requests: int
    estimator_violations: int

    def as_dict(self) -> dict[str, object]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "settled_cost_usd": format(self.settled_cost_usd, ".8f"),
            "outstanding_reserved_cost_usd": format(
                self.outstanding_reserved_cost_usd, ".8f"
            ),
            "limit_usd": format(self.limit_usd, ".8f"),
            "uncertain_requests": self.uncertain_requests,
            "estimator_violations": self.estimator_violations,
        }


class UsageAccountant(Protocol):
    def reserve(
        self,
        *,
        attempt_id: UUID,
        model_id: str,
        region: str,
        reserved_cost_usd: float,
        input_price_usd_per_1000_tokens: float,
        output_price_usd_per_1000_tokens: float,
    ) -> None: ...

    def mark_dispatched(self, attempt_id: UUID) -> None: ...

    def settle(
        self,
        attempt_id: UUID,
        *,
        input_tokens: int,
        output_tokens: int,
        actual_cost_usd: float,
    ) -> None: ...

    def release(self, attempt_id: UUID, safe_reason: str) -> None: ...


class DurableUsageLedger:
    """Append transitions with fsync and rebuild totals after process restart."""

    def __init__(self, path: str | Path, scan_id: UUID, limit_usd: float) -> None:
        self.path = Path(path)
        self.scan_id = scan_id
        self.limit_usd = money(limit_usd)
        self._lock = threading.RLock()
        self._events: list[UsageEvent] = []
        self._load()

    def reserve(
        self,
        *,
        attempt_id: UUID,
        model_id: str,
        region: str,
        reserved_cost_usd: float,
        input_price_usd_per_1000_tokens: float,
        output_price_usd_per_1000_tokens: float,
    ) -> None:
        with self._lock:
            existing = self._state(attempt_id)
            if existing is not None:
                if existing[0].event == "reserved":
                    return
                raise UsageLedgerError("The usage attempt identifier was replayed")
            reserved = money(reserved_cost_usd)
            summary = self.summary()
            consumed = summary.settled_cost_usd + summary.outstanding_reserved_cost_usd
            if consumed + reserved > self.limit_usd:
                raise UsageBudgetExceeded(
                    "The model request would exceed the scan budget"
                )
            self._append(
                UsageEvent(
                    event="reserved",
                    scan_id=self.scan_id,
                    attempt_id=attempt_id,
                    model_id=model_id,
                    region=region,
                    pricing_source=PRICING_SOURCE,
                    pricing_verified_on=PRICING_VERIFIED_ON,
                    input_price_usd_per_1000_tokens=money(
                        input_price_usd_per_1000_tokens
                    ),
                    output_price_usd_per_1000_tokens=money(
                        output_price_usd_per_1000_tokens
                    ),
                    reserved_cost_usd=reserved,
                )
            )

    def mark_dispatched(self, attempt_id: UUID) -> None:
        self._transition(attempt_id, "dispatched")

    def settle(
        self,
        attempt_id: UUID,
        *,
        input_tokens: int,
        output_tokens: int,
        actual_cost_usd: float,
    ) -> None:
        actual = money(actual_cost_usd)
        _, reservation = self._required(attempt_id)
        self._transition(
            attempt_id,
            "settled",
            actual_cost_usd=actual,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimator_violation=actual > reservation.reserved_cost_usd,
        )

    def release(self, attempt_id: UUID, safe_reason: str) -> None:
        with self._lock:
            state, _ = self._required(attempt_id)
            if state == "released":
                return
            if state != "reserved":
                raise UsageLedgerError("A dispatched reservation cannot be released")
            self._transition(attempt_id, "released", safe_reason=safe_reason)

    def summary(self) -> UsageSummary:
        with self._lock:
            latest: dict[UUID, UsageEvent] = {}
            for event in self._events:
                latest[event.attempt_id] = event
            settled = [event for event in latest.values() if event.event == "settled"]
            outstanding = [
                event
                for event in latest.values()
                if event.event in {"reserved", "dispatched"}
            ]
            return UsageSummary(
                input_tokens=sum(event.input_tokens or 0 for event in settled),
                output_tokens=sum(event.output_tokens or 0 for event in settled),
                settled_cost_usd=money(
                    sum(
                        (event.actual_cost_usd or Decimal(0) for event in settled),
                        Decimal(0),
                    )
                ),
                outstanding_reserved_cost_usd=money(
                    sum(
                        (event.reserved_cost_usd for event in outstanding),
                        Decimal(0),
                    )
                ),
                limit_usd=self.limit_usd,
                uncertain_requests=sum(
                    event.event == "dispatched" for event in outstanding
                ),
                estimator_violations=sum(
                    event.estimator_violation for event in settled
                ),
            )

    def _transition(self, attempt_id: UUID, event_name: str, **updates: object) -> None:
        with self._lock:
            state, previous = self._required(attempt_id)
            if state == event_name:
                return
            allowed = {
                "reserved": {"dispatched", "released"},
                "dispatched": {"settled"},
            }
            if event_name not in allowed.get(state, set()):
                raise UsageLedgerError(
                    f"Invalid usage transition: {state} -> {event_name}"
                )
            self._append(
                previous.model_copy(
                    update={
                        "event": event_name,
                        "occurred_at": datetime.now(UTC),
                        **updates,
                    }
                )
            )

    def _required(self, attempt_id: UUID) -> tuple[str, UsageEvent]:
        current = self._state(attempt_id)
        if current is None:
            raise UsageLedgerError("The usage reservation does not exist")
        return current[0].event, current[0]

    def _state(self, attempt_id: UUID) -> tuple[UsageEvent, int] | None:
        for index in range(len(self._events) - 1, -1, -1):
            if self._events[index].attempt_id == attempt_id:
                return self._events[index], index
        return None

    def _append(self, event: UsageEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = event.model_dump_json() + "\n"
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        self._events.append(event)

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open(encoding="utf-8") as stream:
                self._events = [
                    UsageEvent.model_validate_json(line)
                    for line in stream
                    if line.strip()
                ]
        except (OSError, ValueError) as error:
            raise UsageLedgerError(
                "The usage ledger is corrupt or unreadable"
            ) from error
        if any(event.scan_id != self.scan_id for event in self._events):
            raise UsageLedgerError("The usage ledger belongs to another scan")
        states: dict[UUID, str] = {}
        for event in self._events:
            previous = states.get(event.attempt_id)
            allowed_previous = {
                "reserved": None,
                "dispatched": "reserved",
                "settled": "dispatched",
                "released": "reserved",
            }
            if event.event not in allowed_previous:
                raise UsageLedgerError("The usage ledger has an unknown transition")
            if previous != allowed_previous[event.event]:
                raise UsageLedgerError("The usage ledger has an invalid transition")
            if event.event == "settled" and (
                event.actual_cost_usd is None
                or event.input_tokens is None
                or event.output_tokens is None
            ):
                raise UsageLedgerError("The usage settlement is incomplete")
            states[event.attempt_id] = event.event


def new_attempt_id() -> UUID:
    return uuid4()
