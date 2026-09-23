"""Per-run Bedrock token and cost accounting for authentication workflows.

The ledger records the token counts a model reported and nothing else. Money is
derived from those counts once, at report time, so that a published total is
reproducible from the ledger file and cannot drift as entries accumulate.

Every entry states whether its usage came from a live model or a mock. A report
that mixes the two says so on every row, because a mock figure must never be
presented as a measured AWS cost.
"""

import json
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import Field, field_serializer

from authflowguard.bedrock import BedrockActionDecision
from authflowguard.evaluation.cost_model import (
    USD_PLACES,
    ModelPrice,
    cost_usd,
    price_for,
)
from authflowguard.models import ContractModel

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class WorkflowPhase(StrEnum):
    """The part of a scan that spent the tokens."""

    FIELD_DETECTION = "field_detection"
    STATE_ANALYSIS = "state_analysis"
    ACTION_SELECTION = "action_selection"
    OTHER = "other"


class UsageSource(StrEnum):
    """Whether a recorded usage figure came from AWS or from a mock."""

    LIVE = "live"
    MOCK = "mock"
    NONE = "none"


class CostEntry(ContractModel):
    """One priced model request, recorded as exact token counts."""

    entry_id: UUID = Field(default_factory=uuid4)
    request_id: UUID | None = None
    run_id: str = Field(min_length=1)
    workflow: str = Field(min_length=1)
    phase: WorkflowPhase
    model_id: str = Field(min_length=1)
    source: UsageSource
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    image_count: int = Field(default=0, ge=0)
    reserved_cost_usd: Decimal | None = Field(default=None, ge=0)
    scan_id: UUID | None = None
    is_reservation: bool = False
    reconciled: bool = False
    recorded_at: datetime = Field(default_factory=_utc_now)

    @field_serializer("reserved_cost_usd")
    def _serialize_reserved_cost(self, value: Decimal | None) -> str | None:
        """Write money as text so a reload cannot lose decimal places."""

        return None if value is None else str(value)


@dataclass(frozen=True)
class WorkflowCostRow:
    """One row of the per-workflow cost table."""

    workflow: str
    runs: int
    requests: int
    input_tokens: int
    output_tokens: int
    images: int
    total_cost_usd: Decimal
    cost_per_run_usd: Decimal
    model_ids: tuple[str, ...]
    sources: tuple[UsageSource, ...]

    @property
    def is_mock_only(self) -> bool:
        return self.sources == (UsageSource.MOCK,)


@dataclass(frozen=True)
class CostReport:
    """Everything needed to publish a cost table and defend its numbers."""

    rows: tuple[WorkflowCostRow, ...]
    total_cost_usd: Decimal
    total_input_tokens: int
    total_output_tokens: int
    total_requests: int
    total_runs: int
    sources: tuple[UsageSource, ...]
    price_sources: tuple[str, ...]
    generated_at: datetime

    @property
    def contains_mock_usage(self) -> bool:
        return UsageSource.MOCK in self.sources

    @property
    def contains_live_usage(self) -> bool:
        return UsageSource.LIVE in self.sources

    def provenance_note(self) -> str:
        """State plainly what the numbers in this report are."""

        if self.contains_mock_usage and self.contains_live_usage:
            return (
                "MIXED: this report combines live AWS usage with mock usage. "
                "Read the source column on every row before quoting a total."
            )
        if self.contains_mock_usage:
            return (
                "MOCK ONLY: token counts came from local fixtures, not from "
                "AWS. These figures show what a run would cost at the stated "
                "prices. They are not a measured AWS charge."
            )
        return "LIVE: token counts were reported by AWS Bedrock."


class CostLedger:
    """Collects priced requests and turns them into a repeatable cost table."""

    def __init__(
        self,
        price_book: dict[str, ModelPrice] | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        self._price_book = price_book
        self._clock = clock
        self._entries: list[CostEntry] = []

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[CostEntry]:
        return iter(self._entries)

    @property
    def entries(self) -> tuple[CostEntry, ...]:
        return tuple(self._entries)

    def record(
        self,
        *,
        run_id: str,
        workflow: str,
        phase: WorkflowPhase,
        model_id: str,
        source: UsageSource,
        input_tokens: int,
        output_tokens: int,
        image_count: int = 0,
        reserved_cost_usd: Decimal | None = None,
        scan_id: UUID | None = None,
    ) -> CostEntry:
        """Record one request. Rejects models with no configured price."""

        price_for(model_id, self._price_book)
        entry = CostEntry(
            run_id=run_id,
            workflow=workflow,
            phase=phase,
            model_id=model_id,
            source=source,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            image_count=image_count,
            reserved_cost_usd=reserved_cost_usd,
            scan_id=scan_id,
            recorded_at=self._clock(),
        )
        self._entries.append(entry)
        return entry

    def record_bedrock_decision(
        self,
        decision: BedrockActionDecision,
        *,
        run_id: str,
        workflow: str,
        model_id: str,
        source: UsageSource,
        phase: WorkflowPhase = WorkflowPhase.ACTION_SELECTION,
        image_count: int = 0,
        scan_id: UUID | None = None,
    ) -> CostEntry:
        """Record usage straight from the agent loop's own decision object.

        This is the path that ties a published cost figure to the code a scan
        actually runs, rather than to a separate estimate maintained by hand.
        """

        return self.record(
            run_id=run_id,
            workflow=workflow,
            phase=phase,
            model_id=model_id,
            source=source,
            input_tokens=decision.input_tokens,
            output_tokens=decision.output_tokens,
            image_count=image_count,
            reserved_cost_usd=Decimal(str(decision.reserved_cost_usd)),
            scan_id=scan_id,
        )

    def record_reservation(
        self,
        *,
        request_id: UUID,
        run_id: str,
        workflow: str,
        phase: WorkflowPhase,
        model_id: str,
        source: UsageSource,
        reserved_cost_usd: Decimal,
        scan_id: UUID | None = None,
    ) -> CostEntry:
        price_for(model_id, self._price_book)
        entry = CostEntry(
            request_id=request_id,
            run_id=run_id,
            workflow=workflow,
            phase=phase,
            model_id=model_id,
            source=source,
            input_tokens=0,
            output_tokens=0,
            reserved_cost_usd=reserved_cost_usd,
            scan_id=scan_id,
            is_reservation=True,
            recorded_at=self._clock(),
        )
        self._entries.append(entry)
        return entry

    def record_reconciliation(
        self,
        *,
        request_id: UUID,
        run_id: str,
        workflow: str,
        phase: WorkflowPhase,
        model_id: str,
        source: UsageSource,
        input_tokens: int,
        output_tokens: int,
        reserved_cost_usd: Decimal | None = None,
        image_count: int = 0,
        scan_id: UUID | None = None,
    ) -> CostEntry:
        price_for(model_id, self._price_book)
        if any(
            entry.request_id == request_id and entry.reconciled
            for entry in self._entries
        ):
            raise ValueError(f"Request {request_id} was already reconciled")
        entry = CostEntry(
            request_id=request_id,
            run_id=run_id,
            workflow=workflow,
            phase=phase,
            model_id=model_id,
            source=source,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            image_count=image_count,
            reserved_cost_usd=reserved_cost_usd,
            scan_id=scan_id,
            is_reservation=False,
            reconciled=True,
            recorded_at=self._clock(),
        )
        self._entries.append(entry)
        return entry

    def total_observed_cost_usd(self) -> Decimal:
        completed = [e for e in self._entries if not e.is_reservation]
        return self._cost_of(completed)

    def unresolved_reservations(self) -> list[CostEntry]:
        reconciled_ids = {
            e.request_id
            for e in self._entries
            if not e.is_reservation and e.request_id is not None
        }
        return [
            e
            for e in self._entries
            if e.is_reservation
            and e.request_id is not None
            and e.request_id not in reconciled_ids
        ]

    def total_unresolved_reservations_usd(self) -> Decimal:
        total = Decimal("0")
        for res in self.unresolved_reservations():
            if res.reserved_cost_usd is not None:
                total += res.reserved_cost_usd
        return total.quantize(USD_PLACES, rounding=ROUND_HALF_UP)

    def total_budget_committed_usd(self) -> Decimal:
        return self.total_observed_cost_usd() + self.total_unresolved_reservations_usd()

    def exceeds_budget(
        self, budget_usd: Decimal, include_reservations: bool = True
    ) -> bool:
        """Report whether measured spend has passed a configured allowance."""
        if include_reservations:
            return self.total_budget_committed_usd() > budget_usd
        return self.total_observed_cost_usd() > budget_usd

    def extend(self, entries: Iterable[CostEntry]) -> None:
        for entry in entries:
            price_for(entry.model_id, self._price_book)
            if entry.request_id is not None and any(
                prior.request_id == entry.request_id
                and prior.is_reservation == entry.is_reservation
                for prior in self._entries
            ):
                raise ValueError(f"Duplicate cost entry for request {entry.request_id}")
            self._entries.append(entry)

    def entry_cost_usd(self, entry: CostEntry) -> Decimal:
        return cost_usd(
            entry.model_id,
            entry.input_tokens,
            entry.output_tokens,
            self._price_book,
        )

    def cost_by_phase(self) -> dict[WorkflowPhase, Decimal]:
        """Return total cost per phase, so the AI spend can be attributed."""

        grouped: dict[WorkflowPhase, list[CostEntry]] = defaultdict(list)
        for entry in self._entries:
            if not entry.is_reservation:
                grouped[entry.phase].append(entry)
        return {
            phase: self._cost_of(entries) for phase, entries in sorted(grouped.items())
        }

    def build_report(self) -> CostReport:
        """Build the per-workflow cost table."""

        completed_entries = [e for e in self._entries if not e.is_reservation]
        grouped: dict[str, list[CostEntry]] = defaultdict(list)
        for entry in completed_entries:
            grouped[entry.workflow].append(entry)

        rows = tuple(
            self._build_row(workflow, entries)
            for workflow, entries in sorted(grouped.items())
        )
        return CostReport(
            rows=rows,
            total_cost_usd=self._cost_of(completed_entries),
            total_input_tokens=sum(e.input_tokens for e in completed_entries),
            total_output_tokens=sum(e.output_tokens for e in completed_entries),
            total_requests=len(completed_entries),
            total_runs=len({e.run_id for e in completed_entries}),
            sources=self._sources_of(completed_entries),
            price_sources=self._price_sources(),
            generated_at=self._clock(),
        )

    def _build_row(
        self, workflow: str, entries: Sequence[CostEntry]
    ) -> WorkflowCostRow:
        runs = len({entry.run_id for entry in entries})
        total_cost = self._cost_of(entries)
        cost_per_run = (
            (total_cost / runs).quantize(USD_PLACES, rounding=ROUND_HALF_UP)
            if runs
            else Decimal("0").quantize(USD_PLACES)
        )
        return WorkflowCostRow(
            workflow=workflow,
            runs=runs,
            requests=len(entries),
            input_tokens=sum(entry.input_tokens for entry in entries),
            output_tokens=sum(entry.output_tokens for entry in entries),
            images=sum(entry.image_count for entry in entries),
            total_cost_usd=total_cost,
            cost_per_run_usd=cost_per_run,
            model_ids=tuple(sorted({entry.model_id for entry in entries})),
            sources=self._sources_of(entries),
        )

    def _cost_of(self, entries: Sequence[CostEntry]) -> Decimal:
        """Sum tokens per model first, then price once, to avoid drift."""

        tokens_by_model: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for entry in entries:
            totals = tokens_by_model[entry.model_id]
            totals[0] += entry.input_tokens
            totals[1] += entry.output_tokens

        total = Decimal("0")
        for model_id, (input_tokens, output_tokens) in sorted(tokens_by_model.items()):
            total += cost_usd(model_id, input_tokens, output_tokens, self._price_book)
        return total.quantize(USD_PLACES, rounding=ROUND_HALF_UP)

    @staticmethod
    def _sources_of(entries: Sequence[CostEntry]) -> tuple[UsageSource, ...]:
        return tuple(sorted({entry.source for entry in entries}))

    def _price_sources(self) -> tuple[str, ...]:
        model_ids = {entry.model_id for entry in self._entries}
        sources = {
            price_for(model_id, self._price_book).price_source for model_id in model_ids
        }
        return tuple(sorted(sources))


class CostLedgerStore:
    """Appends cost entries to a newline-delimited JSON file.

    The format matches the append-only evidence log the scan store already
    uses, so a ledger survives a restart and a later run can be appended to an
    earlier measurement rather than replacing it.
    """

    def __init__(self, ledger_path: Path) -> None:
        self._ledger_path = ledger_path

    @property
    def ledger_path(self) -> Path:
        return self._ledger_path

    def append(self, entry: CostEntry) -> None:
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self._ledger_path.open("a", encoding="utf-8") as ledger_file:
            ledger_file.write(entry.model_dump_json() + "\n")

    def append_all(self, entries: Iterable[CostEntry]) -> None:
        for entry in entries:
            self.append(entry)

    def load(self) -> list[CostEntry]:
        if not self._ledger_path.exists():
            return []

        entries: list[CostEntry] = []
        with self._ledger_path.open(encoding="utf-8") as ledger_file:
            for line_number, line in enumerate(ledger_file, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entries.append(CostEntry.model_validate_json(stripped))
                except ValueError as error:
                    raise ValueError(
                        f"{self._ledger_path}: line {line_number} is not a "
                        f"valid cost entry: {error}"
                    ) from error
        return entries

    def load_into(
        self,
        price_book: dict[str, ModelPrice] | None = None,
        clock: Clock = _utc_now,
    ) -> CostLedger:
        ledger = CostLedger(price_book=price_book, clock=clock)
        ledger.extend(self.load())
        return ledger


def format_usd(amount: Decimal) -> str:
    """Render money for a table without dropping small Bedrock amounts."""

    return f"${amount.quantize(USD_PLACES, rounding=ROUND_HALF_UP)}"


def report_to_dict(report: CostReport) -> dict[str, object]:
    """Return the report as plain data for JSON export or a table renderer."""

    return {
        "generated_at": report.generated_at.isoformat(),
        "provenance": report.provenance_note(),
        "sources": [source.value for source in report.sources],
        "price_sources": list(report.price_sources),
        "total_runs": report.total_runs,
        "total_requests": report.total_requests,
        "total_input_tokens": report.total_input_tokens,
        "total_output_tokens": report.total_output_tokens,
        "total_cost_usd": str(report.total_cost_usd),
        "rows": [
            {
                "workflow": row.workflow,
                "runs": row.runs,
                "requests": row.requests,
                "input_tokens": row.input_tokens,
                "output_tokens": row.output_tokens,
                "images": row.images,
                "total_cost_usd": str(row.total_cost_usd),
                "cost_per_run_usd": str(row.cost_per_run_usd),
                "model_ids": list(row.model_ids),
                "sources": [source.value for source in row.sources],
            }
            for row in report.rows
        ],
    }


def report_to_json(report: CostReport) -> str:
    return json.dumps(report_to_dict(report), indent=2, sort_keys=True)
