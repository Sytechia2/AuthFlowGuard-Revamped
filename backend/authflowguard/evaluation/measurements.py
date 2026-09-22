"""Measures what a scan consumed, from saved evidence only.

EVA-008 asks for browser request counts, model usage, cost, and durations.
Model usage and cost need live Bedrock calls, which scans started from the web
interface do not make; those stay unmeasured and are reported as such. Browser
request volume and scan duration are recorded in saved evidence and are
measured here.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScanMeasurement:
    case_id: str
    check_id: str
    application: str
    duration_seconds: float
    browser_requests: int
    responses: int
    events: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "check_id": self.check_id,
            "application": self.application,
            "duration_seconds": self.duration_seconds,
            "browser_requests": self.browser_requests,
            "responses": self.responses,
            "events": self.events,
        }


def count_events(events_path: Path) -> tuple[int, int, int]:
    """Return request, response and total event counts for one scan."""

    requests = responses = total = 0
    if not events_path.is_file():
        return 0, 0, 0
    with events_path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            total += 1
            try:
                kind = json.loads(stripped).get("kind")
            except json.JSONDecodeError:
                continue
            if kind == "request":
                requests += 1
            elif kind == "response":
                responses += 1
    return requests, responses, total


def measure_run(results_path: Path, scan_data_root: Path) -> list[ScanMeasurement]:
    """Measure every live case recorded in one results file."""

    document = json.loads(results_path.read_text(encoding="utf-8"))
    measurements: list[ScanMeasurement] = []
    for row in document["results"]:
        if row.get("execution_mode") != "live_scan" or not row.get("scan_id"):
            continue
        events_path = (
            scan_data_root / str(row["case_id"]) / str(row["scan_id"]) / "events.ndjson"
        )
        requests, responses, total = count_events(events_path)
        measurements.append(
            ScanMeasurement(
                case_id=str(row["case_id"]),
                check_id=str(row["check_id"]),
                application=str(row["application"]),
                duration_seconds=float(row.get("duration_seconds") or 0.0),
                browser_requests=requests,
                responses=responses,
                events=total,
            )
        )
    return sorted(measurements, key=lambda m: m.case_id)


def render(measurements: list[ScanMeasurement]) -> str:
    lines = [
        "# EVA-008 — Measured consumption",
        "",
        f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} from saved",
        "evidence. One scan per case, single run each.",
        "",
        "## What is measured and what is not",
        "",
        "| Quantity | State |",
        "| --- | --- |",
        "| Browser request volume | Measured, from the saved event log |",
        "| Scan duration | Measured, wall clock per case |",
        "| Model input/output tokens | **Not measured** — no Bedrock calls |",
        "| Estimated cost before credits | **Not measured** — no model calls |",
        "",
        "Cost accounting is implemented and tested in",
        "`authflowguard.evaluation.cost_model` and `cost_tracking`. It reuses the",
        "production price table and labels every figure as live or mock, so it can",
        "produce a cost table as soon as real model calls exist. No projected",
        "figure appears here, because a projection is not a measurement.",
        "",
        "## Per-case measurements",
        "",
        "| Case | Check | App | Duration (s) | Browser requests | Responses | Events |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for m in measurements:
        lines.append(
            f"| {m.case_id} | {m.check_id} | {m.application} | "
            f"{m.duration_seconds:.2f} | {m.browser_requests} | {m.responses} | "
            f"{m.events} |"
        )

    if measurements:
        total_time = sum(m.duration_seconds for m in measurements)
        total_requests = sum(m.browser_requests for m in measurements)
        count = len(measurements)
        lines += [
            "",
            f"**Totals across {count} live scans:** {total_time:.1f} s, "
            f"{total_requests} browser requests.",
            "",
            f"**Averages:** {total_time / count:.2f} s and "
            f"{total_requests / count:.1f} browser requests per scan.",
            "",
        ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "runs",
        nargs="+",
        help="Run identifiers under --results-root, e.g. A-live-001 C-002",
    )
    parser.add_argument("--results-root", type=Path, default=Path("evaluation/results"))
    parser.add_argument("--out", type=Path, default=None)
    arguments = parser.parse_args(argv)

    measurements: list[ScanMeasurement] = []
    for run in arguments.runs:
        run_directory = arguments.results_root / run
        measurements.extend(
            measure_run(run_directory / "results.json", run_directory / "scan-data")
        )

    rendered = render(sorted(measurements, key=lambda m: m.case_id))
    print(rendered)
    if arguments.out:
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(rendered, encoding="utf-8")
        print(f"Written: {arguments.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
