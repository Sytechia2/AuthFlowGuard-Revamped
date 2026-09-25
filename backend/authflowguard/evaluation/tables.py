"""Renders executed evaluation results as tables fit for the submission.

Tables are generated from saved result files, never typed by hand, so a
published row cannot drift from the run it claims to describe. Rows are sorted
deterministically, so regenerating a table produces a byte-identical file.
"""

import csv
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

VERDICT_SYMBOL = {"pass": "PASS", "fail": "FAIL", "blocked": "BLOCKED", "not_run": "-"}


@dataclass(frozen=True)
class MergedRun:
    """Every result produced for one case file, across several run files."""

    rows: tuple[dict[str, Any], ...]
    source_runs: tuple[str, ...]

    @property
    def totals(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for row in self.rows:
            verdict = str(row["verdict"])
            totals[verdict] = totals.get(verdict, 0) + 1
        return totals


def merge_result_files(paths: list[Path]) -> MergedRun:
    """Combine result files, keeping the last result recorded for each case."""

    by_case: dict[str, dict[str, Any]] = {}
    runs: list[str] = []
    for path in sorted(paths):
        document = json.loads(path.read_text(encoding="utf-8"))
        runs.append(str(document.get("run_id", path.parent.name)))
        for row in document["results"]:
            by_case[str(row["case_id"])] = row
    ordered = tuple(by_case[key] for key in sorted(by_case))
    return MergedRun(rows=ordered, source_runs=tuple(runs))


def render_markdown(merged: MergedRun, title: str) -> str:
    """Render the results as a Markdown table for the report."""

    lines = [
        f"# {title}",
        "",
        f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} from "
        f"{', '.join(merged.source_runs)}.",
        "",
        "| Case | Check | Mode | Expected | Actual | Verdict | Evidence |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in merged.rows:
        evidence = str(row.get("evidence_id") or "-")
        short_evidence = evidence[:8] if evidence != "-" else "-"
        lines.append(
            f"| {row['case_id']} | {row['check_id']} | {row['execution_mode']} "
            f"| {row['expected_outcome']} | {row['actual_outcome']} "
            f"| {VERDICT_SYMBOL.get(str(row['verdict']), row['verdict'])} "
            f"| `{short_evidence}` |"
        )

    totals = merged.totals
    summary = ", ".join(f"{count} {name}" for name, count in sorted(totals.items()))
    lines += ["", f"**Totals:** {len(merged.rows)} cases — {summary}.", ""]
    return "\n".join(lines)


def render_csv(merged: MergedRun) -> str:
    """Render the same rows as CSV for a spreadsheet or appendix."""

    fields = [
        "case_id",
        "check_id",
        "application",
        "execution_mode",
        "expected_outcome",
        "actual_outcome",
        "verdict",
        "scan_id",
        "evidence_id",
        "duration_seconds",
    ]
    buffer = StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    for row in merged.rows:
        writer.writerow(row)
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--title", default="Formal security-check evaluation")
    parser.add_argument("--out-dir", type=Path, default=Path("evaluation/reports"))
    parser.add_argument("--name", default="formal-cases")
    arguments = parser.parse_args(argv)

    merged = merge_result_files(list(arguments.results))
    arguments.out_dir.mkdir(parents=True, exist_ok=True)

    markdown_path = arguments.out_dir / f"{arguments.name}.md"
    csv_path = arguments.out_dir / f"{arguments.name}.csv"
    markdown_path.write_text(render_markdown(merged, arguments.title), encoding="utf-8")
    csv_path.write_text(render_csv(merged), encoding="utf-8")

    print(render_markdown(merged, arguments.title))
    print(f"Written: {markdown_path}")
    print(f"Written: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
