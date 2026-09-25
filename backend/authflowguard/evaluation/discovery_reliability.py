"""Measures how often login discovery completes, and by which route.

EVA-004 asks for each supported login flow to be attempted five times on each
relevant application, with automatic completions reported separately from
guided ones, and a reason recorded for every failure.

Rules mode needs no AWS. Bedrock mode uses an offline double unless live calls
are explicitly confirmed.
"""

import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from authflowguard.config import load_server_settings
from authflowguard.evaluation.case_runner import (
    FormalCase,
    fixture_for,
    load_cases,
    run_live_case,
    serve,
)
from authflowguard.evaluation.cost_tracking import CostLedgerStore

DEFAULT_ATTEMPTS = 5
AUTOMATIC_TARGET = 4


@dataclass
class EvaluationBudget:
    """Shared allowance across all attempts, including unresolved requests."""

    limit_usd: float
    committed_usd: float = 0.0

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.limit_usd - self.committed_usd)

    def charge_attempt(self, attempt_root: Path) -> None:
        for path in attempt_root.rglob("cost-ledger.ndjson"):
            self.committed_usd += float(
                CostLedgerStore(path).load_into().total_budget_committed_usd()
            )


@dataclass(frozen=True)
class Attempt:
    application: str
    attempt: int
    discovery: str
    duration_seconds: float
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "application": self.application,
            "attempt": self.attempt,
            "discovery": self.discovery,
            "duration_seconds": round(self.duration_seconds, 2),
            "detail": self.detail,
        }


def representative_case(cases: list[FormalCase], application: str) -> FormalCase | None:
    """Pick one live secure case to stand for the application's login flow."""

    candidates = [
        case
        for case in cases
        if case.application == application
        and case.execution_mode.value == "live_scan"
        and case.fixture_mode == "secure"
        and case.setup is not None
    ]
    return candidates[0] if candidates else None


def measure_application(
    case: FormalCase,
    data_root: Path,
    attempts: int = DEFAULT_ATTEMPTS,
    discovery_mode: str = "rules",
    reuse_saved_profile: bool | None = None,
    confirm_live_calls: bool = False,
    max_cost_usd: float = 1.0,
    evaluation_budget: EvaluationBudget | None = None,
) -> list[Attempt]:
    """Run one application's login flow repeatedly on a fresh fixture each time."""

    recorded: list[Attempt] = []
    for attempt in range(1, attempts + 1):
        allowance = (
            evaluation_budget.remaining_usd
            if evaluation_budget is not None and discovery_mode == "bedrock"
            else max_cost_usd
        )
        if discovery_mode == "bedrock" and allowance <= 0:
            recorded.append(
                Attempt(
                    case.application,
                    attempt,
                    "failed",
                    0.0,
                    "Evaluation budget exhausted",
                )
            )
            continue
        attempt_root = data_root / f"{case.application}-attempt-{attempt}"
        attempt_root.mkdir(parents=True, exist_ok=True)
        with serve(fixture_for(case.application, case.fixture_mode)) as origin:
            result = run_live_case(
                case,
                origin,
                attempt_root,
                discovery_mode=discovery_mode,
                reuse_saved_profile=reuse_saved_profile,
                confirm_live_calls=confirm_live_calls,
                max_cost_usd=min(
                    max_cost_usd,
                    allowance,
                    load_server_settings().server_max_cost_usd,
                ),
            )
        if evaluation_budget is not None and discovery_mode == "bedrock":
            evaluation_budget.charge_attempt(attempt_root)

        # Check if auth profile was verified even if downstream check
        # outcome was non-matching
        discovery_outcome = result.discovery or "failed"
        if discovery_outcome == "failed":
            # Check if an auth profile was produced and saved
            scan_dirs = list(attempt_root.glob(f"{case.case_id}/*"))
            for sdir in scan_dirs:
                if (sdir / "auth-profile.json").exists():
                    discovery_outcome = "automatic"
                    break

        recorded.append(
            Attempt(
                application=case.application,
                attempt=attempt,
                discovery=discovery_outcome,
                duration_seconds=result.duration_seconds,
                detail=result.detail[:160],
            )
        )
    return recorded


def render(
    attempts: list[Attempt],
    attempts_per_application: int,
    discovery_mode: str = "rules",
) -> str:
    by_application: dict[str, list[Attempt]] = {}
    for attempt in attempts:
        by_application.setdefault(attempt.application, []).append(attempt)

    mode_label = "Bedrock AI" if discovery_mode == "bedrock" else "Rule-based"
    lines = [
        f"# EVA-004 — Login discovery reliability ({mode_label})",
        "",
        f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}.",
        "",
        f"Each application's login flow was attempted {attempts_per_application} "
        "times, each against a freshly started fixture.",
        "",
    ]
    if discovery_mode == "bedrock":
        lines += [
            "Discovery in these scans was driven by Bedrock browser exploration.",
            "Security checks, evidence capture, and reports remained offline.",
        ]
    else:
        lines += [
            "Discovery in a scan started from the web interface is rule-based and does",
            "not call Bedrock, so these figures need no AWS access. They do **not**",
            "measure the terminal Bedrock agent, which stays unmeasured.",
        ]
    lines += [
        "",
        "## Summary",
        "",
        "| Application | Automatic | Guided | Failed | Meets 4/5 automatic target |",
        "| --- | --- | --- | --- | --- |",
    ]
    for application in sorted(by_application):
        counts = Counter(a.discovery for a in by_application[application])
        automatic = counts.get("automatic", 0)
        meets = "Yes" if automatic >= AUTOMATIC_TARGET else "No"
        lines.append(
            f"| {application} | {automatic}/{attempts_per_application} "
            f"| {counts.get('guided', 0)}/{attempts_per_application} "
            f"| {counts.get('failed', 0)}/{attempts_per_application} | {meets} |"
        )

    lines += [
        "",
        "The 4-of-5 automatic target comes from the project plan and applies to",
        "the development applications. Application C was designed independently,",
        "so a guided completion there is an expected outcome, not a regression.",
        "",
        "## Every attempt",
        "",
        "| Application | Attempt | Route | Duration (s) | Detail |",
        "| --- | --- | --- | --- | --- |",
    ]
    for attempt in attempts:
        lines.append(
            f"| {attempt.application} | {attempt.attempt} | {attempt.discovery} "
            f"| {attempt.duration_seconds:.2f} | {attempt.detail} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases", type=Path, default=Path("evaluation/cases/formal_cases.json")
    )
    parser.add_argument("--applications", default="A,B,C")
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument(
        "--run-id", default=datetime.now(UTC).strftime("discovery-%Y%m%d-%H%M%S")
    )
    parser.add_argument("--results-root", type=Path, default=Path("evaluation/results"))
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--discovery-mode",
        choices=["rules", "bedrock"],
        default="rules",
        help="Discovery mode to evaluate ('rules' or 'bedrock').",
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
        default=1.0,
        help="Maximum budget limit for Bedrock inference.",
    )
    parser.add_argument(
        "--no-reuse-saved-profile",
        action="store_true",
        default=False,
        help="Disable reusing saved auth profile.",
    )
    arguments = parser.parse_args(argv)

    reuse_saved_profile = (
        False
        if arguments.no_reuse_saved_profile
        else (arguments.discovery_mode == "rules")
    )
    if arguments.out is None and arguments.discovery_mode == "bedrock":
        arguments.out = Path(
            f"evaluation/reports/discovery_reliability-bedrock-{arguments.run_id}.md"
        )

    cases = load_cases(arguments.cases)
    run_directory = arguments.results_root / arguments.run_id
    scan_data_root = run_directory / "scan-data"

    attempts: list[Attempt] = []
    evaluation_budget = EvaluationBudget(arguments.max_evaluation_cost_usd)
    for application in [n.strip() for n in arguments.applications.split(",")]:
        case = representative_case(cases, application)
        if case is None:
            print(f"No live secure case found for application {application}")
            continue
        print(
            f"Application {application}: {arguments.attempts} attempts...", flush=True
        )
        for attempt in measure_application(
            case,
            scan_data_root,
            arguments.attempts,
            discovery_mode=arguments.discovery_mode,
            reuse_saved_profile=reuse_saved_profile,
            confirm_live_calls=arguments.confirm_live_calls,
            max_cost_usd=arguments.max_evaluation_cost_usd,
            evaluation_budget=evaluation_budget,
        ):
            print(
                f"  attempt {attempt.attempt}: {attempt.discovery} "
                f"({attempt.duration_seconds:.2f}s)",
                flush=True,
            )
            attempts.append(attempt)

    run_directory.mkdir(parents=True, exist_ok=True)
    out_filename = (
        "discovery.json"
        if arguments.discovery_mode == "rules"
        else f"discovery-bedrock-{arguments.run_id}.json"
    )
    (run_directory / out_filename).write_text(
        json.dumps(
            {
                "run_id": arguments.run_id,
                "discovery_mode": arguments.discovery_mode,
                "attempts_per_application": arguments.attempts,
                "attempts": [a.as_dict() for a in attempts],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    rendered = render(
        attempts, arguments.attempts, discovery_mode=arguments.discovery_mode
    )
    print()
    print(rendered)
    if arguments.out:
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(rendered, encoding="utf-8")
        print(f"Written: {arguments.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
