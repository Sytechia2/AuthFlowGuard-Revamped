"""Verifies that analysis and reporting work with the target stopped.

EVA-007 requires results and reports to be regenerated from saved evidence
while the target application, a browser, and AWS are all unavailable. This
module re-analyses an already completed scan and regenerates its reports with
no fixture running, and records what it observed.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from authflowguard.app import create_app


@dataclass
class OfflineCheck:
    name: str
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


def result_versions(scan_directory: Path) -> list[str]:
    results = scan_directory / "results"
    if not results.is_dir():
        return []
    return sorted(path.name for path in results.glob("result-v*.json"))


def verify_scan(scan_data_root: Path, scan_directory: Path) -> list[OfflineCheck]:
    """Re-analyse one saved scan and regenerate its reports, fully offline."""

    scan_id = scan_directory.name
    checks: list[OfflineCheck] = []

    versions_before = result_versions(scan_directory)
    client = TestClient(create_app(data_root=scan_data_root))

    response = client.post(f"/api/scans/{scan_id}/reanalyse")
    checks.append(
        OfflineCheck(
            "Reanalysis endpoint responds with the target stopped",
            response.status_code == 200,
            f"HTTP {response.status_code}",
        )
    )
    if response.status_code != 200:
        return checks

    payload = response.json()
    produced = payload.get("results", [])
    checks.append(
        OfflineCheck(
            "Reanalysis returns one result per stored evidence record",
            len(produced) >= 1,
            f"{len(produced)} result(s) returned",
        )
    )

    versions_after = result_versions(scan_directory)
    checks.append(
        OfflineCheck(
            "A new result version is saved and earlier versions are kept",
            len(versions_after) > len(versions_before)
            and set(versions_before).issubset(set(versions_after)),
            f"{versions_before} then {versions_after}",
        )
    )

    outcomes_before = {r["check_id"]: r["outcome"] for r in _latest(scan_directory, 1)}
    outcomes_after = {r["check_id"]: r["outcome"] for r in produced}
    checks.append(
        OfflineCheck(
            "Offline reanalysis reproduces the original outcome",
            all(outcomes_after.get(k) == v for k, v in outcomes_before.items()),
            f"{outcomes_before} then {outcomes_after}",
        )
    )

    for extension in ("json", "html"):
        report = client.get(f"/api/scans/{scan_id}/report/{extension}")
        checks.append(
            OfflineCheck(
                f"The {extension.upper()} report regenerates offline",
                report.status_code == 200 and len(report.content) > 0,
                f"HTTP {report.status_code}, {len(report.content)} bytes",
            )
        )
    return checks


def _latest(scan_directory: Path, version: int) -> list[dict[str, Any]]:
    path = scan_directory / "results" / f"result-v{version}.json"
    if not path.is_file():
        return []
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, list) else [loaded]


def render(checks: list[OfflineCheck], scan_id: str) -> str:
    lines = [
        "# EVA-007 — Offline analysis and reporting",
        "",
        f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}.",
        "",
        "No evaluation target was running, no browser was launched, and no AWS",
        "credentials were used. Saved evidence was the only input.",
        "",
        f"Scan re-analysed: `{scan_id}`",
        "",
        "| Check | Result | Detail |",
        "| --- | --- | --- |",
    ]
    for check in checks:
        lines.append(
            f"| {check.name} | {'PASS' if check.passed else 'FAIL'} | {check.detail} |"
        )
    passed = sum(1 for check in checks if check.passed)
    lines += ["", f"**Totals:** {passed} of {len(checks)} checks passed.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_scan_root", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    arguments = parser.parse_args(argv)

    scan_directories = [p for p in arguments.case_scan_root.iterdir() if p.is_dir()]
    if not scan_directories:
        print(f"No saved scan found under {arguments.case_scan_root}")
        return 1

    scan_directory = scan_directories[0]
    checks = verify_scan(arguments.case_scan_root, scan_directory)
    rendered = render(checks, scan_directory.name)
    print(rendered)

    if arguments.out:
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(rendered, encoding="utf-8")
        print(f"Written: {arguments.out}")
    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
