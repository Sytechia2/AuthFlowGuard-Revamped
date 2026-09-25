"""Offline JSON and printable HTML report rendering."""

import html
import json
from collections.abc import Iterable, Mapping
from typing import Any
from uuid import UUID

from authflowguard.evidence import EvidenceStore
from authflowguard.models import CheckResult, TestRunEvidence

CHECK_CODES = {
    "login_enumeration": "CHK-001",
    "registration_enumeration": "CHK-002",
    "reset_request_enumeration": "CHK-003",
    "login_throttling": "CHK-004",
    "session_fixation": "CHK-005",
    "logout_invalidation": "CHK-006",
}


def build_json_report(
    metadata: Mapping[str, Any],
    evidence: Iterable[TestRunEvidence],
    results: Iterable[CheckResult | Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a complete report using only saved local models."""

    return {
        "metadata": dict(metadata),
        "evidence": [item.model_dump(mode="json") for item in evidence],
        "results": [
            item.model_dump(mode="json")
            if isinstance(item, CheckResult)
            else dict(item)
            for item in results
        ],
    }


def write_json_report(
    path: str,
    metadata: Mapping[str, Any],
    evidence: Iterable[TestRunEvidence],
    results: Iterable[CheckResult | Mapping[str, Any]],
) -> None:
    report = build_json_report(metadata, evidence, results)
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def write_html_report(
    path: str,
    metadata: Mapping[str, Any],
    evidence: Iterable[TestRunEvidence],
    results: Iterable[CheckResult | Mapping[str, Any]],
) -> None:
    report = build_json_report(metadata, evidence, results)
    results_html = (
        "".join(_result_html(result) for result in report["results"])
        or "<p>No results have been saved.</p>"
    )
    limitations = "<p>No coverage limitations recorded.</p>"
    all_limitations = [
        limitation
        for item in report["evidence"]
        for limitation in item.get("coverage", {}).get("limitations", [])
    ]
    if all_limitations:
        limitations = (
            "<ul>"
            + "".join(
                f"<li>{html.escape(str(limitation))}</li>"
                for limitation in all_limitations
            )
            + "</ul>"
        )
    cancellation_notice = (
        "<p><strong>Execution was cancelled; unfinished checks have no security "
        "outcome.</strong></p>"
        if report["metadata"].get("state") == "cancelled"
        else ""
    )
    usage = report["metadata"].get("usage", {})
    usage_html = "<p>Usage accounting unavailable.</p>"
    if isinstance(usage, Mapping) and not usage.get("accounting_error"):
        input_tokens = html.escape(str(usage.get("input_tokens", 0)))
        output_tokens = html.escape(str(usage.get("output_tokens", 0)))
        settled_cost = html.escape(str(usage.get("settled_cost_usd", "0.00000000")))
        reserved_cost = html.escape(
            str(usage.get("outstanding_reserved_cost_usd", "0.00000000"))
        )
        budget_limit = html.escape(str(usage.get("limit_usd", "unknown")))
        uncertain = html.escape(str(usage.get("uncertain_requests", 0)))
        usage_source = html.escape(str(usage.get("usage_source", "none")))
        usage_html = (
            "<ul>"
            f"<li>Usage source: {usage_source}</li>"
            f"<li>Input tokens: {input_tokens}</li>"
            f"<li>Output tokens: {output_tokens}</li>"
            f"<li>Settled estimated cost (USD): {settled_cost}</li>"
            f"<li>Outstanding reserved cost (USD): {reserved_cost}</li>"
            f"<li>Budget limit (USD): {budget_limit}</li>"
            f"<li>Uncertain requests: {uncertain}</li>"
            "</ul>"
        )
    document = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>AuthFlowGuard report</title>
<style>
body {{ font: 16px system-ui, sans-serif; max-width: 900px;
margin: 2rem auto; }}
section {{ border: 1px solid #ccd3dd; border-radius: .5rem;
padding: 1rem;
margin: 1rem 0; }}
.finding_confirmed {{ color: #9b1c1c; }}
.no_issue_observed {{ color: #176b37; }}
</style>
</head><body><h1>AuthFlowGuard security report</h1>
<p>Scan: {html.escape(str(report["metadata"].get("scan_id", "unknown")))}</p>
<p>Execution status: {html.escape(str(report["metadata"].get("state", "unknown")))}</p>
{cancellation_notice}
<h2>AI usage and estimated cost</h2>{usage_html}
<h2>Results</h2>{results_html}
<h2>Coverage limitations</h2>{limitations}
<h2>Saved evidence</h2><p>{len(report["evidence"])} evidence package(s) are
available for offline review.</p>
</body></html>
"""
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(document)


def export_scan_reports(
    store: EvidenceStore,
    scan_id: UUID,
    evidence: Iterable[TestRunEvidence],
    results: Iterable[CheckResult | Mapping[str, Any]],
) -> tuple[str, str]:
    """Write JSON and HTML reports below the selected scan directory."""

    scan_dir = store.create_scan(scan_id)
    metadata = store.read_metadata(scan_id)
    json_path = scan_dir / "report.json"
    html_path = scan_dir / "report.html"
    write_json_report(str(json_path), metadata, evidence, results)
    write_html_report(str(html_path), metadata, evidence, results)
    return str(json_path), str(html_path)


def _result_html(result: Mapping[str, Any]) -> str:
    outcome = str(result.get("outcome", "unknown"))
    explanation = html.escape(str(result.get("explanation", "")))
    check_id = html.escape(str(result.get("check_id", "unknown")))
    check_code = CHECK_CODES.get(str(result.get("check_id")), "")
    reference = html.escape(str(result.get("owasp_reference", "")))
    return (
        f'<section><h3 class="{html.escape(outcome)}">{check_code} {check_id}</h3>'
        f"<p><strong>Outcome:</strong> {html.escape(outcome)}</p>"
        f"<p><strong>OWASP:</strong> {reference}</p><p>{explanation}</p></section>"
    )
