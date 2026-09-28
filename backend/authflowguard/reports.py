"""Offline JSON and printable HTML report rendering."""

import html
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from authflowguard.evidence import EvidenceStore
from authflowguard.models import CheckOutcome, CheckResult, TestRunEvidence


@dataclass(frozen=True)
class CheckReportInfo:
    code: str
    title: str
    failure_severity: str
    recommendation: str


# Severity applies only when a finding is confirmed; the analysers decide
# outcomes, and this table only describes what a confirmed finding means.
CHECK_REPORT_INFO = {
    "login_enumeration": CheckReportInfo(
        code="CHK-001",
        title="Login Enumeration",
        failure_severity="MEDIUM",
        recommendation=(
            "OWASP WSTG-IDNT-04: Return indistinguishable login failure responses "
            "(status, message, body size, headers, and timing) for valid and "
            "invalid accounts."
        ),
    ),
    "registration_enumeration": CheckReportInfo(
        code="CHK-002",
        title="Registration Enumeration",
        failure_severity="MEDIUM",
        recommendation=(
            "OWASP WSTG-IDNT-04: Prevent account enumeration during registration "
            "by returning generic responses and avoiding account-exists disclosure."
        ),
    ),
    "reset_request_enumeration": CheckReportInfo(
        code="CHK-003",
        title="Password Reset Enumeration",
        failure_severity="MEDIUM",
        recommendation=(
            "OWASP WSTG-IDNT-04: Use generic password reset responses and "
            "identical behavior regardless of whether an account exists."
        ),
    ),
    "login_throttling": CheckReportInfo(
        code="CHK-004",
        title="Rate Limiting",
        failure_severity="HIGH",
        recommendation=(
            "OWASP WSTG-ATHN-03: Implement rate limiting, lockout, and abuse "
            "monitoring for authentication endpoints."
        ),
    ),
    "session_fixation": CheckReportInfo(
        code="CHK-005",
        title="Session Fixation",
        failure_severity="HIGH",
        recommendation=(
            "OWASP WSTG-SESS-03: Regenerate session identifiers after "
            "authentication and prevent fixation of pre-authenticated sessions."
        ),
    ),
    "logout_invalidation": CheckReportInfo(
        code="CHK-006",
        title="Logout Invalidation",
        failure_severity="CRITICAL",
        recommendation=(
            "OWASP WSTG-SESS-06: Invalidate server-side session state on logout "
            "and ensure replayed tokens/cookies no longer grant authenticated "
            "access."
        ),
    ),
}

STATUS_LABELS = {
    CheckOutcome.FINDING_CONFIRMED.value: "FAIL",
    CheckOutcome.NO_ISSUE_OBSERVED.value: "PASS",
    CheckOutcome.INCONCLUSIVE.value: "INCONCLUSIVE",
    CheckOutcome.NOT_APPLICABLE.value: "N/A",
    CheckOutcome.UNSUPPORTED.value: "UNSUPPORTED",
    CheckOutcome.EXECUTION_ERROR.value: "ERROR",
}
NOT_RUN_STATUS = "NOT RUN"
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


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
    metadata = report["metadata"]
    rows = _check_rows(metadata, report["evidence"], report["results"])
    statuses = [row["status"] for row in rows]
    failures = sorted(
        (row for row in rows if row["status"] == "FAIL"),
        key=lambda row: SEVERITY_RANK.get(row["severity"], len(SEVERITY_RANK)),
    )

    cancellation_notice = (
        '<p class="notice"><strong>Execution was cancelled; unfinished checks '
        "have no security outcome.</strong></p>"
        if metadata.get("state") == "cancelled"
        else ""
    )
    overview_rows = "".join(
        "<tr>"
        f"<td>{_esc(row['code'])}</td>"
        f"<td>{_esc(row['title'])}</td>"
        f"<td>{_status_badge(row['status'])}</td>"
        f"<td>{_esc(row['severity'])}</td>"
        f"<td>{_esc(row['reference'])}</td>"
        f"<td>{_esc(row['recorded_at'])}</td>"
        "</tr>"
        for row in rows
    )
    overview = (
        (
            "<table><thead><tr><th>Code</th><th>Check</th><th>Status</th>"
            "<th>Severity</th><th>Reference</th><th>Recorded at</th></tr></thead>"
            f"<tbody>{overview_rows}</tbody></table>"
        )
        if rows
        else "<p>No results have been saved.</p>"
    )
    details = "".join(
        _check_section(number, row) for number, row in enumerate(rows, start=1)
    )

    document = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuthFlowGuard report</title>
<style>
body {{ font: 15px/1.5 system-ui, sans-serif; color: #1c2430; background: #fff;
max-width: 1000px; margin: 2rem auto; padding: 0 1rem; }}
h1 {{ margin-bottom: .25rem; }}
h2 {{ border-bottom: 2px solid #ccd3dd; padding-bottom: .25rem; margin-top: 2rem; }}
h4 {{ margin: 1rem 0 .25rem; }}
table {{ border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }}
th, td {{ border: 1px solid #ccd3dd; padding: .35rem .6rem; text-align: left;
vertical-align: top; overflow-wrap: anywhere; }}
th {{ background: #eef1f5; }}
table.fields td:first-child {{ width: 11rem; font-weight: 600; background: #f6f8fa; }}
section.check {{ border: 1px solid #ccd3dd; border-radius: .5rem; padding: 0 1rem 1rem;
margin: 1.25rem 0; break-inside: avoid-page; }}
pre {{ background: #f6f8fa; border: 1px solid #ccd3dd; border-radius: .35rem;
padding: .75rem; font-size: 12.5px; white-space: pre-wrap; overflow-wrap: anywhere; }}
.status {{ font-weight: 700; padding: .05rem .45rem; border-radius: .25rem; }}
.status-fail {{ color: #9b1c1c; background: #fde8e8; }}
.status-pass {{ color: #176b37; background: #e3f5ea; }}
.status-other {{ color: #6b4e00; background: #fdf3d8; }}
.notice {{ border-left: 4px solid #9b1c1c; padding-left: .75rem; }}
@media print {{ body {{ margin: 0; max-width: none; }} }}
</style>
</head><body>
<h1>AuthFlowGuard Security Report</h1>
<p><strong>Executive Summary:</strong> {_esc(_executive_summary(rows, failures))}</p>
{cancellation_notice}
<table class="fields"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>
{_scan_overview_rows(metadata, statuses, len(report["evidence"]))}
</tbody></table>
<h2>All Findings Overview</h2>{overview}
<h2>AI Usage and Estimated Cost</h2>{_usage_html(metadata.get("usage", {}))}
<h2>Analyst Details</h2>
<p>Detailed analysis per check with evidence snapshot.</p>
{details}
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


def _check_rows(
    metadata: Mapping[str, Any],
    evidence: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Join each selected check with its latest result and evidence package."""

    results_by_check = {str(result.get("check_id")): result for result in results}
    evidence_by_check = {str(item.get("check_id")): item for item in evidence}
    selected = metadata.get("selected_checks")
    check_ids = list(
        dict.fromkeys(
            [
                *(
                    str(check)
                    for check in (selected if isinstance(selected, list) else [])
                ),
                *results_by_check,
            ]
        )
    )
    order = list(CHECK_REPORT_INFO)
    check_ids.sort(
        key=lambda check: order.index(check) if check in order else len(order)
    )

    rows = []
    for check_id in check_ids:
        info = CHECK_REPORT_INFO.get(check_id)
        result = results_by_check.get(check_id)
        evidence_item = evidence_by_check.get(check_id)
        limitations = [
            *(result.get("coverage_limitations", []) if result else []),
            *(
                evidence_item.get("coverage", {}).get("limitations", [])
                if evidence_item
                else []
            ),
        ]
        outcome = str(result.get("outcome")) if result else None
        status = (
            STATUS_LABELS.get(outcome, outcome.upper()) if outcome else NOT_RUN_STATUS
        )
        if status == "FAIL":
            severity = info.failure_severity if info else "UNRATED"
        elif status == "PASS":
            severity = "INFO"
        else:
            severity = "N/A"
        rows.append(
            {
                "check_id": check_id,
                "code": info.code if info else "",
                "title": info.title if info else check_id,
                "status": status,
                "outcome": outcome or "not_run",
                "severity": severity,
                "summary": (
                    str(result.get("explanation", ""))
                    if result
                    else "No result was recorded for this check."
                ),
                "reference": str(result.get("owasp_reference", "")) if result else "",
                "recommendation": info.recommendation if info else "",
                "analyser_version": str(result.get("analyser_version", ""))
                if result
                else "",
                "recorded_at": str(result.get("created_at", "")) if result else "",
                "coverage_limitations": list(dict.fromkeys(limitations)),
                "evidence": evidence_item,
            }
        )
    return rows


def _executive_summary(
    rows: list[dict[str, Any]], failures: list[dict[str, Any]]
) -> str:
    total = len(rows)
    reported = sum(1 for row in rows if row["status"] != NOT_RUN_STATUS)
    failed = len(failures)
    passed = sum(1 for row in rows if row["status"] == "PASS")
    other = total - failed - passed
    high_or_critical = sum(
        1 for row in failures if row["severity"] in {"HIGH", "CRITICAL"}
    )
    priority = (
        "Priority checks requiring analyst attention: "
        + ", ".join(row["title"] for row in failures)
        + "."
        if failures
        else "No checks currently require priority attention."
    )
    return (
        f"The assessment reviewed {reported}/{total} selected authentication "
        f"security checks. {failed} check(s) failed, {passed} passed, and {other} "
        f"did not produce a pass/fail verdict. There are {high_or_critical} "
        f"high/critical failure(s). {priority}"
    )


def _scan_overview_rows(
    metadata: Mapping[str, Any], statuses: list[str], evidence_count: int
) -> str:
    target = metadata.get("target")
    target_url = target.get("target_url") if isinstance(target, Mapping) else target
    origins = target.get("permitted_origins", []) if isinstance(target, Mapping) else []
    provenance = metadata.get("provenance")
    discovery = str(metadata.get("discovery_mode", "unknown"))
    if isinstance(provenance, Mapping):
        engine = provenance.get("actual_engine") or "none"
        discovery = f"{discovery} (engine: {engine}"
        if provenance.get("model_id"):
            discovery += f", model: {provenance['model_id']}"
        if provenance.get("reused_profile"):
            discovery += ", reused saved profile"
        if provenance.get("guidance_used"):
            discovery += ", guidance used"
        discovery += ")"
    other = sum(1 for status in statuses if status not in {"PASS", "FAIL"})
    fields = [
        ("Generated at", datetime.now(UTC).isoformat(timespec="seconds")),
        ("Scan ID", metadata.get("scan_id", "unknown")),
        ("Target", target_url or "unknown"),
        ("Permitted origins", ", ".join(str(origin) for origin in origins) or "—"),
        ("Execution status", metadata.get("state", "unknown")),
        ("Started at", metadata.get("started_at") or "—"),
        ("Finished at", metadata.get("finished_at") or "—"),
        ("Discovery", discovery),
        ("Total checks", len(statuses)),
        ("PASS", statuses.count("PASS")),
        ("FAIL", statuses.count("FAIL")),
        ("No verdict", other),
        ("Evidence packages", evidence_count),
    ]
    return "".join(
        f"<tr><td>{_esc(name)}</td><td>{_esc(value)}</td></tr>"
        for name, value in fields
    )


def _usage_html(usage: Any) -> str:
    if not isinstance(usage, Mapping) or usage.get("accounting_error"):
        return "<p>Usage accounting unavailable.</p>"
    fields = [
        ("Usage source", usage.get("usage_source", "none")),
        ("Input tokens", usage.get("input_tokens", 0)),
        ("Output tokens", usage.get("output_tokens", 0)),
        ("Settled estimated cost (USD)", usage.get("settled_cost_usd", "0.00000000")),
        (
            "Outstanding reserved cost (USD)",
            usage.get("outstanding_reserved_cost_usd", "0.00000000"),
        ),
        ("Budget limit (USD)", usage.get("limit_usd", "unknown")),
        ("Uncertain requests", usage.get("uncertain_requests", 0)),
    ]
    return (
        '<table class="fields"><thead><tr><th>Field</th><th>Value</th></tr></thead>'
        "<tbody>"
        + "".join(
            f"<tr><td>{_esc(name)}</td><td>{_esc(value)}</td></tr>"
            for name, value in fields
        )
        + "</tbody></table>"
    )


def _check_section(number: int, row: Mapping[str, Any]) -> str:
    evidence = row["evidence"]
    fields = [
        ("Check", _esc(f"{row['code']} {row['check_id']}".strip())),
        ("Status", _status_badge(row["status"])),
        ("Severity", _esc(row["severity"])),
        ("Outcome", _esc(row["outcome"])),
        ("Summary", _esc(row["summary"])),
        ("Reference", _esc(row["reference"] or "—")),
        ("Recommendation", _esc(row["recommendation"] or "—")),
        ("Evidence package", _esc(evidence.get("evidence_id") if evidence else "—")),
        ("Analyser version", _esc(row["analyser_version"] or "—")),
        ("Recorded at", _esc(row["recorded_at"] or "—")),
    ]
    field_rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{value}</td></tr>" for name, value in fields
    )
    comparisons = evidence.get("control_comparisons", []) if evidence else []
    errors = evidence.get("errors", []) if evidence else []
    if evidence:
        observations = json.dumps(
            evidence.get("observations", {}), indent=2, sort_keys=True
        )
        snapshot = f"<pre>{_esc(observations)}</pre>"
    else:
        snapshot = "<p>No evidence package was saved for this check.</p>"
    return (
        f'<section class="check"><h3>{number}. {_esc(row["title"])}</h3>'
        '<table class="fields"><thead><tr><th>Field</th><th>Value</th></tr></thead>'
        f"<tbody>{field_rows}</tbody></table>"
        + _list_block("Controls compared", comparisons)
        + _list_block("Coverage limitations", row["coverage_limitations"])
        + _list_block("Execution errors", errors)
        + f"<h4>Evidence Snapshot</h4>{snapshot}</section>"
    )


def _list_block(heading: str, items: Iterable[Any]) -> str:
    entries = "".join(f"<li>{_esc(item)}</li>" for item in items)
    return f"<h4>{_esc(heading)}</h4><ul>{entries}</ul>" if entries else ""


def _status_badge(status: str) -> str:
    kind = {"FAIL": "fail", "PASS": "pass"}.get(status, "other")
    return f'<span class="status status-{kind}">{_esc(status)}</span>'


def _esc(value: Any) -> str:
    return html.escape(str(value))
