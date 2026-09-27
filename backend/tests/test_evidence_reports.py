"""Tests for local evidence persistence and offline report generation."""

import json
from pathlib import Path
from uuid import UUID, uuid4

from authflowguard import models
from authflowguard.evidence import (
    EvidenceStore,
    redact_persisted_data,
    transient_secret_redaction,
)
from authflowguard.models import (
    CheckId,
    CheckOutcome,
    CheckResult,
    EvidenceEvent,
    EvidenceKind,
)
from authflowguard.reports import export_scan_reports


def make_event(scan_id: UUID) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=uuid4(),
        scan_id=scan_id,
        kind=EvidenceKind.RESPONSE,
        summary="A response was observed.",
        redacted_details={
            "url": "https://app.example/account?token=query-secret#fragment",
            "password": "live-password",
            "headers": {"Authorization": "live-password"},
            "body": "live-password response body",
            "nested": "live-password appears here",
        },
    )


def make_evidence(scan_id: UUID) -> models.TestRunEvidence:
    return models.TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=scan_id,
        check_id=CheckId.LOGIN_ENUMERATION,
        profile_version="1.0",
        coverage={"limitations": ["Bounded test"]},
    )


def make_result(scan_id: UUID) -> CheckResult:
    return CheckResult(
        result_id=uuid4(),
        scan_id=scan_id,
        check_id=CheckId.LOGIN_ENUMERATION,
        outcome=CheckOutcome.NO_ISSUE_OBSERVED,
        owasp_reference="WSTG-IDNT-04",
        analyser_version="1.0",
        explanation="No repeatable difference was observed.",
    )


def test_evidence_store_redacts_events_and_survives_reopen(tmp_path: Path) -> None:
    scan_id = uuid4()
    store = EvidenceStore(tmp_path, secret_values=["live-password", "query-secret"])
    first_event = make_event(scan_id)
    second_event = make_event(scan_id)

    store.append_event(first_event)
    store.append_event(second_event)

    reopened_store = EvidenceStore(tmp_path, secret_values=["live-password"])
    events = reopened_store.read_events(scan_id)
    raw_events = (tmp_path / str(scan_id) / "events.ndjson").read_text()

    assert len(events) == 2
    assert "live-password" not in raw_events
    assert "query-secret" not in raw_events
    assert "?token=" not in raw_events
    assert events[0].redacted_details["password"] == "[redacted]"


def test_transient_scan_redaction_covers_metadata_and_nested_events(
    tmp_path: Path,
) -> None:
    scan_id = uuid4()
    canary = "credential-canary-2-2"
    store = EvidenceStore(tmp_path)

    with transient_secret_redaction([canary]):
        store.create_scan(
            scan_id,
            {
                "target": {
                    "target_url": f"https://app.example/login?token={canary}",
                    "permitted_origins": [
                        f"https://app.example?origin-secret={canary}"
                    ],
                },
                "description": f"Echoed {canary}",
            },
        )
        store.append_event(
            EvidenceEvent(
                event_id=uuid4(),
                scan_id=scan_id,
                kind=EvidenceKind.PAGE_STATE,
                summary=f"Echoed {canary}",
                redacted_details={"nested": {"label": canary}},
            )
        )

    persisted = "".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / str(scan_id)).rglob("*")
        if path.is_file()
    )
    assert canary not in persisted
    assert "?token=" not in persisted
    assert "?origin-secret=" not in persisted


def test_evidence_and_results_are_saved_with_versioned_result_files(
    tmp_path: Path,
) -> None:
    scan_id = uuid4()
    store = EvidenceStore(tmp_path)
    store.create_scan(scan_id, {"target": "https://app.example/login"})
    evidence = make_evidence(scan_id)
    result = make_result(scan_id)

    evidence_path = store.save_evidence(evidence)
    first_version, first_path = store.save_result(result)
    second_version, second_path = store.save_result(result)

    assert evidence_path.exists()
    assert store.read_evidence(
        scan_id, CheckId.LOGIN_ENUMERATION.value, evidence.evidence_id
    )
    assert (first_version, second_version) == (1, 2)
    assert first_path.exists() and second_path.exists()
    assert len(store.read_results(scan_id)) == 2


def test_offline_reports_are_written_from_saved_models(tmp_path: Path) -> None:
    scan_id = uuid4()
    store = EvidenceStore(tmp_path)
    store.create_scan(scan_id, {"target": "https://app.example/login"})
    evidence = make_evidence(scan_id)
    result = make_result(scan_id)

    json_path, html_path = export_scan_reports(
        store,
        scan_id,
        [evidence],
        [result],
    )
    report = json.loads(Path(json_path).read_text())

    assert report["metadata"]["scan_id"] == str(scan_id)
    assert report["evidence"][0]["check_id"] == CheckId.LOGIN_ENUMERATION.value
    assert "WSTG-IDNT-04" in Path(html_path).read_text()


def test_persisted_urls_keep_hash_routes_but_drop_token_fragments() -> None:
    redacted = redact_persisted_data(
        {
            "url": "http://127.0.0.1:3000/?next=query-secret#/login",
            "protected-url": "https://app.example/callback#access_token=secret",
        }
    )

    assert redacted == {
        "url": "http://127.0.0.1:3000/#/login",
        "protected-url": "https://app.example/callback",
    }
