"""Scan/API/report integration for all three enumeration checks."""

import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from authflowguard.app import create_app
from authflowguard.authentication import (
    LoginFormDiscoveryError,
    StaleAuthProfileError,
    VerifiedLoginExecution,
)
from authflowguard.checks.form_enumeration import FormEnumerationRun
from authflowguard.checks.login_enumeration import LoginEnumerationRun
from authflowguard.evaluation_targets.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
    EvaluationMode,
    create_controlled_app,
)
from authflowguard.models import (
    CheckId,
    CheckOutcome,
    EvidenceEvent,
    EvidenceKind,
    ScanRequest,
)
from authflowguard.scan_manager import ScanExecutionInput, ScanManager, ScanState
from fastapi.testclient import TestClient
from test_form_enumeration import (
    CHECKS,
    PASSWORD,
    UNKNOWN,
    make_evidence,
    profile_for,
    serve,
)


def execution_for(origin: str) -> ScanExecutionInput:
    return ScanExecutionInput(
        runtime_secrets={
            "known": KNOWN_USERNAME,
            "password": KNOWN_PASSWORD,
            "missing": UNKNOWN,
            "failure": PASSWORD,
        },
        username_reference="known",
        password_reference="password",
        nonexistent_identifier_reference="missing",
        failure_password_reference="failure",
        protected_resource=f"{origin}/account",
        account_marker_selector='[data-testid="account-marker"]',
        account_marker_description="Authenticated account marker",
    )


@pytest.mark.parametrize(
    "selected",
    [
        [CheckId.REGISTRATION_ENUMERATION],
        [CheckId.RESET_REQUEST_ENUMERATION],
        list(CHECKS),
        [CheckId.LOGIN_ENUMERATION],
        [CheckId.LOGIN_ENUMERATION, *CHECKS],
    ],
)
def test_selected_checks_only_are_run_persisted_and_reanalysed_offline(
    selected: list[CheckId],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[CheckId] = []
    manager = ScanManager(tmp_path)
    profile = profile_for("https://app.example")
    record = manager.create_scan(
        ScanRequest(target=profile.target, selected_checks=selected)
    )
    record.state = ScanState.RUNNING

    def fake_runner(check: CheckId) -> Any:
        async def run(**kwargs: Any) -> Any:
            calls.append(check)
            evidence = make_evidence(check, different=True)
            evidence.scan_id = kwargs["scan_id"]
            event = EvidenceEvent(
                event_id=uuid4(),
                scan_id=record.scan_id,
                check_id=check,
                kind=EvidenceKind.PAGE_STATE,
                summary="Comparison outcome",
            )
            evidence.event_ids = [event.event_id]
            if check is CheckId.LOGIN_ENUMERATION:
                evidence.observations = {
                    "pairs": [
                        {
                            "known": {"body_fingerprint": "one"},
                            "nonexistent": {"body_fingerprint": "two"},
                        }
                        for _ in range(3)
                    ]
                }
                return LoginEnumerationRun(evidence=evidence, events=[event])
            return FormEnumerationRun(evidence=evidence, events=[event])

        return run

    for check, name in [
        (CheckId.LOGIN_ENUMERATION, "run_login_enumeration_check"),
        (CheckId.REGISTRATION_ENUMERATION, "run_registration_enumeration_check"),
        (CheckId.RESET_REQUEST_ENUMERATION, "run_reset_request_enumeration_check"),
    ]:
        monkeypatch.setattr(f"authflowguard.scan_manager.{name}", fake_runner(check))
    asyncio.run(
        manager._complete_profile_execution(
            record,
            execution_for("https://app.example"),
            VerifiedLoginExecution(profile=profile, events=[], traffic=[]),
        )
    )
    assert set(calls) == set(selected)
    if all(check in selected for check in CHECKS):
        assert calls.index(CheckId.RESET_REQUEST_ENUMERATION) < calls.index(
            CheckId.REGISTRATION_ENUMERATION
        )
    assert record.state is ScanState.COMPLETED
    assert {result.check_id for result in record.results} == set(selected)
    assert all(
        result.outcome is CheckOutcome.FINDING_CONFIRMED for result in record.results
    )
    assert len(manager._store.read_all_evidence(record.scan_id)) == len(selected)
    assert len(manager._store.read_events(record.scan_id)) == len(selected)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Reanalysis must not run a browser or obtain credentials")

    monkeypatch.setattr(
        "authflowguard.checks.form_enumeration.async_playwright", forbidden
    )
    monkeypatch.setattr(
        "authflowguard.checks.login_enumeration.async_playwright", forbidden
    )
    monkeypatch.setattr("authflowguard.secrets.RuntimeSecrets.resolve", forbidden)
    client = TestClient(create_app(data_root=tmp_path))
    # More than ten saved result versions exercises numeric version ordering.
    for _ in range(4):
        response = client.post(f"/api/scans/{record.scan_id}/reanalyse")
        assert response.status_code == 200
        assert {result["check_id"] for result in response.json()["results"]} == set(
            selected
        )
        assert all(
            result["outcome"] == "finding_confirmed"
            for result in response.json()["results"]
        )
    reopened = ScanManager(tmp_path).get_scan(record.scan_id)
    assert len(reopened.results) == len(selected)
    assert {result.check_id: str(result.result_id) for result in reopened.results} == {
        result["check_id"]: result["result_id"] for result in response.json()["results"]
    }
    assert len(manager._store.read_results(record.scan_id)) == 5 * len(selected)
    assert len(calls) == len(selected)
    report = client.get(f"/api/scans/{record.scan_id}/report/json").json()
    assert len(report["results"]) == len(selected)
    assert report["metadata"]["state"] == "completed"
    html = client.get(f"/api/scans/{record.scan_id}/report/html").text
    assert "WSTG-IDNT-04" in html
    for check, code in [
        (CheckId.REGISTRATION_ENUMERATION, "CHK-002"),
        (CheckId.RESET_REQUEST_ENUMERATION, "CHK-003"),
    ]:
        if check in selected:
            assert code in html and check.value in html


@pytest.mark.parametrize("mode", list(EvaluationMode))
@pytest.mark.parametrize("guided", [False, True])
def test_real_scan_runs_both_checks_with_automatic_or_guided_profile(
    mode: EvaluationMode,
    guided: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = create_controlled_app(mode)
    with serve(fixture) as origin:
        app = create_app(data_root=tmp_path)
        manager = app.state.scan_manager
        client = TestClient(app)
        profile = profile_for(origin)
        if guided:

            async def needs_guidance(**kwargs: Any) -> Any:
                raise LoginFormDiscoveryError("Login controls are ambiguous")

            monkeypatch.setattr(
                "authflowguard.scan_manager.execute_verified_login_flow", needs_guidance
            )
        created = client.post(
            "/api/scans",
            json=ScanRequest(
                target=profile.target, selected_checks=list(CHECKS)
            ).model_dump(mode="json"),
        )
        scan_id = created.json()["scan_id"]
        record = manager.get_scan(UUID(scan_id))
        response = client.post(
            f"/api/scans/{scan_id}/start",
            json=execution_for(origin).model_dump(mode="json"),
        )
        assert response.status_code == 200
        record.future.result(timeout=60)
        if guided:
            assert record.state is ScanState.AWAITING_GUIDANCE
            observation = client.post(f"/api/scans/{scan_id}/guidance/observe").json()
            controls = observation["controls"]
            username = next(
                c["observed_control_id"] for c in controls if c["name"] == "username"
            )
            password = next(
                c["observed_control_id"] for c in controls if c["name"] == "password"
            )
            submit = next(
                c["observed_control_id"] for c in controls if c["tag"] == "button"
            )
            response = client.post(
                f"/api/scans/{scan_id}/guidance",
                json={
                    "actions": [
                        {
                            "action_type": "navigate",
                            "url": f"{origin}/login",
                            "description": "Open login",
                        },
                        {
                            "action_type": "fill",
                            "observed_control_id": username,
                            "value_reference": "known",
                            "description": "Fill identifier",
                        },
                        {
                            "action_type": "fill",
                            "observed_control_id": password,
                            "value_reference": "password",
                            "description": "Fill password",
                        },
                        {
                            "action_type": "click",
                            "observed_control_id": submit,
                            "description": "Submit",
                        },
                    ]
                },
            )
            assert response.status_code == 200
            record.future.result(timeout=60)
        status = client.get(f"/api/scans/{scan_id}").json()
        assert status["state"] == "completed", status
        assert status["profile_source"] == ("guided" if guided else "automatic")
        assert status["evidence_count"] == status["result_count"] == 2
        expected = (
            "finding_confirmed"
            if mode is EvaluationMode.VULNERABLE
            else "no_issue_observed"
        )
        assert all(result["outcome"] == expected for result in status["results"]), (
            status["results"]
        )
        # Reset saw a nonexistent account before registration created it.
        assert fixture.state.controlled.users[UNKNOWN] == PASSWORD
        reanalysed = client.post(f"/api/scans/{scan_id}/reanalyse").json()["results"]
        assert {r["check_id"]: r["outcome"] for r in reanalysed} == {
            check.value: expected for check in CHECKS
        }
        assert client.get(f"/api/scans/{scan_id}").json()["result_count"] == 2
        stored = "".join(
            path.read_text() for path in (tmp_path / scan_id).rglob("*.json")
        )
        assert KNOWN_PASSWORD not in stored
        assert PASSWORD not in stored
        assert UNKNOWN not in stored


def test_reanalysis_processes_multiple_evidence_records_for_the_same_check(
    tmp_path: Path,
) -> None:
    manager = ScanManager(tmp_path)
    profile = profile_for("https://app.example")
    record = manager.create_scan(
        ScanRequest(target=profile.target, selected_checks=list(CHECKS))
    )
    record.profile = profile
    record.state = ScanState.COMPLETED
    for different in (False, True):
        evidence = make_evidence(CheckId.REGISTRATION_ENUMERATION, different)
        evidence.scan_id = record.scan_id
        record.evidence.append(evidence)
    results = manager.reanalyse(record.scan_id)
    assert [result.outcome for result in results] == [
        CheckOutcome.NO_ISSUE_OBSERVED,
        CheckOutcome.FINDING_CONFIRMED,
    ]
    manager.reanalyse(record.scan_id)
    assert len(record.results) == 2


def test_cancellation_during_check_persists_failure_and_skips_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path)
    profile = profile_for("https://app.example")
    record = manager.create_scan(
        ScanRequest(target=profile.target, selected_checks=list(CHECKS))
    )
    record.state = ScanState.RUNNING

    async def cancelled(**kwargs: Any) -> FormEnumerationRun:
        manager.cancel_scan(record.scan_id)
        assert kwargs["cancel_requested"]()
        evidence = make_evidence(CheckId.RESET_REQUEST_ENUMERATION)
        evidence.scan_id = record.scan_id
        evidence.errors = ["EnumerationCancelledError"]
        return FormEnumerationRun(evidence=evidence, events=[])

    async def forbidden(**kwargs: Any) -> Any:
        raise AssertionError("Registration must not execute after cancellation")

    monkeypatch.setattr(
        "authflowguard.scan_manager.run_reset_request_enumeration_check", cancelled
    )
    monkeypatch.setattr(
        "authflowguard.scan_manager.run_registration_enumeration_check", forbidden
    )
    asyncio.run(
        manager._complete_profile_execution(
            record,
            execution_for("https://app.example"),
            VerifiedLoginExecution(profile=profile, events=[], traffic=[]),
        )
    )
    assert record.state is ScanState.CANCELLED
    assert len(record.results) == 1
    assert record.results[0].outcome is CheckOutcome.EXECUTION_ERROR
    report = json.loads(manager.report_path(record.scan_id, "json").read_text())
    assert report["metadata"]["state"] == "cancelled"
    assert "execution_error" in manager.report_path(record.scan_id, "html").read_text()


def test_stale_saved_profile_returns_to_guidance_before_any_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path)
    profile = profile_for("https://app.example")
    record = manager.create_scan(
        ScanRequest(target=profile.target, selected_checks=list(CHECKS))
    )
    record.state = ScanState.RUNNING
    monkeypatch.setattr(manager, "_find_saved_profile", lambda *args: profile)

    async def stale(**kwargs: Any) -> Any:
        raise StaleAuthProfileError("Changed control signatures")

    async def forbidden(**kwargs: Any) -> Any:
        raise AssertionError("A stale profile must not be replayed or tested")

    monkeypatch.setattr("authflowguard.scan_manager.revalidate_auth_profile", stale)
    monkeypatch.setattr(
        "authflowguard.scan_manager.replay_verified_auth_profile", forbidden
    )
    monkeypatch.setattr(
        "authflowguard.scan_manager.run_reset_request_enumeration_check", forbidden
    )
    asyncio.run(manager._run_scan_async(record, execution_for("https://app.example")))
    assert record.state is ScanState.AWAITING_GUIDANCE
    assert not record.evidence
    manager.cancel_scan(record.scan_id)
    assert record.state is ScanState.CANCELLED
    assert record.pending_execution is None
