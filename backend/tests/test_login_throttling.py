"""CHK-004 runner and deterministic analyser tests."""

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from authflowguard.authentication import VerifiedLoginExecution
from authflowguard.checks.login_throttling import (
    LoginThrottlingRun,
    analyse_login_throttling,
    run_login_throttling_check,
)
from authflowguard.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
    EvaluationMode,
    create_controlled_app,
)
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    CheckId,
    CheckOutcome,
    Coverage,
    EvidenceEvent,
    EvidenceKind,
    ScanRequest,
    SecurityPolicy,
    TargetScope,
)
from authflowguard.models import (
    TestRunEvidence as EvidencePackage,
)
from authflowguard.scan_manager import ScanExecutionInput, ScanManager, ScanState
from authflowguard.secrets import RuntimeSecrets
from test_form_enumeration import serve


def profile_for(origin: str) -> AuthProfile:
    return AuthProfile(
        target=TargetScope(target_url=f"{origin}/login", permitted_origins=[origin]),
        features={AuthFeature.LOGIN: "verified"},
        authentication_steps={
            AuthFeature.LOGIN: [
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url=f"{origin}/login",
                    description="Open login",
                ),
                BrowserAction(
                    action_type=BrowserActionType.FILL,
                    observed_control_id="control-5",
                    value_reference="username",
                    description="Fill username",
                ),
                BrowserAction(
                    action_type=BrowserActionType.FILL,
                    observed_control_id="control-6",
                    value_reference="password",
                    description="Fill password",
                ),
                BrowserAction(
                    action_type=BrowserActionType.CLICK,
                    observed_control_id="control-7",
                    description="Submit login",
                ),
            ]
        },
    )


def run_check(
    origin: str, *, cancel_requested: Callable[[], bool] = lambda: False
) -> tuple[AuthProfile, LoginThrottlingRun]:
    profile = profile_for(origin)
    secrets = RuntimeSecrets(
        {
            "username": KNOWN_USERNAME,
            "password": KNOWN_PASSWORD,
            "failure": "wrong-password",
        }
    )
    try:
        return profile, asyncio.run(
            run_login_throttling_check(
                profile=profile,
                scan_id=uuid4(),
                runtime_secrets=secrets,
                username_reference="username",
                password_reference="password",
                failure_password_reference="failure",
                cancel_requested=cancel_requested,
            )
        )
    finally:
        secrets.discard_all()


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (EvaluationMode.SECURE, CheckOutcome.NO_ISSUE_OBSERVED),
        (EvaluationMode.VULNERABLE, CheckOutcome.FINDING_CONFIRMED),
    ],
)
def test_runner_and_analyser_detect_secure_and_vulnerable_lockout(
    mode: EvaluationMode, expected: CheckOutcome
) -> None:
    with serve(create_controlled_app(mode)) as origin:
        profile, run = run_check(origin)
        result = analyse_login_throttling(run.evidence, profile, SecurityPolicy())
    assert run.evidence.check_id is CheckId.LOGIN_THROTTLING
    assert not run.evidence.errors
    assert result.outcome is expected
    assert result.owasp_reference == "WSTG-ATHN-03"
    assert len(run.evidence.observations["failed_attempts"]) == 4


def test_explicit_policy_threshold_is_used_in_evidence() -> None:
    with serve(create_controlled_app(EvaluationMode.SECURE)) as origin:
        profile = profile_for(origin)
        secrets = RuntimeSecrets(
            {"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD, "failure": "wrong"}
        )
        try:
            run = asyncio.run(
                run_login_throttling_check(
                    profile=profile,
                    scan_id=uuid4(),
                    runtime_secrets=secrets,
                    username_reference="username",
                    password_reference="password",
                    failure_password_reference="failure",
                    expected_lockout_threshold=3,
                )
            )
        finally:
            secrets.discard_all()
    assert run.evidence.observations["attempt_count"] == 3
    assert (
        analyse_login_throttling(
            run.evidence, profile, SecurityPolicy(expected_lockout_threshold=3)
        ).outcome
        is CheckOutcome.NO_ISSUE_OBSERVED
    )


def test_analyser_is_deterministic_and_offline() -> None:
    with serve(create_controlled_app(EvaluationMode.SECURE)) as origin:
        profile, run = run_check(origin)
    first = analyse_login_throttling(run.evidence, profile, SecurityPolicy())
    second = analyse_login_throttling(run.evidence, profile, SecurityPolicy())
    assert first == second
    assert first.result_id == second.result_id


@pytest.mark.parametrize("malformed", ["missing", "wrong_shape", "missing_status"])
def test_ambiguous_evidence_is_inconclusive(malformed: str) -> None:
    with serve(create_controlled_app(EvaluationMode.SECURE)) as origin:
        profile, run = run_check(origin)
    observations = run.evidence.observations
    if malformed == "missing":
        observations.pop("failed_attempts")
    elif malformed == "wrong_shape":
        observations["failed_attempts"] = [{}]
    else:
        observations["failed_attempts"][-1]["valid_login_control"].pop(
            "final_status_code"
        )
    result = analyse_login_throttling(run.evidence, profile, SecurityPolicy())
    assert result.outcome is CheckOutcome.INCONCLUSIVE


def test_execution_failure_is_not_reported_as_secure() -> None:
    profile = profile_for("http://127.0.0.1:1")
    secrets = RuntimeSecrets(
        {"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD, "failure": "wrong"}
    )
    try:
        run = asyncio.run(
            run_login_throttling_check(
                profile=profile,
                scan_id=uuid4(),
                runtime_secrets=secrets,
                username_reference="username",
                password_reference="password",
                failure_password_reference="failure",
            )
        )
    finally:
        secrets.discard_all()
    assert run.evidence.errors
    assert (
        analyse_login_throttling(run.evidence, profile, SecurityPolicy()).outcome
        is CheckOutcome.EXECUTION_ERROR
    )


def test_unexpected_server_status_is_execution_error() -> None:
    with serve(create_controlled_app(EvaluationMode.SECURE)) as origin:
        profile, run = run_check(origin)
    run.evidence.observations["failed_attempts"][0]["status_codes"] = [503]
    result = analyse_login_throttling(run.evidence, profile, SecurityPolicy())
    assert result.outcome is CheckOutcome.EXECUTION_ERROR


def test_cancellation_produces_execution_error() -> None:
    with serve(create_controlled_app(EvaluationMode.SECURE)) as origin:
        profile = profile_for(origin)
        profile_calls = {"count": 0}

        def cancel() -> bool:
            profile_calls["count"] += 1
            return profile_calls["count"] > 1

        _profile, run = run_check(origin, cancel_requested=cancel)
    assert run.evidence.errors
    assert (
        analyse_login_throttling(run.evidence, profile, SecurityPolicy()).outcome
        is CheckOutcome.EXECUTION_ERROR
    )


def test_scan_manager_persists_and_reanalyses_throttling_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path)
    profile = profile_for("https://app.example")
    record = manager.create_scan(
        ScanRequest(
            target=profile.target,
            selected_checks=[CheckId.LOGIN_THROTTLING],
        )
    )
    record.state = ScanState.RUNNING
    execution = ScanExecutionInput(
        runtime_secrets={
            "username": KNOWN_USERNAME,
            "password": KNOWN_PASSWORD,
            "missing": "missing@example.test",
            "failure": "wrong-password",
        },
        username_reference="username",
        password_reference="password",
        nonexistent_identifier_reference="missing",
        failure_password_reference="failure",
        protected_resource="https://app.example/account",
        account_marker_selector='[data-testid="account-marker"]',
        account_marker_description="Authenticated account marker",
    )
    event = EvidenceEvent(
        event_id=uuid4(),
        scan_id=record.scan_id,
        check_id=CheckId.LOGIN_THROTTLING,
        kind=EvidenceKind.PAGE_STATE,
        summary="Captured throttling control outcomes.",
    )
    fingerprint = "a" * 64
    evidence = EvidencePackage(
        evidence_id=uuid4(),
        scan_id=record.scan_id,
        check_id=CheckId.LOGIN_THROTTLING,
        profile_version=profile.schema_version,
        event_ids=[event.event_id],
        observations={
            "attempt_count": 1,
            "captured_at": "2026-01-01T00:00:00+00:00",
            "failed_attempts": [
                {
                    "status_codes": [401],
                    "final_status_code": 401,
                    "url": "https://app.example/login",
                    "title_fingerprint": fingerprint,
                    "body_fingerprint": fingerprint,
                    "safe_indicators": ["authentication_required"],
                    "completed": True,
                },
                {
                    "valid_login_control": {
                        "status_codes": [429],
                        "final_status_code": 429,
                        "url": "https://app.example/login",
                        "title_fingerprint": fingerprint,
                        "body_fingerprint": fingerprint,
                        "safe_indicators": ["rate_limited"],
                        "completed": True,
                    }
                },
            ],
        },
        control_comparisons=[
            "Bounded failed attempts were compared with a valid-login control."
        ],
        coverage=Coverage(
            attempted_steps=["failed_attempt_1", "valid_login_control"],
            completed_steps=["failed_attempt_1", "valid_login_control"],
            limitations=["Fixture evidence for manager integration."],
        ),
    )

    async def fake_runner(**kwargs: Any) -> LoginThrottlingRun:
        assert kwargs["scan_id"] == record.scan_id
        return LoginThrottlingRun(evidence=evidence, events=[event])

    monkeypatch.setattr(
        "authflowguard.scan_manager.run_login_throttling_check", fake_runner
    )
    asyncio.run(
        manager._complete_profile_execution(
            record,
            execution,
            VerifiedLoginExecution(profile=profile, events=[], traffic=[]),
        )
    )

    assert record.state is ScanState.COMPLETED
    assert record.results[0].outcome is CheckOutcome.NO_ISSUE_OBSERVED
    assert (
        manager._store.read_all_evidence(record.scan_id)[0].check_id
        is CheckId.LOGIN_THROTTLING
    )
    assert "CHK-004" in manager.report_path(record.scan_id, "html").read_text()
    reanalysed = manager.reanalyse(record.scan_id)
    assert len(reanalysed) == 1
    assert reanalysed[0].outcome is CheckOutcome.NO_ISSUE_OBSERVED
