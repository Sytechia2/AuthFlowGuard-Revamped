"""CHK-005 and CHK-006 browser and offline analyser tests."""

import asyncio
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from authflowguard.authentication import VerifiedLoginExecution
from authflowguard.checks.logout_invalidation import (
    LogoutInvalidationRun,
    analyse_logout_invalidation,
    run_logout_invalidation_check,
)
from authflowguard.checks.session_fixation import (
    SessionFixationRun,
    analyse_session_fixation,
    run_session_fixation_check,
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


def run_check(origin: str, check: CheckId) -> tuple[AuthProfile, Any]:
    profile = profile_for(origin)
    secrets = RuntimeSecrets({"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD})
    run: SessionFixationRun | LogoutInvalidationRun
    try:
        if check is CheckId.SESSION_FIXATION:
            run = asyncio.run(
                run_session_fixation_check(
                    profile=profile,
                    scan_id=uuid4(),
                    runtime_secrets=secrets,
                    username_reference="username",
                    password_reference="password",
                    protected_resource=f"{origin}/account",
                    account_marker_selector='[data-testid="account-marker"]',
                )
            )
        else:
            run = asyncio.run(
                run_logout_invalidation_check(
                    profile=profile,
                    scan_id=uuid4(),
                    runtime_secrets=secrets,
                    username_reference="username",
                    password_reference="password",
                    protected_resource=f"{origin}/account",
                    account_marker_selector='[data-testid="account-marker"]',
                )
            )
    finally:
        secrets.discard_all()
    return profile, run


@pytest.mark.parametrize(
    ("check", "analyser", "vulnerable", "secure"),
    [
        (
            CheckId.SESSION_FIXATION,
            analyse_session_fixation,
            CheckOutcome.FINDING_CONFIRMED,
            CheckOutcome.NO_ISSUE_OBSERVED,
        ),
        (
            CheckId.LOGOUT_INVALIDATION,
            analyse_logout_invalidation,
            CheckOutcome.FINDING_CONFIRMED,
            CheckOutcome.NO_ISSUE_OBSERVED,
        ),
    ],
)
@pytest.mark.parametrize("mode", list(EvaluationMode))
def test_session_checks_cover_secure_and_vulnerable_modes(
    check: CheckId,
    analyser: Any,
    vulnerable: CheckOutcome,
    secure: CheckOutcome,
    mode: EvaluationMode,
) -> None:
    with serve(create_controlled_app(mode)) as origin:
        profile, run = run_check(origin, check)
    assert isinstance(run, (SessionFixationRun, LogoutInvalidationRun))
    assert run.evidence.check_id is check
    assert not run.evidence.errors
    result = analyser(run.evidence, profile, SecurityPolicy())
    expected = secure if mode is EvaluationMode.SECURE else vulnerable
    assert result.outcome is expected
    assert result.owasp_reference in {"WSTG-SESS-03", "WSTG-SESS-06"}
    assert result == analyser(run.evidence, profile, SecurityPolicy())


@pytest.mark.parametrize(
    "check", [CheckId.SESSION_FIXATION, CheckId.LOGOUT_INVALIDATION]
)
def test_session_check_malformed_evidence_is_inconclusive(check: CheckId) -> None:
    with serve(create_controlled_app(EvaluationMode.SECURE)) as origin:
        profile, run = run_check(origin, check)
    run.evidence.observations.pop("anonymous_control")
    analyser = (
        analyse_session_fixation
        if check is CheckId.SESSION_FIXATION
        else analyse_logout_invalidation
    )
    assert (
        analyser(run.evidence, profile, SecurityPolicy()).outcome
        is CheckOutcome.INCONCLUSIVE
    )


@pytest.mark.parametrize(
    "check", [CheckId.SESSION_FIXATION, CheckId.LOGOUT_INVALIDATION]
)
def test_session_check_browser_failure_is_execution_error(check: CheckId) -> None:
    profile = profile_for("http://127.0.0.1:1")
    secrets = RuntimeSecrets({"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD})
    run: SessionFixationRun | LogoutInvalidationRun
    try:
        if check is CheckId.SESSION_FIXATION:
            run = asyncio.run(
                run_session_fixation_check(
                    profile=profile,
                    scan_id=uuid4(),
                    runtime_secrets=secrets,
                    username_reference="username",
                    password_reference="password",
                    protected_resource="http://127.0.0.1:1/account",
                    account_marker_selector='[data-testid="account-marker"]',
                )
            )
        else:
            run = asyncio.run(
                run_logout_invalidation_check(
                    profile=profile,
                    scan_id=uuid4(),
                    runtime_secrets=secrets,
                    username_reference="username",
                    password_reference="password",
                    protected_resource="http://127.0.0.1:1/account",
                    account_marker_selector='[data-testid="account-marker"]',
                )
            )
    finally:
        secrets.discard_all()
    analyser = (
        analyse_session_fixation
        if check is CheckId.SESSION_FIXATION
        else analyse_logout_invalidation
    )
    assert run.evidence.errors
    assert (
        analyser(run.evidence, profile, SecurityPolicy()).outcome
        is CheckOutcome.EXECUTION_ERROR
    )


@pytest.mark.parametrize(
    "check", [CheckId.SESSION_FIXATION, CheckId.LOGOUT_INVALIDATION]
)
def test_scan_manager_persists_and_reanalyses_session_check(
    check: CheckId, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = ScanManager(tmp_path)
    profile = profile_for("https://app.example")
    record = manager.create_scan(
        ScanRequest(target=profile.target, selected_checks=[check])
    )
    record.state = ScanState.RUNNING
    execution = ScanExecutionInput(
        runtime_secrets={"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD},
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
        check_id=check,
        kind=EvidenceKind.PAGE_STATE,
        summary="Captured session controls.",
    )
    controls = {
        "authenticated_control": {"status": 200, "marker_present": True},
        "anonymous_control": {"status": 401, "marker_present": False},
    }
    if check is CheckId.SESSION_FIXATION:
        observations = {
            **controls,
            "original_session_replay": {"status": 401, "marker_present": False},
            "pre_login_session": {"fingerprint": "a" * 64},
            "post_login_session": {"fingerprint": "b" * 64},
        }
        run_class: Any = SessionFixationRun
        runner_name = "run_session_fixation_check"
        code = "CHK-005"
    else:
        observations = {
            **controls,
            "old_session_replay": {"status": 401, "marker_present": False},
            "post_logout_control": {"status": 401, "marker_present": False},
            "logout_status": 303,
        }
        run_class = LogoutInvalidationRun
        runner_name = "run_logout_invalidation_check"
        code = "CHK-006"
    evidence = EvidencePackage(
        evidence_id=uuid4(),
        scan_id=record.scan_id,
        check_id=check,
        profile_version=profile.schema_version,
        event_ids=[event.event_id],
        observations={**observations, "captured_at": "2026-01-01T00:00:00+00:00"},
        control_comparisons=["Session controls compared."],
        coverage=Coverage(
            attempted_steps=["login", "replay"],
            completed_steps=["login", "replay"],
            limitations=["Fixture evidence."],
        ),
    )

    async def fake_runner(**kwargs: Any) -> Any:
        assert kwargs["scan_id"] == record.scan_id
        return run_class(evidence=evidence, events=[event])

    monkeypatch.setattr(f"authflowguard.scan_manager.{runner_name}", fake_runner)
    asyncio.run(
        manager._complete_profile_execution(
            record,
            execution,
            VerifiedLoginExecution(profile=profile, events=[], traffic=[]),
        )
    )
    assert record.state is ScanState.COMPLETED
    assert record.results[0].outcome is CheckOutcome.NO_ISSUE_OBSERVED
    assert code in manager.report_path(record.scan_id, "html").read_text()
    assert (
        manager.reanalyse(record.scan_id)[0].outcome is CheckOutcome.NO_ISSUE_OBSERVED
    )
