"""Browser runner and offline analyser tests for login enumeration."""

import asyncio
import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Thread
from uuid import uuid4

import pytest
import uvicorn
from authflowguard import models
from authflowguard.authentication import execute_verified_login_flow
from authflowguard.checks.login_enumeration import (
    LoginEnumerationRun,
    analyse_login_enumeration,
    run_login_enumeration_check,
)
from authflowguard.evaluation_targets.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
    EvaluationMode,
    create_controlled_app,
)
from authflowguard.evaluation_targets.react_json_app import (
    KNOWN_USERNAME as REACT_KNOWN_USERNAME,
)
from authflowguard.evaluation_targets.react_json_app import (
    EvaluationMode as ReactJsonMode,
)
from authflowguard.evaluation_targets.react_json_app import (
    create_react_json_app,
)
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    CheckId,
    CheckOutcome,
    SecurityPolicy,
    TargetScope,
)
from authflowguard.secrets import RuntimeSecrets
from test_form_enumeration import serve


@contextmanager
def run_controlled_server(mode: EvaluationMode) -> Iterator[str]:
    # Chromium refuses a small set of well-known ports (including 6667).
    # Retry an ephemeral bind if the OS happens to select one of them.
    unsafe_ports = {
        1,
        7,
        9,
        11,
        13,
        15,
        17,
        19,
        20,
        21,
        22,
        23,
        25,
        37,
        42,
        43,
        53,
        67,
        69,
        79,
        87,
        95,
        101,
        102,
        103,
        104,
        109,
        110,
        111,
        113,
        115,
        117,
        119,
        123,
        135,
        137,
        139,
        143,
        161,
        179,
        389,
        427,
        465,
        512,
        513,
        514,
        515,
        526,
        530,
        531,
        532,
        540,
        556,
        563,
        587,
        601,
        636,
        993,
        995,
        2049,
        3659,
        4045,
        6000,
        6665,
        6666,
        6667,
        6668,
        6669,
        6697,
        10080,
    }
    while True:
        listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listening_socket.bind(("127.0.0.1", 0))
        if listening_socket.getsockname()[1] not in unsafe_ports:
            break
        listening_socket.close()
    listening_socket.listen()
    port = listening_socket.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            create_controlled_app(mode),
            log_level="error",
            lifespan="off",
        )
    )
    thread = Thread(
        target=server.run,
        kwargs={"sockets": [listening_socket]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("Controlled evaluation server did not start")

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listening_socket.close()


async def make_profile(origin: str) -> AuthProfile:
    result = await execute_verified_login_flow(
        scan_id=uuid4(),
        target=TargetScope(
            target_url=f"{origin}/login",
            permitted_origins=[origin],
        ),
        runtime_secrets=RuntimeSecrets(
            {
                "login-username": KNOWN_USERNAME,
                "login-password": KNOWN_PASSWORD,
            }
        ),
        username_reference="login-username",
        password_reference="login-password",
        protected_resource=f"{origin}/account",
        account_marker_selector='[data-testid="account-marker"]',
        account_marker_description="The protected page contains an account marker",
    )
    return result.profile


async def run_check(profile: AuthProfile) -> LoginEnumerationRun:
    return await run_login_enumeration_check(
        profile=profile,
        scan_id=uuid4(),
        runtime_secrets=RuntimeSecrets(
            {
                "known-identifier": KNOWN_USERNAME,
                "nonexistent-identifier": "missing@example.test",
                "failure-password": "definitely-wrong",
            }
        ),
        known_identifier_reference="known-identifier",
        nonexistent_identifier_reference="nonexistent-identifier",
        failure_password_reference="failure-password",
        password_references=frozenset({"login-password"}),
    )


@pytest.mark.parametrize(
    ("mode", "expected_outcome"),
    [
        (EvaluationMode.VULNERABLE, CheckOutcome.FINDING_CONFIRMED),
        (EvaluationMode.SECURE, CheckOutcome.NO_ISSUE_OBSERVED),
    ],
)
def test_runner_and_offline_analyser_cover_secure_and_vulnerable_modes(
    mode: EvaluationMode,
    expected_outcome: CheckOutcome,
) -> None:
    with run_controlled_server(mode) as origin:
        profile = asyncio.run(make_profile(origin))
        run = asyncio.run(run_check(profile))
        result = analyse_login_enumeration(run.evidence, profile, SecurityPolicy())

    assert run.evidence.check_id is CheckId.LOGIN_ENUMERATION
    assert len(run.evidence.observations["pairs"]) == 3
    assert len(run.evidence.event_ids) == len(run.events)
    assert not run.evidence.errors
    assert result.outcome is expected_outcome
    assert result.owasp_reference == "WSTG-IDNT-04"
    assert result.evidence_references


def test_analyser_is_repeatable_and_does_not_need_live_io() -> None:
    evidence = models.TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=uuid4(),
        check_id=CheckId.LOGIN_ENUMERATION,
        profile_version="1.0",
        observations={
            "pairs": [
                {
                    "pair_number": number,
                    "known": {"body_fingerprint": "same"},
                    "nonexistent": {"body_fingerprint": "different"},
                }
                for number in range(1, 4)
            ]
        },
    )
    profile = AuthProfile(
        target=TargetScope(
            target_url="https://app.example/login",
            permitted_origins=["https://app.example"],
        ),
        features={AuthFeature.LOGIN: "verified"},
        authentication_steps={
            AuthFeature.LOGIN: [
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url="https://app.example/login",
                    description="Open login",
                )
            ]
        },
    )

    first = analyse_login_enumeration(evidence, profile, SecurityPolicy())
    second = analyse_login_enumeration(evidence, profile, SecurityPolicy())

    assert first.outcome is CheckOutcome.FINDING_CONFIRMED
    assert second.outcome is first.outcome
    assert second.explanation == first.explanation
    assert second.analyser_version == first.analyser_version


def test_analyser_reports_incomplete_and_execution_failure_evidence() -> None:
    profile = AuthProfile(
        target=TargetScope(
            target_url="https://app.example/login",
            permitted_origins=["https://app.example"],
        ),
        features={AuthFeature.LOGIN: "verified"},
        authentication_steps={
            AuthFeature.LOGIN: [
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url="https://app.example/login",
                    description="Open login",
                )
            ]
        },
    )
    incomplete = models.TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=uuid4(),
        check_id=CheckId.LOGIN_ENUMERATION,
        profile_version="1.0",
        observations={"pairs": []},
    )
    failed = incomplete.model_copy(
        update={"errors": ["pair-1-known-failure: TimeoutError"]}
    )

    assert (
        analyse_login_enumeration(incomplete, profile, SecurityPolicy()).outcome
        is CheckOutcome.INCONCLUSIVE
    )
    assert (
        analyse_login_enumeration(failed, profile, SecurityPolicy()).outcome
        is CheckOutcome.EXECUTION_ERROR
    )


def test_runner_rejects_a_profile_without_verified_login() -> None:
    profile = AuthProfile(
        target=TargetScope(
            target_url="https://app.example/login",
            permitted_origins=["https://app.example"],
        ),
        features={AuthFeature.LOGIN: "found"},
        authentication_steps={AuthFeature.LOGIN: []},
    )

    with pytest.raises(ValueError, match="verified login"):
        asyncio.run(
            run_login_enumeration_check(
                profile=profile,
                scan_id=uuid4(),
                runtime_secrets=RuntimeSecrets({}),
                known_identifier_reference="known",
                nonexistent_identifier_reference="missing",
                failure_password_reference="wrong",
                password_references=frozenset(),
            )
        )


def two_step_profile(origin: str) -> AuthProfile:
    """Email, Continue, then a verification code that appears only on success."""

    def step(action: BrowserActionType, **fields: str) -> BrowserAction:
        return BrowserAction(action_type=action, description="Two-step login", **fields)

    return AuthProfile(
        target=TargetScope(target_url=f"{origin}/login", permitted_origins=[origin]),
        features={AuthFeature.LOGIN: "verified"},
        authentication_steps={
            AuthFeature.LOGIN: [
                step(BrowserActionType.NAVIGATE, url=f"{origin}/login"),
                step(
                    BrowserActionType.FILL,
                    observed_control_id="control-1",
                    value_reference="login-username",
                ),
                step(BrowserActionType.CLICK, observed_control_id="control-2"),
                step(
                    BrowserActionType.FILL,
                    observed_control_id="control-3",
                    value_reference="login-code",
                ),
                step(BrowserActionType.CLICK, observed_control_id="control-4"),
            ]
        },
    )


def run_two_step_check(
    mode: ReactJsonMode, known_identifier: str = REACT_KNOWN_USERNAME
) -> tuple[AuthProfile, LoginEnumerationRun]:
    with serve(create_react_json_app(mode)) as origin:
        profile = two_step_profile(origin)
        run = asyncio.run(
            run_login_enumeration_check(
                profile=profile,
                scan_id=uuid4(),
                runtime_secrets=RuntimeSecrets(
                    {
                        "known-identifier": known_identifier,
                        "nonexistent-identifier": "missing@example.test",
                        "failure-password": "000000",
                    }
                ),
                known_identifier_reference="known-identifier",
                nonexistent_identifier_reference="nonexistent-identifier",
                failure_password_reference="failure-password",
                # The scan's password reference; this flow has no password step.
                password_references=frozenset({"login-password"}),
                username_action_reference="login-username",
                password_action_reference="login-code",
            )
        )
    return profile, run


@pytest.mark.parametrize(
    ("mode", "expected_outcome"),
    [
        # The unknown email is rejected before the code field appears; that
        # early end is recorded as the response rather than waited on.
        (ReactJsonMode.VULNERABLE, CheckOutcome.FINDING_CONFIRMED),
        (ReactJsonMode.SECURE, CheckOutcome.NO_ISSUE_OBSERVED),
    ],
)
def test_two_step_login_records_an_early_rejection(
    mode: ReactJsonMode, expected_outcome: CheckOutcome
) -> None:
    profile, run = run_two_step_check(mode)

    assert run.evidence.errors == []
    result = analyse_login_enumeration(run.evidence, profile, SecurityPolicy())
    assert result.outcome is expected_outcome


def test_known_identifier_attempt_must_complete_every_step() -> None:
    # An identifier the app rejects at the first step, used as the known one:
    # the flow cannot be completed, which must be an error, never "no issue".
    profile, run = run_two_step_check(
        ReactJsonMode.VULNERABLE, known_identifier="also-missing@example.test"
    )

    assert run.evidence.errors
    result = analyse_login_enumeration(run.evidence, profile, SecurityPolicy())
    assert result.outcome is CheckOutcome.EXECUTION_ERROR
