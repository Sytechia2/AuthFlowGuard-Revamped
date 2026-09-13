"""Browser-level tests for login execution and authentication proof."""

import asyncio
import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Thread
from uuid import uuid4

import pytest
import uvicorn
from authflowguard.authentication import (
    VerifiedLoginExecution,
    execute_guided_verified_login_flow,
    execute_verified_login_flow,
    record_guided_flow,
    replay_verified_auth_profile,
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
    DiscoverySource,
    FeatureStatus,
    TargetScope,
)
from authflowguard.secrets import RuntimeSecrets


@contextmanager
def run_controlled_server() -> Iterator[str]:
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.bind(("127.0.0.1", 0))
    listening_socket.listen()
    port = listening_socket.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            create_controlled_app(EvaluationMode.SECURE),
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


async def run_verified_flow(
    origin: str, password: str = KNOWN_PASSWORD
) -> VerifiedLoginExecution:
    target = TargetScope(
        target_url=f"{origin}/login",
        permitted_origins=[origin],
    )
    return await execute_verified_login_flow(
        scan_id=uuid4(),
        target=target,
        runtime_secrets=RuntimeSecrets(
            {
                "login-username": KNOWN_USERNAME,
                "login-password": password,
            }
        ),
        username_reference="login-username",
        password_reference="login-password",
        protected_resource=f"{origin}/account?private=must-not-be-saved",
        account_marker_selector='[data-testid="account-marker"]',
        account_marker_description="The protected page contains an account marker",
    )


def guided_login_actions(origin: str) -> list[BrowserAction]:
    """The control references are deliberately supplied by a guidance user."""
    return [
        BrowserAction(
            action_type=BrowserActionType.NAVIGATE,
            url=f"{origin}/login?guided_session=do-not-save",
            description=f"Open the login page with the password {KNOWN_PASSWORD}",
        ),
        BrowserAction(
            action_type=BrowserActionType.FILL,
            observed_control_id="control-5",
            value_reference="login-username",
            description="Fill the username",
        ),
        BrowserAction(
            action_type=BrowserActionType.FILL,
            observed_control_id="control-6",
            value_reference="login-password",
            description="Fill the password",
        ),
        BrowserAction(
            action_type=BrowserActionType.CLICK,
            observed_control_id="control-7",
            description="Submit the form",
        ),
    ]


def test_flow_executes_csrf_safe_login_and_builds_verified_profile() -> None:
    with run_controlled_server() as origin:
        result = asyncio.run(run_verified_flow(origin))

    profile = result.profile
    assert profile.features[AuthFeature.LOGIN] is FeatureStatus.VERIFIED
    assert [
        step.action_type for step in profile.authentication_steps[AuthFeature.LOGIN]
    ] == [
        BrowserActionType.NAVIGATE,
        BrowserActionType.FILL,
        BrowserActionType.FILL,
        BrowserActionType.CLICK,
    ]
    assert profile.protected_resource_check is not None
    assert profile.protected_resource_check.resource == f"{origin}/account"
    assert profile.relevant_traffic
    assert profile.session_references

    authenticated_id = profile.protected_resource_check.authenticated_evidence_ids[0]
    anonymous_id = profile.protected_resource_check.anonymous_evidence_ids[0]
    evidence_by_id = {event.event_id: event for event in result.events}
    assert (
        evidence_by_id[authenticated_id].redacted_details["account_marker_present"]
        is True
    )
    assert (
        evidence_by_id[anonymous_id].redacted_details["account_marker_present"] is False
    )

    persisted_output = profile.model_dump_json() + "".join(
        event.model_dump_json() for event in result.events
    )
    assert KNOWN_USERNAME not in persisted_output
    assert KNOWN_PASSWORD not in persisted_output
    assert "must-not-be-saved" not in persisted_output


def test_flow_rejects_login_when_authenticated_marker_is_absent() -> None:
    with run_controlled_server() as origin:
        with pytest.raises(ValueError, match="account marker was absent"):
            asyncio.run(run_verified_flow(origin, password="incorrect-password"))


def test_guided_flow_records_references_and_redacts_live_values() -> None:
    with run_controlled_server() as origin:
        result = asyncio.run(
            record_guided_flow(
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
                actions=guided_login_actions(origin),
            )
        )

    saved = "".join(action.model_dump_json() for action in result.actions)
    assert str(result.actions[0].url) == f"{origin}/login"
    assert "guided_session" not in saved
    assert KNOWN_USERNAME not in saved
    assert KNOWN_PASSWORD not in saved
    assert result.actions[1].value_reference == "login-username"
    assert result.actions[2].value_reference == "login-password"


def test_guided_flow_builds_verified_profile_and_replays_in_fresh_context() -> None:
    with run_controlled_server() as origin:
        target = TargetScope(
            target_url=f"{origin}/login",
            permitted_origins=[origin],
        )
        secrets = RuntimeSecrets(
            {
                "login-username": KNOWN_USERNAME,
                "login-password": KNOWN_PASSWORD,
            }
        )
        guided_result = asyncio.run(
            execute_guided_verified_login_flow(
                scan_id=uuid4(),
                target=target,
                runtime_secrets=secrets,
                actions=guided_login_actions(origin),
                protected_resource=f"{origin}/account?proof=not-saved",
                account_marker_selector='[data-testid="account-marker"]',
                account_marker_description=(
                    "The protected page contains an account marker"
                ),
            )
        )
        replay_result = asyncio.run(
            replay_verified_auth_profile(
                profile=guided_result.profile,
                scan_id=uuid4(),
                runtime_secrets=secrets,
                account_marker_selector='[data-testid="account-marker"]',
            )
        )

    assert guided_result.profile.discovery_history[-1].source is DiscoverySource.GUIDED
    assert replay_result.profile.features[AuthFeature.LOGIN] is FeatureStatus.VERIFIED
    replay_check = replay_result.profile.protected_resource_check
    guided_check = guided_result.profile.protected_resource_check
    assert replay_check is not None
    assert guided_check is not None
    assert replay_check.resource == f"{origin}/account"
    assert replay_check.authenticated_evidence_ids
    assert replay_check.anonymous_evidence_ids
    assert replay_check.authenticated_evidence_ids != (
        guided_check.authenticated_evidence_ids
    )


def test_profile_replay_rejects_unverified_or_incomplete_profiles() -> None:
    with pytest.raises(ValueError, match="no saved login flow"):
        asyncio.run(
            replay_verified_auth_profile(
                profile=AuthProfile(
                    target=TargetScope(
                        target_url="https://app.example/login",
                        permitted_origins=["https://app.example"],
                    ),
                    features={},
                ),
                scan_id=uuid4(),
                runtime_secrets=RuntimeSecrets({}),
                account_marker_selector="#marker",
            )
        )
