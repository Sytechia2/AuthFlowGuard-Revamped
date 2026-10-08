"""Browser-level tests for login execution and authentication proof."""

import asyncio
import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs
from uuid import uuid4

import pytest
import uvicorn
from authflowguard.action_executor import BrowserActionExecutor
from authflowguard.authentication import (
    StaleAuthProfileError,
    VerifiedLoginExecution,
    _prepare_guided_actions,
    execute_guided_verified_login_flow,
    execute_verified_login_flow,
    record_guided_flow,
    replay_verified_auth_profile,
    revalidate_auth_profile,
)
from authflowguard.control_safety import RecordedControlNotFoundError
from authflowguard.evaluation_targets.controlled_app import (
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


@pytest.mark.slow
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


@pytest.mark.slow
def test_flow_rejects_login_when_authenticated_marker_is_absent() -> None:
    with run_controlled_server() as origin:
        with pytest.raises(ValueError, match="account marker was absent"):
            asyncio.run(run_verified_flow(origin, password="incorrect-password"))


@pytest.mark.slow
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
                password_references=frozenset({"login-password"}),
            )
        )

    saved = "".join(action.model_dump_json() for action in result.actions)
    assert str(result.actions[0].url) == f"{origin}/login"
    assert "guided_session" not in saved
    assert KNOWN_USERNAME not in saved
    assert KNOWN_PASSWORD not in saved
    assert result.actions[1].value_reference == "login-username"
    assert result.actions[2].value_reference == "login-password"


@pytest.mark.slow
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
                password_references=frozenset({"login-password"}),
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
                password_references=frozenset({"login-password"}),
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
                password_references=frozenset(),
                account_marker_selector="#marker",
            )
        )


@pytest.mark.slow
def test_saved_profile_revalidation_rejects_changed_control_metadata() -> None:
    with run_controlled_server() as origin:
        result = asyncio.run(run_verified_flow(origin))
        asyncio.run(
            revalidate_auth_profile(
                profile=result.profile,
                scan_id=uuid4(),
                password_references=frozenset(),
            )
        )
        # A profile saved before fingerprints is still checked by the
        # position-keyed signatures.
        legacy_profile = result.profile.model_copy(deep=True)
        legacy_profile.authentication_steps[AuthFeature.LOGIN] = [
            step.model_copy(update={"control_fingerprint": None})
            for step in legacy_profile.authentication_steps[AuthFeature.LOGIN]
        ]
        legacy_profile.control_signatures["control-5"] = "changed"

        with pytest.raises(StaleAuthProfileError, match="stale.*changed"):
            asyncio.run(
                revalidate_auth_profile(
                    profile=legacy_profile,
                    scan_id=uuid4(),
                    password_references=frozenset(),
                )
            )

        # A fingerprinted profile is checked by its fingerprints instead, so
        # the signatures no longer decide; a changed fingerprint does.
        fingerprinted = result.profile.model_copy(deep=True)
        fingerprinted.control_signatures["control-5"] = "changed"
        asyncio.run(
            revalidate_auth_profile(
                profile=fingerprinted,
                scan_id=uuid4(),
                password_references=frozenset(),
            )
        )
        username_step = fingerprinted.authentication_steps[AuthFeature.LOGIN][1]
        assert username_step.control_fingerprint is not None
        username_step.control_fingerprint = (
            username_step.control_fingerprint.model_copy(update={"name": "changed"})
        )

        with pytest.raises(StaleAuthProfileError, match="not on the page"):
            asyncio.run(
                revalidate_auth_profile(
                    profile=fingerprinted,
                    scan_id=uuid4(),
                    password_references=frozenset(),
                )
            )


def test_guided_navigation_keeps_hash_routes_but_not_token_fragments() -> None:
    origin = "http://127.0.0.1:3000"
    target = TargetScope(target_url=f"{origin}/#/login", permitted_origins=[origin])
    destinations = [
        f"{origin}/?session=do-not-save#/login",
        f"{origin}/#access_token=do-not-save",
    ]

    actions = _prepare_guided_actions(
        [
            BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=destination,
                description="Open the sign-in route",
            )
            for destination in destinations
        ],
        target,
        RuntimeSecrets({}),
    )

    assert [str(action.url) for action in actions] == [
        f"{origin}/#/login",
        f"{origin}/",
    ]


class ShiftingLoginHandler(BaseHTTPRequestHandler):
    """A login page that can gain controls before its form between visits.

    ``layout`` is set by the test: ``plain`` is the page as recorded,
    ``banner`` inserts a consent banner and a newsletter form before the login
    form, and ``renamed`` changes the login form's username field.
    """

    layout = "plain"
    newsletter_posts: list[str] = []

    def do_GET(self) -> None:
        if self.path.startswith("/account"):
            signed_in = "session=signed-in" in (self.headers.get("Cookie") or "")
            marker = '<p data-testid="account-marker">Welcome</p>' if signed_in else ""
            self._send(200, f"<title>Account</title>{marker}")
            return
        self._send(200, self._login_page())

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        if self.path.startswith("/newsletter"):
            type(self).newsletter_posts.append(self.path)
            self._send(200, "<title>Subscribed</title>")
            return
        if form.get("email") == [KNOWN_USERNAME] and form.get("password") == [
            KNOWN_PASSWORD
        ]:
            self.send_response(303)
            self.send_header("Location", "/account")
            self.send_header("Set-Cookie", "session=signed-in; Path=/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send(401, "<title>Login failed</title>")

    def _login_page(self) -> str:
        username_name = "user" if self.layout == "renamed" else "email"
        banner = ""
        if self.layout == "banner":
            banner = """
            <div id="consent">
                <input type="checkbox" name="analytics">
                <button type="button">Accept all</button>
                <a href="/privacy">Privacy</a>
            </div>
            <form action="/newsletter" method="post">
                <input type="email" name="email" placeholder="Newsletter">
                <button type="submit">Subscribe</button>
            </form>"""
        return f"""<title>Sign in</title>{banner}
            <form action="/session" method="post">
                <input type="email" name="{username_name}"
                       autocomplete="username">
                <input type="password" name="password"
                       autocomplete="current-password">
                <button type="submit">Sign in</button>
            </form>"""

    def _send(self, status: int, body: str) -> None:
        encoded = f"<!doctype html><html><body>{body}</body></html>".encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def run_shifting_login_server() -> Iterator[str]:
    ShiftingLoginHandler.layout = "plain"
    ShiftingLoginHandler.newsletter_posts = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ShiftingLoginHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


SHIFTING_SECRETS = {"login-username": KNOWN_USERNAME, "login-password": KNOWN_PASSWORD}


def replay_shifting_login(profile: AuthProfile) -> VerifiedLoginExecution:
    return asyncio.run(
        replay_verified_auth_profile(
            profile=profile,
            scan_id=uuid4(),
            runtime_secrets=RuntimeSecrets(SHIFTING_SECRETS),
            password_references=frozenset({"login-password"}),
            account_marker_selector='[data-testid="account-marker"]',
        )
    )


def without_fingerprints(profile: AuthProfile) -> AuthProfile:
    """The same profile as it would have been saved before fingerprints."""

    legacy = profile.model_copy(deep=True)
    legacy.authentication_steps[AuthFeature.LOGIN] = [
        step.model_copy(update={"control_fingerprint": None})
        for step in legacy.authentication_steps[AuthFeature.LOGIN]
    ]
    return legacy


@pytest.mark.slow
def test_a_saved_login_still_succeeds_after_controls_are_added_before_it() -> None:
    with run_shifting_login_server() as origin:
        recorded = asyncio.run(
            execute_verified_login_flow(
                scan_id=uuid4(),
                target=TargetScope(
                    target_url=f"{origin}/login", permitted_origins=[origin]
                ),
                runtime_secrets=RuntimeSecrets(SHIFTING_SECRETS),
                username_reference="login-username",
                password_reference="login-password",
                protected_resource=f"{origin}/account",
                account_marker_selector='[data-testid="account-marker"]',
                account_marker_description="The account page greets the user",
            )
        )
        steps = recorded.profile.authentication_steps[AuthFeature.LOGIN]
        assert [step.observed_control_id for step in steps[1:]] == [
            "control-1",
            "control-2",
            "control-3",
        ]
        assert all(step.control_fingerprint is not None for step in steps[1:])

        # A banner and a newsletter form now come first. By position,
        # control-1 would be the newsletter's email field: the username would
        # have been typed there.
        ShiftingLoginHandler.layout = "banner"
        asyncio.run(
            revalidate_auth_profile(
                profile=recorded.profile,
                scan_id=uuid4(),
                password_references=frozenset({"login-password"}),
            )
        )
        replayed = replay_shifting_login(recorded.profile)

        assert replayed.profile.features[AuthFeature.LOGIN] is FeatureStatus.VERIFIED
        assert ShiftingLoginHandler.newsletter_posts == []
        # The saved identity is kept, not replaced by today's positions.
        assert replayed.profile.authentication_steps[AuthFeature.LOGIN] == steps

        # A profile saved before fingerprints still guards by position: the
        # shifted page is reported stale instead of typing into the wrong
        # field.
        with pytest.raises(StaleAuthProfileError, match="control-1"):
            replay_shifting_login(without_fingerprints(recorded.profile))
        assert ShiftingLoginHandler.newsletter_posts == []


@pytest.mark.slow
def test_an_old_profile_replays_by_position_and_gains_fingerprints() -> None:
    with run_shifting_login_server() as origin:
        recorded = asyncio.run(
            execute_verified_login_flow(
                scan_id=uuid4(),
                target=TargetScope(
                    target_url=f"{origin}/login", permitted_origins=[origin]
                ),
                runtime_secrets=RuntimeSecrets(SHIFTING_SECRETS),
                username_reference="login-username",
                password_reference="login-password",
                protected_resource=f"{origin}/account",
                account_marker_selector='[data-testid="account-marker"]',
                account_marker_description="The account page greets the user",
            )
        )
        # As read from an auth-profile.json saved before fingerprints.
        saved = without_fingerprints(recorded.profile).model_dump(mode="json")
        for step in saved["authentication_steps"]["login"]:
            del step["control_fingerprint"]
        legacy = AuthProfile.model_validate(saved)

        replayed = replay_shifting_login(legacy)

    upgraded = replayed.profile.authentication_steps[AuthFeature.LOGIN]
    original = recorded.profile.authentication_steps[AuthFeature.LOGIN]
    assert [step.control_fingerprint for step in upgraded] == [
        step.control_fingerprint for step in original
    ]


@pytest.mark.slow
def test_a_saved_control_that_is_gone_asks_for_guidance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BrowserActionExecutor, "CONTROL_LOOKUP_TIMEOUT_SECONDS", 0.3)
    with run_shifting_login_server() as origin:
        recorded = asyncio.run(
            execute_verified_login_flow(
                scan_id=uuid4(),
                target=TargetScope(
                    target_url=f"{origin}/login", permitted_origins=[origin]
                ),
                runtime_secrets=RuntimeSecrets(SHIFTING_SECRETS),
                username_reference="login-username",
                password_reference="login-password",
                protected_resource=f"{origin}/account",
                account_marker_selector='[data-testid="account-marker"]',
                account_marker_description="The account page greets the user",
            )
        )

        ShiftingLoginHandler.layout = "renamed"
        expected = (
            "Step 2: The email input recorded for this flow as control-1 is not "
            "on the page, so the value was not typed into it."
        )
        # StaleAuthProfileError is the path the scan manager turns into a
        # request for guidance; a hard control refusal would fail the scan.
        with pytest.raises(StaleAuthProfileError) as revalidation:
            asyncio.run(
                revalidate_auth_profile(
                    profile=recorded.profile,
                    scan_id=uuid4(),
                    password_references=frozenset({"login-password"}),
                )
            )
        with pytest.raises(StaleAuthProfileError) as replay:
            replay_shifting_login(recorded.profile)

    assert str(revalidation.value) == expected
    assert str(replay.value) == expected
    assert isinstance(replay.value.__cause__, RecordedControlNotFoundError)
