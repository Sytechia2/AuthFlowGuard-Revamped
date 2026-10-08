"""CHK-005 and CHK-006 browser and offline analyser tests."""

import asyncio
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from authflowguard.authentication import VerifiedLoginExecution
from authflowguard.checks.logout_invalidation import (
    LogoutInvalidationRun,
    _find_logout_control,
    _submit_logout,
    analyse_logout_invalidation,
    run_logout_invalidation_check,
)
from authflowguard.checks.session_fixation import (
    SessionFixationRun,
    analyse_session_fixation,
    run_session_fixation_check,
)
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
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from playwright.async_api import async_playwright
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


def _replay_evidence(check: CheckId, **observations: Any) -> EvidencePackage:
    return EvidencePackage(
        evidence_id=uuid4(),
        scan_id=uuid4(),
        check_id=check,
        profile_version="1.0",
        observations={**observations, "captured_at": "2026-01-01T00:00:00+00:00"},
        coverage=Coverage(limitations=["Fixture evidence."]),
    )


AUTHENTICATED = {"status": 200, "marker_present": True}
SIGNED_OUT_500 = {"status": 500, "marker_present": False}


@pytest.mark.parametrize(
    ("replay", "anonymous", "expected"),
    [
        # Replay answered exactly like a signed-out visitor: the 500 is how
        # the application rejects unauthenticated requests.
        (SIGNED_OUT_500, SIGNED_OUT_500, CheckOutcome.NO_ISSUE_OBSERVED),
        # The account marker proves authentication despite an anonymous 500.
        (AUTHENTICATED, SIGNED_OUT_500, CheckOutcome.FINDING_CONFIRMED),
        # A server error only on the replay is still a failed procedure.
        (
            {"status": 503, "marker_present": False},
            {"status": 401, "marker_present": False},
            CheckOutcome.EXECUTION_ERROR,
        ),
        # Different server errors cannot be read as the same rejection.
        (
            {"status": 502, "marker_present": False},
            SIGNED_OUT_500,
            CheckOutcome.EXECUTION_ERROR,
        ),
        # A rejected replay cannot be compared with a failing baseline.
        (
            {"status": 401, "marker_present": False},
            SIGNED_OUT_500,
            CheckOutcome.EXECUTION_ERROR,
        ),
    ],
)
def test_session_fixation_compares_server_errors_with_signed_out_baseline(
    replay: dict[str, Any], anonymous: dict[str, Any], expected: CheckOutcome
) -> None:
    evidence = _replay_evidence(
        CheckId.SESSION_FIXATION,
        authenticated_control=AUTHENTICATED,
        original_session_replay=replay,
        anonymous_control=anonymous,
    )
    result = analyse_session_fixation(
        evidence, profile_for("http://app"), SecurityPolicy()
    )
    assert result.outcome is expected


def test_session_fixation_authenticated_server_error_is_execution_error() -> None:
    evidence = _replay_evidence(
        CheckId.SESSION_FIXATION,
        authenticated_control={"status": 500, "marker_present": True},
        original_session_replay=SIGNED_OUT_500,
        anonymous_control=SIGNED_OUT_500,
    )
    result = analyse_session_fixation(
        evidence, profile_for("http://app"), SecurityPolicy()
    )
    assert result.outcome is CheckOutcome.EXECUTION_ERROR


CLIENT_SIDE_LOGOUT = {
    "logout_status": None,
    "logout_method": "control",
    "logout_request_observed": False,
    "post_logout_control": SIGNED_OUT_500,
}


@pytest.mark.parametrize(
    ("logout", "expected"),
    [
        (CLIENT_SIDE_LOGOUT, CheckOutcome.FINDING_CONFIRMED),
        # Missing logout evidence stays inconclusive, as in A-CHK-006-ambiguous.
        ({"post_logout_control": SIGNED_OUT_500}, CheckOutcome.INCONCLUSIVE),
        # The browser still showed the account after logout: not demonstrated.
        (
            {**CLIENT_SIDE_LOGOUT, "post_logout_control": AUTHENTICATED},
            CheckOutcome.INCONCLUSIVE,
        ),
        # A logout request was sent but its status is unknown.
        (
            {**CLIENT_SIDE_LOGOUT, "logout_request_observed": True},
            CheckOutcome.INCONCLUSIVE,
        ),
    ],
)
def test_logout_accepts_only_a_demonstrated_client_side_logout(
    logout: dict[str, Any], expected: CheckOutcome
) -> None:
    evidence = _replay_evidence(
        CheckId.LOGOUT_INVALIDATION,
        authenticated_control=AUTHENTICATED,
        old_session_replay=AUTHENTICATED,
        anonymous_control=SIGNED_OUT_500,
        **logout,
    )
    result = analyse_logout_invalidation(
        evidence, profile_for("http://app"), SecurityPolicy()
    )
    assert result.outcome is expected
    if expected is CheckOutcome.FINDING_CONFIRMED:
        assert "sent no request" in result.explanation


def create_client_logout_app() -> FastAPI:
    """Like Juice Shop: logout sits in an account menu and only clears the
    browser, and signed-out visitors to the protected page get a 500."""

    application = FastAPI()
    session_value = "stateless-session"

    @application.get("/login", response_class=HTMLResponse)
    def login_page() -> str:
        return """<!doctype html><title>Shop</title>
        <nav>
            <button aria-label="Show account menu" aria-haspopup="menu"
                    onclick="document.getElementById('menu').hidden = false">
                Account
            </button>
            <div id="menu" hidden>
                <button onclick="document.cookie = 'session=; Max-Age=0; Path=/'">
                    Logout
                </button>
            </div>
        </nav>
        <form method="post" action="/login">
            <input name="username"><input name="password" type="password">
            <button type="submit">Log in</button>
        </form>"""

    @application.post("/login")
    def login() -> Response:
        response = RedirectResponse("/login", status_code=303)
        response.set_cookie("session", session_value, path="/")
        return response

    @application.get("/account", response_class=HTMLResponse)
    def account(request: Request) -> Response:
        if request.cookies.get("session") != session_value:
            return HTMLResponse("Blocked illegal activity", status_code=500)
        return HTMLResponse('<p data-testid="account-marker">Signed in</p>')

    return application


def test_client_side_menu_logout_is_found_and_reported() -> None:
    with serve(create_client_logout_app()) as origin:
        base_profile = profile_for(origin)
        navigate, *controls = base_profile.authentication_steps[AuthFeature.LOGIN]
        # The menu toggle and logout button come first on this page.
        shifted = [
            step.model_copy(update={"observed_control_id": f"control-{number}"})
            for step, number in zip(controls, (3, 4, 5), strict=True)
        ]
        profile = base_profile.model_copy(
            update={"authentication_steps": {AuthFeature.LOGIN: [navigate, *shifted]}}
        )
        secrets = RuntimeSecrets({"username": "user", "password": "pass"})
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

    observations = run.evidence.observations
    assert run.evidence.errors == []
    # Nothing was saved with this profile, so the check searched as before.
    assert observations["logout_source"] == "keyword_search"
    assert observations["logout_method"] == "control"
    assert observations["logout_request_observed"] is False
    assert observations["post_logout_control"]["marker_present"] is False
    result = analyse_logout_invalidation(run.evidence, profile, SecurityPolicy())
    assert result.outcome is CheckOutcome.FINDING_CONFIRMED


async def _search_for_logout(html: str) -> tuple[str | None, list[str]]:
    """Run the logout search on a page and report what it clicked."""

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content(html)
            control = await _find_logout_control(page)
            label = " ".join((await control.inner_text()).split()) if control else None
            return label, await page.evaluate("window.clicked")
        finally:
            await browser.close()


def test_logout_search_never_clicks_destructive_or_navigating_controls() -> None:
    """Controls whose labels mention the account, but that act or navigate
    rather than open a menu, sit before the real account menu."""

    found, clicked = asyncio.run(
        _search_for_logout(
            """<script>window.clicked = [];</script>
            <button aria-haspopup="true" onclick="clicked.push('delete')">
                Delete account</button>
            <button aria-expanded="false" onclick="clicked.push('close')">
                Close my profile</button>
            <a href="#/account" onclick="clicked.push('link')">My account</a>
            <button onclick="clicked.push('plain')">Edit profile</button>
            <button aria-haspopup="menu" onclick="clicked.push('menu');
                    document.getElementById('menu').hidden = false">
                Account</button>
            <div id="menu" hidden>
                <button onclick="clicked.push('delete-in-menu')">
                    Log out and delete account</button>
                <button>Log out</button>
            </div>"""
        )
    )

    assert found == "Log out"
    assert clicked == ["menu"]


def test_logout_search_stops_when_a_toggle_navigates() -> None:
    found, clicked = asyncio.run(
        _search_for_logout(
            """<script>window.clicked = [];</script>
            <button aria-haspopup="true"
                    onclick="clicked.push('user'); location.hash = '#/users'">
                Users</button>
            <button aria-haspopup="menu" onclick="clicked.push('menu')">
                Account</button>"""
        )
    )

    assert found is None
    assert clicked == ["user"]


def create_cross_origin_app(outside: str, *, redirect_anonymous: bool) -> FastAPI:
    """A login app whose pages also load content from ``outside``.

    Each page embeds an image and a background request to the other origin.
    With ``redirect_anonymous``, signed-out visitors to the protected page are
    redirected there instead, as an external sign-in service would.
    """

    application = FastAPI()
    sessions: set[str] = set()
    beacons = (
        f'<img src="{outside}/beacon.png" alt="">'
        f'<script>fetch("{outside}/fetch").catch(() => {{}});</script>'
    )

    @application.get("/login", response_class=HTMLResponse)
    def login_page() -> str:
        return f"""<!doctype html><title>Login</title>{beacons}
        <form method="post" action="/login">
            <input name="username"><input name="password" type="password">
            <button type="submit">Log in</button>
        </form>"""

    @application.post("/login")
    def login() -> Response:
        session = uuid4().hex
        sessions.add(session)
        response = RedirectResponse("/account", status_code=303)
        response.set_cookie("session", session, path="/")
        return response

    @application.get("/account", response_class=HTMLResponse)
    def account(request: Request) -> Response:
        if request.cookies.get("session") not in sessions:
            if redirect_anonymous:
                return RedirectResponse(f"{outside}/signin", status_code=302)
            return HTMLResponse(f"{beacons}<p>Sign in first</p>", status_code=401)
        return HTMLResponse(
            f"""{beacons}<p data-testid="account-marker">Signed in</p>
            <form method="post" action="/logout"><button>Log out</button></form>"""
        )

    @application.post("/logout")
    def logout(request: Request) -> Response:
        sessions.discard(request.cookies.get("session", ""))
        return RedirectResponse("/login", status_code=303)

    return application


def create_outside_app(received: list[str]) -> FastAPI:
    application = FastAPI()

    @application.get("/{path:path}", response_class=HTMLResponse)
    def anything(path: str) -> str:
        received.append(path)
        return '<p data-testid="account-marker">Outside scope</p>'

    return application


def run_cross_origin_check(check: CheckId, origin: str) -> tuple[AuthProfile, Any]:
    base_profile = profile_for(origin)
    navigate, *controls = base_profile.authentication_steps[AuthFeature.LOGIN]
    # The login form's controls are the only controls on the page.
    numbered = [
        step.model_copy(update={"observed_control_id": f"control-{number}"})
        for step, number in zip(controls, (1, 2, 3), strict=True)
    ]
    profile = base_profile.model_copy(
        update={"authentication_steps": {AuthFeature.LOGIN: [navigate, *numbered]}}
    )
    runner = (
        run_session_fixation_check
        if check is CheckId.SESSION_FIXATION
        else run_logout_invalidation_check
    )
    secrets = RuntimeSecrets({"username": "user", "password": "pass"})
    try:
        run = asyncio.run(
            runner(
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
    "check", [CheckId.SESSION_FIXATION, CheckId.LOGOUT_INVALIDATION]
)
def test_session_checks_never_send_requests_outside_scope(check: CheckId) -> None:
    """Every context the check opens, including the replay and anonymous
    ones, aborts requests to origins outside permitted_origins."""

    received: list[str] = []
    with serve(create_outside_app(received)) as outside:
        application = create_cross_origin_app(outside, redirect_anonymous=False)
        with serve(application) as origin:
            profile, run = run_cross_origin_check(check, origin)

    assert run.evidence.errors == []
    assert received == []
    assert not any(outside in str(event.redacted_details) for event in run.events)
    analyser = (
        analyse_session_fixation
        if check is CheckId.SESSION_FIXATION
        else analyse_logout_invalidation
    )
    result = analyser(run.evidence, profile, SecurityPolicy())
    assert result.outcome is CheckOutcome.NO_ISSUE_OBSERVED


@pytest.mark.parametrize(
    "check", [CheckId.SESSION_FIXATION, CheckId.LOGOUT_INVALIDATION]
)
def test_session_checks_never_read_a_page_redirected_outside_scope(
    check: CheckId,
) -> None:
    """A protected resource that redirects outside scope is not observed.

    The browser follows a redirect without consulting the scope guard, so
    the redirected request itself is not stopped; what the page then shows
    must not become evidence, and the check stops with an error.
    """

    received: list[str] = []
    with serve(create_outside_app(received)) as outside:
        application = create_cross_origin_app(outside, redirect_anonymous=True)
        with serve(application) as origin:
            profile, run = run_cross_origin_check(check, origin)

    assert run.evidence.errors == ["ValueError"]
    assert outside not in str(run.evidence.observations)
    assert not any(outside in str(event.redacted_details) for event in run.events)
    analyser = (
        analyse_session_fixation
        if check is CheckId.SESSION_FIXATION
        else analyse_logout_invalidation
    )
    result = analyser(run.evidence, profile, SecurityPolicy())
    assert result.outcome is CheckOutcome.EXECUTION_ERROR


def create_form_logout_app(html: str, posted: list[str]) -> FastAPI:
    """Serve ``html`` signed in and record every form the page submits."""

    application = FastAPI()

    @application.get("/account", response_class=HTMLResponse)
    def account() -> str:
        return html

    @application.post("/{path:path}", response_class=HTMLResponse)
    def submitted(path: str) -> str:
        posted.append(path)
        return "<p>Submitted</p>"

    return application


async def _submit_logout_on(origin: str) -> str | None:
    """Run the logout search on the served page; return its method or error."""

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.goto(f"{origin}/account")
            try:
                attempt = await _submit_logout(page, f"{origin}/account")
            except ValueError as error:
                return str(error)
            return attempt.method
        finally:
            await browser.close()


DESTRUCTIVE_LOGOUT_FORMS = [
    # The form's own action and submit label both look like logout.
    """<form method="post" action="/logout-everywhere">
        <button>Log out and delete account</button></form>""",
    # The form's text says log out; its submit control deletes the account.
    """<form method="post" action="/account/remove">
        <p>Log out of every device</p>
        <input type="submit" value="Delete account"></form>""",
]


@pytest.mark.parametrize("form", DESTRUCTIVE_LOGOUT_FORMS, ids=["button", "input"])
def test_logout_form_with_a_destructive_submit_is_never_submitted(form: str) -> None:
    posted: list[str] = []
    with serve(create_form_logout_app(form, posted)) as origin:
        outcome = asyncio.run(_submit_logout_on(origin))

    assert outcome == "The application has no identifiable logout control"
    assert posted == []


@pytest.mark.parametrize("form", DESTRUCTIVE_LOGOUT_FORMS, ids=["button", "input"])
def test_logout_search_skips_a_destructive_form_for_a_safe_one(form: str) -> None:
    safe = '<form method="post" action="/logout"><button>Log out</button></form>'
    posted: list[str] = []
    with serve(create_form_logout_app(form + safe, posted)) as origin:
        outcome = asyncio.run(_submit_logout_on(origin))

    assert outcome == "form"
    assert posted == ["logout"]
