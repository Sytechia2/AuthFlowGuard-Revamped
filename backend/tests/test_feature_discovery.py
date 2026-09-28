"""Discover, validate, verify, save and replay the non-login features.

Real browsers against small local applications. No test here reaches AWS:
model answers come from fakes, and the boto3 session is replaced so that a
mistake fails loudly instead of sending a request.
"""

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from authflowguard.auth_profiles import with_form_link
from authflowguard.authentication import (
    execute_guided_verified_login_flow,
    execute_verified_login_flow,
)
from authflowguard.checks.form_enumeration import LABELS
from authflowguard.checks.logout_invalidation import (
    analyse_logout_invalidation,
    run_logout_invalidation_check,
)
from authflowguard.checks.registration_enumeration import (
    run_registration_enumeration_check,
)
from authflowguard.checks.reset_request_enumeration import (
    run_reset_request_enumeration_check,
)
from authflowguard.control_roles import (
    ControlRole,
    RoleContext,
    RoleSuggestion,
    ValidatedRoles,
)
from authflowguard.evaluation.cost_tracking import CostLedger, UsageSource
from authflowguard.evaluation_targets.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
    EvaluationMode,
    create_controlled_app,
)
from authflowguard.feature_discovery import (
    FeatureDiscoveryRequest,
    FeatureDiscoveryResult,
    ObservedControls,
    RoleClassifier,
    discover_form_links,
)
from authflowguard.login_suggestions import (
    ClassificationBudget,
    classification_objective,
    classify_within_budget,
    observation_for_classification,
)
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    CheckId,
    CheckOutcome,
    DiscoveryMode,
    DiscoverySource,
    FeatureStatus,
    ScanRequest,
    SecurityPolicy,
    TargetScope,
)
from authflowguard.scan_manager import (
    GuidanceSubmission,
    ScanExecutionInput,
    ScanManager,
)
from authflowguard.secrets import RuntimeSecrets
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from playwright.async_api import async_playwright
from test_form_enumeration import CLIENT_APP_PAGE, client_form_app, serve
from test_login_suggestions import ScriptedClassifier
from test_session_checks import create_client_logout_app

MARKER = '[data-testid="account-marker"]'
LOGOUT_ONLY = frozenset({AuthFeature.LOGOUT})


@pytest.fixture(autouse=True)
def no_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("A test tried to create a real AWS session")

    monkeypatch.setattr("authflowguard.bedrock.boto3.Session", refuse)


def account_app(account_controls: str, *, logout_signs_out: bool = True) -> FastAPI:
    """A server-rendered app whose account page holds ``account_controls``.

    Every irreversible request is counted, so a test can prove that nothing
    destructive was clicked.
    """

    application = FastAPI()
    application.state.deleted = 0
    application.state.logouts = 0
    session = "signed-in-session"

    @application.get("/login", response_class=HTMLResponse)
    def login_page() -> str:
        return """<!doctype html><title>Sign in</title>
        <form method="post" action="/login">
          <input name="username" type="email" autocomplete="username">
          <input name="password" type="password" autocomplete="current-password">
          <button type="submit">Sign in</button>
        </form>"""

    @application.post("/login")
    def login() -> Response:
        response = RedirectResponse("/account", status_code=303)
        response.set_cookie("session", session, path="/")
        return response

    @application.get("/account", response_class=HTMLResponse)
    def account(request: Request) -> Response:
        if request.cookies.get("session") != session:
            return HTMLResponse("<p>Please sign in</p>", status_code=401)
        return HTMLResponse(
            f"""<!doctype html><title>Account</title>
            <p data-testid="account-marker">Signed in</p>{account_controls}"""
        )

    @application.post("/delete")
    def delete() -> Response:
        application.state.deleted += 1
        return Response(status_code=204)

    @application.post("/logout")
    def logout() -> Response:
        application.state.logouts += 1
        response = RedirectResponse("/login", status_code=303)
        if logout_signs_out:
            response.delete_cookie("session", path="/")
        return response

    return application


def scope_for(origin: str, login_path: str = "/login") -> TargetScope:
    return TargetScope(target_url=f"{origin}{login_path}", permitted_origins=[origin])


def rules_login(
    origin: str, feature_discovery: FeatureDiscoveryRequest | None
) -> AuthProfile:
    secrets = RuntimeSecrets({"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD})
    execution = asyncio.run(
        execute_verified_login_flow(
            scan_id=uuid4(),
            target=scope_for(origin),
            runtime_secrets=secrets,
            username_reference="username",
            password_reference="password",
            protected_resource=f"{origin}/account",
            account_marker_selector=MARKER,
            account_marker_description="Account marker",
            feature_discovery=feature_discovery,
        )
    )
    return execution.profile


def run_logout_check(origin: str, profile: AuthProfile) -> Any:
    secrets = RuntimeSecrets({"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD})
    return asyncio.run(
        run_logout_invalidation_check(
            profile=profile,
            scan_id=uuid4(),
            runtime_secrets=secrets,
            username_reference="username",
            password_reference="password",
            protected_resource=f"{origin}/account",
            account_marker_selector=MARKER,
        )
    )


def test_logout_behind_an_account_menu_is_verified_saved_and_replayed() -> None:
    with serve(create_client_logout_app()) as origin:
        secrets = RuntimeSecrets(
            {"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD}
        )
        execution = asyncio.run(
            execute_guided_verified_login_flow(
                scan_id=uuid4(),
                target=scope_for(origin),
                runtime_secrets=secrets,
                actions=[
                    BrowserAction(
                        action_type=BrowserActionType.NAVIGATE,
                        url=f"{origin}/login",
                        description="Open login",
                    ),
                    BrowserAction(
                        action_type=BrowserActionType.FILL,
                        observed_control_id="control-3",
                        value_reference="username",
                        description="Fill username",
                    ),
                    BrowserAction(
                        action_type=BrowserActionType.FILL,
                        observed_control_id="control-4",
                        value_reference="password",
                        description="Fill password",
                    ),
                    BrowserAction(
                        action_type=BrowserActionType.CLICK,
                        observed_control_id="control-5",
                        description="Submit login",
                    ),
                ],
                password_references=frozenset({"password"}),
                protected_resource=f"{origin}/account",
                account_marker_selector=MARKER,
                account_marker_description="Account marker",
                feature_discovery=FeatureDiscoveryRequest(features=LOGOUT_ONLY),
            )
        )
        profile = execution.profile

        assert profile.features[AuthFeature.LOGOUT] is FeatureStatus.VERIFIED
        steps = profile.authentication_steps[AuthFeature.LOGOUT]
        # The account page has no navigation, so the start page is used:
        # open it, open the account menu, then click logout inside it.
        assert [step.action_type for step in steps] == [
            BrowserActionType.NAVIGATE,
            BrowserActionType.CLICK,
            BrowserActionType.CLICK,
        ]
        assert all(step.control_fingerprint is not None for step in steps[1:])
        assert steps[2].control_fingerprint is not None
        assert steps[2].control_fingerprint.text == "Logout"
        logout_record = profile.discovery_history[-1]
        assert logout_record.feature is AuthFeature.LOGOUT
        assert logout_record.verified is True
        assert profile.discovery_history[0].feature is AuthFeature.LOGIN

        run = run_logout_check(origin, profile)

    observations = run.evidence.observations
    assert run.evidence.errors == []
    assert observations["logout_source"] == "saved_profile"
    assert observations["logout_method"] == "control"
    assert observations["logout_request_observed"] is False
    assert observations["post_logout_control"]["marker_present"] is False
    result = analyse_logout_invalidation(run.evidence, profile, SecurityPolicy())
    assert result.outcome is CheckOutcome.FINDING_CONFIRMED


def test_a_page_whose_only_match_is_delete_account_saves_and_clicks_nothing() -> None:
    application = account_app(
        """<button aria-haspopup="menu"
                   onclick="fetch('/delete', {method: 'POST'})">Delete account</button>
           <button onclick="fetch('/delete', {method: 'POST'})">
             Log out and delete account</button>"""
    )
    with serve(application) as origin:
        profile = rules_login(origin, FeatureDiscoveryRequest(features=LOGOUT_ONLY))

    assert AuthFeature.LOGOUT not in profile.features
    assert AuthFeature.LOGOUT not in profile.authentication_steps
    assert application.state.deleted == 0


def test_a_logout_that_leaves_the_account_signed_in_is_not_saved() -> None:
    application = account_app(
        """<form method="post" action="/logout"><button>Log out</button></form>""",
        logout_signs_out=False,
    )
    with serve(application) as origin:
        profile = rules_login(origin, FeatureDiscoveryRequest(features=LOGOUT_ONLY))

    assert AuthFeature.LOGOUT not in profile.features
    # It was tried once, in the throwaway verification context.
    assert application.state.logouts == 1


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        # Vulnerable logout keeps the browser signed in: nothing is saved and
        # the check searches as it always did.
        (EvaluationMode.VULNERABLE, None),
        (EvaluationMode.SECURE, "saved_profile"),
    ],
)
def test_controlled_app_logout_is_saved_only_when_it_signs_out(
    mode: EvaluationMode, expected: str | None
) -> None:
    with serve(create_controlled_app(mode)) as origin:
        profile = rules_login(origin, FeatureDiscoveryRequest(features=LOGOUT_ONLY))
        run = run_logout_check(origin, profile)

    assert (AuthFeature.LOGOUT in profile.features) is (expected is not None)
    assert run.evidence.errors == []
    assert run.evidence.observations["logout_source"] == (expected or "keyword_search")
    outcome = analyse_logout_invalidation(
        run.evidence, profile, SecurityPolicy()
    ).outcome
    assert outcome is (
        CheckOutcome.FINDING_CONFIRMED
        if mode is EvaluationMode.VULNERABLE
        else CheckOutcome.NO_ISSUE_OBSERVED
    )


# --- The AI path, with fakes -------------------------------------------------


def fake_classifier(
    answer: list[RoleSuggestion], ledger: CostLedger
) -> tuple[RoleClassifier, ScriptedClassifier]:
    """A classifier that spends through the real budget code and a fake model."""

    client = ScriptedClassifier(answer)
    budget = ClassificationBudget(
        scan_id=uuid4(),
        limit_usd=0.25,
        ledger=ledger,
        ledger_store=None,
        usage_source=UsageSource.MOCK,
        model_id="amazon.nova-micro-v1:0",
    )

    async def classify(
        observed: ObservedControls,
        roles: tuple[ControlRole, ...],
        context: RoleContext,
    ) -> ValidatedRoles | None:
        observation = observation_for_classification(
            page_url=observed.page_url,
            page_title=observed.page_title,
            controls=observed.controls,
            redact=str,
            objective=classification_objective(roles),
        )
        return classify_within_budget(
            client, observation, observed.controls, budget, roles=roles, context=context
        ).roles

    return classify, client


# Rules find nothing: the logout button says only "Leave".
AI_ONLY_ACCOUNT = """
    <button onclick="fetch('/delete', {method: 'POST'})">Delete account</button>
    <form method="post" action="/logout"><button>Leave</button></form>"""


def test_ai_logout_is_validated_verified_saved_and_costed() -> None:
    application = account_app(AI_ONLY_ACCOUNT)
    ledger = CostLedger()
    # Controls: control-1 "Delete account", control-2 "Leave".
    classify, client = fake_classifier(
        [RoleSuggestion("control-2", ControlRole.LOGOUT)], ledger
    )
    with serve(application) as origin:
        profile = rules_login(
            origin, FeatureDiscoveryRequest(features=LOGOUT_ONLY, classify=classify)
        )

    assert profile.features[AuthFeature.LOGOUT] is FeatureStatus.VERIFIED
    assert profile.discovery_history[-1].notes is not None
    assert "AI" in profile.discovery_history[-1].notes
    assert len(client.observations) == 1
    assert "logout" in client.observations[0].objective
    assert application.state.deleted == 0
    # One reservation and its reconciliation.
    assert [entry.is_reservation for entry in ledger] == [True, False]


def test_a_malicious_ai_logout_answer_is_rejected() -> None:
    application = account_app(AI_ONLY_ACCOUNT)
    ledger = CostLedger()
    classify, _client = fake_classifier(
        [RoleSuggestion("control-1", ControlRole.LOGOUT)], ledger
    )
    with serve(application) as origin:
        profile = rules_login(
            origin, FeatureDiscoveryRequest(features=LOGOUT_ONLY, classify=classify)
        )

    assert AuthFeature.LOGOUT not in profile.features
    assert application.state.deleted == 0
    assert application.state.logouts == 0


def test_rules_mode_scans_get_no_classifier(tmp_path: Path) -> None:
    manager = ScanManager(tmp_path, worker_backend="thread")
    try:
        execution = ScanExecutionInput(
            runtime_secrets={"u": "user", "p": "pass"},
            username_reference="u",
            password_reference="p",
            nonexistent_identifier_reference="u",
            failure_password_reference="p",
            protected_resource="https://app.example/account",
            account_marker_selector="#marker",
            account_marker_description="Marker",
        )
        requests = {}
        for mode in DiscoveryMode:
            record = manager.create_scan(
                ScanRequest(
                    target={
                        "target_url": "https://app.example/login",
                        "permitted_origins": ["https://app.example"],
                    },
                    selected_checks=[CheckId.LOGOUT_INVALIDATION],
                    discovery_mode=mode,
                )
            )
            requests[mode] = manager._feature_discovery(record, execution)
    finally:
        manager.shutdown()

    assert requests[DiscoveryMode.RULES].classify is None
    assert requests[DiscoveryMode.BEDROCK].classify is not None
    assert requests[DiscoveryMode.RULES].features == LOGOUT_ONLY


# --- Registration and reset links --------------------------------------------

HASH_LOGIN_PAGE = CLIENT_APP_PAGE.replace(
    'view.innerHTML = "<p>Signed out</p>";',
    """view.innerHTML = `<a href="#/register">Not yet a customer?</a>
        <a href="#/forgot-password">Forgot your password?</a>
        <a href="https://outside.example/partner">Register as a partner</a>`;""",
)


def hash_routed_app() -> FastAPI:
    application = client_form_app(vulnerable=True)
    application.router.routes = [
        route
        for route in application.router.routes
        if getattr(route, "path", None) != "/app"
    ]

    @application.get("/app")
    async def page() -> HTMLResponse:
        return HTMLResponse(HASH_LOGIN_PAGE)

    return application


def form_profile(origin: str) -> AuthProfile:
    return AuthProfile(
        target=scope_for(origin, "/app#/login"),
        features={AuthFeature.LOGIN: FeatureStatus.VERIFIED},
        authentication_steps={
            AuthFeature.LOGIN: [
                BrowserAction(
                    action_type=BrowserActionType.NAVIGATE,
                    url=f"{origin}/app#/login",
                    description="Open login",
                )
            ]
        },
    )


async def find_links(
    origin: str, request: FeatureDiscoveryRequest
) -> tuple[list[Any], Any]:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            return await discover_form_links(
                browser=browser,
                scan_id=uuid4(),
                target=scope_for(origin, "/app#/login"),
                page_url=f"{origin}/app#/login",
                request=request,
            )
        finally:
            await browser.close()


def run_form_check(
    check: CheckId, profile: AuthProfile, form_url: str | None = None
) -> Any:
    secrets = RuntimeSecrets(
        {
            "known": KNOWN_USERNAME,
            "missing": "disposable@example.test",
            "password": "disposable-password-123!",
        }
    )
    runner: Callable[..., Awaitable[Any]]
    options: dict[str, Any] = {}
    if check is CheckId.REGISTRATION_ENUMERATION:
        runner = run_registration_enumeration_check
        options["registration_password_reference"] = "password"
    else:
        runner = run_reset_request_enumeration_check
    return asyncio.run(
        runner(
            profile=profile,
            scan_id=uuid4(),
            runtime_secrets=secrets,
            known_identifier_reference="known",
            nonexistent_identifier_reference="missing",
            form_url=form_url,
            **options,
        )
    )


BOTH_FORMS = frozenset({AuthFeature.REGISTRATION, AuthFeature.RESET_REQUEST})


def test_hash_routed_links_are_saved_and_used_by_the_form_checks() -> None:
    with serve(hash_routed_app()) as origin:
        # "Not yet a customer?" says nothing the rules recognise, and the
        # partner link leaves the scope: the developer's choice is validated
        # and saved, and the rules find the reset link.
        guided, guided_event = asyncio.run(
            find_links(
                origin,
                FeatureDiscoveryRequest(
                    features=BOTH_FORMS,
                    chosen_links={
                        ControlRole.REGISTRATION_LINK: "control-1",
                        ControlRole.RESET_LINK: "control-2",
                    },
                ),
            )
        )
        rules, rules_event = asyncio.run(
            find_links(origin, FeatureDiscoveryRequest(features=BOTH_FORMS))
        )
        outside, outside_event = asyncio.run(
            find_links(
                origin,
                FeatureDiscoveryRequest(
                    features=BOTH_FORMS,
                    chosen_links={
                        ControlRole.REGISTRATION_LINK: "control-3",
                        ControlRole.RESET_LINK: None,
                    },
                ),
            )
        )

        assert {(link.feature, link.form_url) for link in guided} == {
            (AuthFeature.REGISTRATION, f"{origin}/app#/register"),
            (AuthFeature.RESET_REQUEST, f"{origin}/app#/forgot-password"),
        }
        assert [(link.feature, link.source.value) for link in rules] == [
            (AuthFeature.RESET_REQUEST, "rules")
        ]
        assert outside == []
        assert outside_event.redacted_details["rejected"] == [
            {
                "observed_control_id": "control-3",
                "role": "registration_link",
                "reason": "out_of_scope",
            }
        ]

        profile = FeatureDiscoveryResult(links=guided).apply_to(form_profile(origin))
        assert profile.features[AuthFeature.REGISTRATION] is FeatureStatus.FOUND
        registration = run_form_check(CheckId.REGISTRATION_ENUMERATION, profile)
        reset = run_form_check(CheckId.RESET_REQUEST_ENUMERATION, profile)
        # Without a saved feature the keyword search cannot name this
        # registration link, as before.
        unsaved = run_form_check(CheckId.REGISTRATION_ENUMERATION, form_profile(origin))

    for run in (registration, reset):
        assert run.evidence.errors == []
        assert run.evidence.observations["form_url_source"] == "saved_profile"
        assert run.evidence.observations[LABELS[0]]["interaction"] == "client"
    assert unsaved.evidence.observations["form_url_source"] == "keyword_search"
    assert unsaved.evidence.errors == ["ValueError"]


def test_an_explicit_form_url_wins_over_the_saved_one() -> None:
    with serve(hash_routed_app()) as origin:
        profile = with_form_link(
            form_profile(origin),
            AuthFeature.RESET_REQUEST,
            f"{origin}/app#/missing",
            DiscoverySource.AUTOMATIC,
            "stale",
        )
        run = run_form_check(
            CheckId.RESET_REQUEST_ENUMERATION,
            profile,
            form_url=f"{origin}/app#/forgot-password",
        )

    assert run.evidence.errors == []
    assert run.evidence.observations["form_url_source"] == "scan_input"


def test_guided_link_answers_are_validated_and_always_looked_for(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError):
        GuidanceSubmission.model_validate(
            {
                "actions": [
                    {
                        "action_type": "navigate",
                        "url": "https://app.example/login",
                        "description": "Open login",
                    }
                ],
                "feature_links": {"registration_link": "a[href='/x']"},
            }
        )
    guidance = GuidanceSubmission.model_validate(
        {
            "actions": [
                {
                    "action_type": "navigate",
                    "url": "https://app.example/login",
                    "description": "Open login",
                }
            ],
            "feature_links": {"registration_link": "control-4", "reset_link": None},
        }
    )
    manager = ScanManager(tmp_path, worker_backend="thread")
    try:
        record = manager.create_scan(
            ScanRequest(
                target={
                    "target_url": "https://app.example/login",
                    "permitted_origins": ["https://app.example"],
                },
                selected_checks=[CheckId.LOGIN_ENUMERATION],
            )
        )
        execution = ScanExecutionInput(
            runtime_secrets={"u": "user", "p": "pass"},
            username_reference="u",
            password_reference="p",
            nonexistent_identifier_reference="u",
            failure_password_reference="p",
            protected_resource="https://app.example/account",
            account_marker_selector="#marker",
            account_marker_description="Marker",
        )
        request = manager._feature_discovery(record, execution, guidance)
    finally:
        manager.shutdown()

    # The developer's answer is saved whichever checks run; "None" is not
    # replaced by a rules search.
    assert request.features == frozenset({AuthFeature.REGISTRATION})
    assert request.chosen_links == {
        ControlRole.REGISTRATION_LINK: "control-4",
        ControlRole.RESET_LINK: None,
    }
