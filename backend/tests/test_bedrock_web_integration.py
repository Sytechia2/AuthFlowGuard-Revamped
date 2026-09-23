"""End-to-end integration tests for Bedrock web discovery and authentication flows.

Covers Task 2.6 / INT-011 requirements:
- Full API scan using DeterministicModelDouble against Application A.
- Multi-page navigation discovery & replay with step_control_signatures.
- Application C two-form disambiguation using model double.
- Proof rejection test (account marker visible anonymously halts).
- Replay control signature validation (tampered control rejects replay).
- Durable accounting reservation persistence before model call and reconciliation.
- Secret redaction in outbound model observation.
- Handling unconfigured Bedrock client gracefully.
- Reload persisted scan from disk with cost ledger and provenance.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.parse import parse_qs
from uuid import UUID, uuid4

import pytest
import uvicorn
from authflowguard.app import create_app
from authflowguard.authentication import (
    StaleAuthProfileError,
    execute_ai_verified_login_flow,
    replay_verified_auth_profile,
    revalidate_auth_profile,
)
from authflowguard.automatic_actions import (
    AutomaticBrowserController,
)
from authflowguard.bedrock import BedrockResponseError, PageObservationForModel
from authflowguard.evaluation.cost_tracking import (
    CostLedger,
    CostLedgerStore,
    UsageSource,
    WorkflowPhase,
)
from authflowguard.evaluation.discovery_reliability import EvaluationBudget
from authflowguard.evaluation.model_double import DeterministicModelDouble
from authflowguard.evaluation_targets.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
    EvaluationMode,
    create_controlled_app,
)
from authflowguard.evaluation_targets.site_app import (
    KNOWN_MEMBER_ID,
    KNOWN_PASSPHRASE,
    create_site_app,
)
from authflowguard.models import (
    AuthFeature,
    BrowserAction,
    BrowserActionType,
    CheckId,
    DiscoveryMode,
    ExecutionLimits,
    FeatureStatus,
    TargetScope,
)
from authflowguard.scan_manager import ScanManager, ScanState
from authflowguard.secrets import RuntimeSecrets
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.testclient import TestClient
from playwright.async_api import async_playwright


@contextmanager
def run_app_server(application: FastAPI) -> Iterator[str]:
    """Run an in-process HTTP test server on an ephemeral port."""
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.bind(("127.0.0.1", 0))
    listening_socket.listen()
    port = listening_socket.getsockname()[1]

    server = uvicorn.Server(
        uvicorn.Config(
            application,
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
        raise RuntimeError("Test HTTP server did not start in time")

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listening_socket.close()


def create_multipage_app() -> FastAPI:
    """A multi-page application requiring navigation from landing page to login."""
    app = FastAPI(title="Multi-page Application")
    sessions: set[str] = set()

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse("""<!doctype html>
<html>
  <head><title>Portal Home</title></head>
  <body>
    <h1>Welcome to the Member Portal</h1>
    <nav>
      <a href="/portal/login" id="signin-link">Sign in to Member Portal</a>
    </nav>
  </body>
</html>""")

    @app.get("/portal/login", response_class=HTMLResponse)
    async def login_form() -> HTMLResponse:
        return HTMLResponse("""<!doctype html>
<html>
  <head><title>Member Login</title></head>
  <body>
    <h1>Member Login</h1>
    <form method="post" action="/portal/login">
      <label>Email <input name="username" type="email" autocomplete="username"></label>
      <label>Password <input name="password" type="password"></label>
      <button type="submit" id="submit-btn">Enter Portal</button>
    </form>
  </body>
</html>""")

    @app.post("/portal/login")
    async def do_login(request: Request) -> Response:
        body = (await request.body()).decode("utf-8")
        parsed = parse_qs(body)
        username = parsed.get("username", [""])[0]
        password = parsed.get("password", [""])[0]
        if username == "member@portal.test" and password == "portal-secret-123":
            resp = RedirectResponse("/portal/dashboard", status_code=303)
            resp.set_cookie("portal_sess", "sess-auth-99", httponly=True)
            sessions.add("sess-auth-99")
            return resp
        return HTMLResponse("<h1>Invalid Credentials</h1>", status_code=401)

    @app.get("/portal/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        sess = request.cookies.get("portal_sess")
        if sess in sessions:
            return HTMLResponse("""<!doctype html>
<html>
  <head><title>Portal Dashboard</title></head>
  <body>
    <h1>Member Dashboard</h1>
    <div id="account-marker" data-testid="account-marker">Member</div>
  </body>
</html>""")
        return HTMLResponse("<h1>Unauthorized</h1>", status_code=401)

    return app


def test_full_api_bedrock_scan_against_application_a(tmp_path: Path) -> None:
    """Test 1: Full API scan using DeterministicModelDouble against Application A."""
    with run_app_server(create_controlled_app(EvaluationMode.SECURE)) as origin:
        app = create_app(
            data_root=tmp_path,
            action_client_factory=lambda: DeterministicModelDouble(),
        )
        client = TestClient(app)

        scan_payload = {
            "target": {
                "target_url": f"{origin}/login",
                "permitted_origins": [origin],
            },
            "selected_checks": [CheckId.LOGIN_ENUMERATION.value],
            "discovery_mode": "bedrock",
            "reuse_saved_profile": False,
        }
        create_res = client.post("/api/scans", json=scan_payload)
        assert create_res.status_code == 201
        scan_id = create_res.json()["scan_id"]

        start_payload = {
            "runtime_secrets": {
                "username": KNOWN_USERNAME,
                "password": KNOWN_PASSWORD,
                "missing": "missing@example.test",
                "failure": "wrong-password",
            },
            "username_reference": "username",
            "password_reference": "password",
            "nonexistent_identifier_reference": "missing",
            "failure_password_reference": "failure",
            "protected_resource": f"{origin}/account",
            "account_marker_selector": '[data-testid="account-marker"]',
            "account_marker_description": "Authenticated account marker",
        }
        start_res = client.post(f"/api/scans/{scan_id}/start", json=start_payload)
        assert start_res.status_code == 200

        # Wait until scan completes
        orig_record = app.state.scan_manager.get_scan(UUID(scan_id))
        if orig_record.future is not None:
            orig_record.future.result(timeout=60)

        status = client.get(f"/api/scans/{scan_id}").json()
        assert status.get("state") == "completed", f"Scan did not complete: {status}"
        assert status.get("phase") == "completed"

        # Verify Bedrock provenance & accounting metrics
        provenance = status.get("provenance", {})
        assert provenance.get("requested_mode") == "bedrock"
        assert provenance.get("actual_engine") == "bedrock"
        assert provenance.get("usage_source") == "mock"
        assert provenance.get("reused_profile") is False

        assert status.get("decision_count", 0) >= 3
        assert status.get("model_request_count", 0) >= 3
        assert status.get("total_input_tokens", 0) > 0
        assert status.get("total_output_tokens", 0) > 0
        assert status.get("estimated_cost_usd", 0.0) > 0.0
        assert status.get("unresolved_reservations_usd", 0.0) == 0.0

        # Verify check results ran downstream
        results = status.get("results", [])
        assert len(results) >= 1
        assert results[0]["check_id"] == CheckId.LOGIN_ENUMERATION.value

        # Verify report download works
        report_res = client.get(f"/api/scans/{scan_id}/report/json")
        assert report_res.status_code == 200

        # Verify ledger file exists on disk and is durable
        ledger_path = tmp_path / scan_id / "cost-ledger.ndjson"
        assert ledger_path.exists()
        store = CostLedgerStore(ledger_path)
        entries = store.load()
        assert len(entries) >= 6  # At least 3 reservations + 3 reconciliations
        reservations = [e for e in entries if e.is_reservation]
        reconciliations = [e for e in entries if not e.is_reservation and e.reconciled]
        assert len(reservations) == len(reconciliations)


def test_multipage_navigation_discovery_and_replay() -> None:
    """Test 2: Multi-page navigation discovery & replay with step_control_signatures."""
    with run_app_server(create_multipage_app()) as origin:
        target = TargetScope(
            target_url=f"{origin}/",
            permitted_origins=[origin],
        )
        runtime_secrets = RuntimeSecrets(
            {
                "user-ref": "member@portal.test",
                "pass-ref": "portal-secret-123",
            }
        )
        double = DeterministicModelDouble()

        # Step 1: Discover via Bedrock controller
        scan_id = uuid4()
        execution = asyncio.run(
            execute_ai_verified_login_flow(
                scan_id=scan_id,
                target=target,
                runtime_secrets=runtime_secrets,
                username_reference="user-ref",
                password_reference="pass-ref",
                protected_resource=f"{origin}/portal/dashboard",
                account_marker_selector='[data-testid="account-marker"]',
                account_marker_description="Dashboard member marker",
                action_client=double,
                limits=ExecutionLimits(maximum_ai_decisions=10),
            )
        )

        profile = execution.profile
        assert profile.features[AuthFeature.LOGIN] is FeatureStatus.VERIFIED
        assert profile.discovery_history[-1].source == "automatic"

        # Verify step_control_signatures exist for every step
        steps = profile.authentication_steps[AuthFeature.LOGIN]
        assert (
            len(steps) >= 4
        )  # NAVIGATE -> CLICK link -> FILL user -> FILL pass -> CLICK submit
        assert len(profile.step_control_signatures) >= len(steps)

        # Step 2: Revalidate profile in a fresh context
        asyncio.run(revalidate_auth_profile(profile=profile, scan_id=scan_id))

        # Step 3: Replay profile in an isolated context
        replay_execution = asyncio.run(
            replay_verified_auth_profile(
                profile=profile,
                scan_id=scan_id,
                runtime_secrets=runtime_secrets,
                account_marker_selector='[data-testid="account-marker"]',
            )
        )
        assert (
            replay_execution.profile.features[AuthFeature.LOGIN]
            is FeatureStatus.VERIFIED
        )


def test_failed_action_is_excluded_from_saved_replay() -> None:
    with run_app_server(create_controlled_app(EvaluationMode.SECURE)) as origin:
        target = TargetScope(target_url=f"{origin}/login", permitted_origins=[origin])
        secrets = RuntimeSecrets(
            {"username": KNOWN_USERNAME, "password": KNOWN_PASSWORD}
        )
        failed_fill = BrowserAction(
            action_type=BrowserActionType.FILL,
            observed_control_id="control-999",
            value_reference="username",
            description="Unavailable control",
        )
        double = DeterministicModelDouble(scripted_actions=[failed_fill])
        scan_id = uuid4()
        execution = asyncio.run(
            execute_ai_verified_login_flow(
                scan_id=scan_id,
                target=target,
                runtime_secrets=secrets,
                username_reference="username",
                password_reference="password",
                protected_resource=f"{origin}/account",
                account_marker_selector='[data-testid="account-marker"]',
                account_marker_description="Account marker",
                action_client=double,
                limits=ExecutionLimits(maximum_ai_decisions=10),
            )
        )
        profile = execution.profile
        steps = profile.authentication_steps[AuthFeature.LOGIN]
        assert len(profile.step_control_signatures) == len(steps)
        assert all(step.observed_control_id != "control-999" for step in steps)
        assert any(event.kind.value == "error" for event in execution.events)
        asyncio.run(
            replay_verified_auth_profile(
                profile=profile,
                scan_id=uuid4(),
                runtime_secrets=secrets,
                account_marker_selector='[data-testid="account-marker"]',
            )
        )


def test_application_c_two_form_disambiguation_with_model_double() -> None:
    """Test 3: Application C two-form disambiguation using model double."""
    with run_app_server(create_site_app(EvaluationMode.SECURE)) as origin:
        target = TargetScope(
            target_url=f"{origin}/desk/entry",
            permitted_origins=[origin],
        )
        runtime_secrets = RuntimeSecrets(
            {
                "member_id": KNOWN_MEMBER_ID,
                "passphrase": KNOWN_PASSPHRASE,
            }
        )
        double = DeterministicModelDouble()

        execution = asyncio.run(
            execute_ai_verified_login_flow(
                scan_id=uuid4(),
                target=target,
                runtime_secrets=runtime_secrets,
                username_reference="member_id",
                password_reference="passphrase",
                protected_resource=f"{origin}/desk/bookings",
                account_marker_selector=".booking-holder",
                account_marker_description="Workshop booking holder marker",
                action_client=double,
                limits=ExecutionLimits(maximum_ai_decisions=10),
            )
        )

        profile = execution.profile
        assert profile.features[AuthFeature.LOGIN] is FeatureStatus.VERIFIED
        # Ensure it filled the login controls, not the search form
        step_types = [
            step.action_type for step in profile.authentication_steps[AuthFeature.LOGIN]
        ]
        assert BrowserActionType.FILL in step_types
        assert BrowserActionType.CLICK in step_types


def test_proof_rejection_halts_when_marker_visible_anonymously() -> None:
    """Test 4: Proof rejection test (account marker visible anonymously halts)."""
    with run_app_server(create_controlled_app(EvaluationMode.SECURE)) as origin:
        target = TargetScope(
            target_url=f"{origin}/login",
            permitted_origins=[origin],
        )
        runtime_secrets = RuntimeSecrets(
            {
                "username": KNOWN_USERNAME,
                "password": KNOWN_PASSWORD,
            }
        )
        double = DeterministicModelDouble()

        # Marker selector 'h1' is present anonymously, so proof must fail
        with pytest.raises(Exception) as exc_info:
            asyncio.run(
                execute_ai_verified_login_flow(
                    scan_id=uuid4(),
                    target=target,
                    runtime_secrets=runtime_secrets,
                    username_reference="username",
                    password_reference="password",
                    protected_resource=f"{origin}/account",
                    account_marker_selector="h1",
                    account_marker_description="Header element",
                    action_client=double,
                    limits=ExecutionLimits(maximum_ai_decisions=10),
                )
            )

        assert "Authentication proof failed" in str(exc_info.value) or (
            "visible in anonymous context" in str(exc_info.value)
        )


def test_replay_control_signature_validation_rejects_tampered_control() -> None:
    """Test 5: Replay control signature validation (tampered control rejects replay)."""
    with run_app_server(create_controlled_app(EvaluationMode.SECURE)) as origin:
        target = TargetScope(
            target_url=f"{origin}/login",
            permitted_origins=[origin],
        )
        runtime_secrets = RuntimeSecrets(
            {
                "username": KNOWN_USERNAME,
                "password": KNOWN_PASSWORD,
            }
        )
        double = DeterministicModelDouble()

        execution = asyncio.run(
            execute_ai_verified_login_flow(
                scan_id=uuid4(),
                target=target,
                runtime_secrets=runtime_secrets,
                username_reference="username",
                password_reference="password",
                protected_resource=f"{origin}/account",
                account_marker_selector='[data-testid="account-marker"]',
                account_marker_description="Account marker",
                action_client=double,
                limits=ExecutionLimits(maximum_ai_decisions=10),
            )
        )

        tampered_profile = execution.profile.model_copy(deep=True)
        # Tamper control signature for one of the controls
        for cid in tampered_profile.control_signatures:
            tampered_profile.control_signatures[cid] = "corrupted_signature_hash"
            break

        with pytest.raises(StaleAuthProfileError) as exc_info:
            asyncio.run(
                revalidate_auth_profile(profile=tampered_profile, scan_id=uuid4())
            )
        assert "is stale: changed" in str(exc_info.value)


def test_durable_accounting_persistence_and_write_failure(tmp_path: Path) -> None:
    """Test 6: Durable accounting reservation persistence and safe failure handling."""
    ledger_path = tmp_path / "test-ledger.ndjson"
    store = CostLedgerStore(ledger_path)
    ledger = CostLedger()
    scan_id = uuid4()
    req_id = uuid4()

    # 1. Test reservation recording
    reservation = ledger.record_reservation(
        request_id=req_id,
        run_id=str(scan_id),
        workflow="login_discovery",
        phase=WorkflowPhase.ACTION_SELECTION,
        model_id="amazon.nova-micro-v1:0",
        source=UsageSource.MOCK,
        reserved_cost_usd=Decimal("0.001"),
        scan_id=scan_id,
    )
    store.append(reservation)

    # Outstanding reservation survives reload
    reloaded_ledger = store.load_into()
    unresolved = reloaded_ledger.unresolved_reservations()
    assert len(unresolved) == 1
    assert unresolved[0].request_id == req_id
    assert reloaded_ledger.total_unresolved_reservations_usd() == Decimal("0.001000")

    # 2. Test reconciliation recording
    reconciliation = ledger.record_reconciliation(
        request_id=req_id,
        run_id=str(scan_id),
        workflow="login_discovery",
        phase=WorkflowPhase.ACTION_SELECTION,
        model_id="amazon.nova-micro-v1:0",
        source=UsageSource.MOCK,
        input_tokens=100,
        output_tokens=25,
        reserved_cost_usd=Decimal("0.001"),
        scan_id=scan_id,
    )
    store.append(reconciliation)

    reloaded_ledger_2 = store.load_into()
    assert len(reloaded_ledger_2.unresolved_reservations()) == 0
    assert reloaded_ledger_2.total_unresolved_reservations_usd() == Decimal("0.000000")
    assert reloaded_ledger_2.total_observed_cost_usd() > Decimal("0")

    # 3. Test safe handling of write failure halts before model call
    class FailingStore(CostLedgerStore):
        def append(self, entry: Any) -> None:
            raise OSError("Simulated disk write failure")

    failing_store = FailingStore(tmp_path / "failing.ndjson")
    called_model = False

    class StubActionClient:
        def estimate_maximum_cost(self, observation: Any) -> float:
            return 0.001

        def choose_action(self, observation: Any) -> Any:
            nonlocal called_model
            called_model = True
            raise RuntimeError("Should never be called")

    # Run AutomaticBrowserController with failing store
    with run_app_server(create_controlled_app(EvaluationMode.SECURE)) as origin:

        async def run_with_failing_store() -> None:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                page = await browser.new_page()
                controller = AutomaticBrowserController(
                    page=page,
                    target=TargetScope(
                        target_url=f"{origin}/login",
                        permitted_origins=[origin],
                    ),
                    runtime_secrets=RuntimeSecrets({}),
                    scan_id=scan_id,
                    action_client=StubActionClient(),
                    limits=ExecutionLimits(),
                    credential_references=[],
                    cost_ledger=CostLedger(),
                    cost_ledger_store=failing_store,
                    model_id="amazon.nova-micro-v1:0",
                    usage_source=UsageSource.MOCK,
                )
                try:
                    await controller.run(lambda p: asyncio.sleep(0.01, result=False))
                finally:
                    await browser.close()

        with pytest.raises(OSError, match="Simulated disk write failure"):
            asyncio.run(run_with_failing_store())

    assert called_model is False, (
        "Model must not be called when reservation append fails"
    )

    class ReconciliationFailingStore(CostLedgerStore):
        def append(self, entry: Any) -> None:
            if entry.reconciled:
                raise OSError("Simulated reconciliation write failure")
            super().append(entry)

    reconciliation_store = ReconciliationFailingStore(
        tmp_path / "reconciliation-failing.ndjson"
    )
    reconciliation_ledger = CostLedger()
    model = DeterministicModelDouble()
    with run_app_server(create_controlled_app(EvaluationMode.SECURE)) as origin:

        async def run_with_reconciliation_failure() -> None:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    controller = AutomaticBrowserController(
                        page=page,
                        target=TargetScope(
                            target_url=f"{origin}/login", permitted_origins=[origin]
                        ),
                        runtime_secrets=RuntimeSecrets({}),
                        scan_id=uuid4(),
                        action_client=model,
                        limits=ExecutionLimits(),
                        credential_references=[],
                        cost_ledger=reconciliation_ledger,
                        cost_ledger_store=reconciliation_store,
                        model_id="amazon.nova-micro-v1:0",
                        usage_source=UsageSource.MOCK,
                    )
                    await controller.run(lambda p: asyncio.sleep(0.01, result=False))
                finally:
                    await browser.close()

        with pytest.raises(OSError, match="reconciliation write failure"):
            asyncio.run(run_with_reconciliation_failure())
    assert model.choose_calls == 1
    assert len(reconciliation_ledger.unresolved_reservations()) == 1


def test_duplicate_reconciliation_and_corrupt_ledger_fail_closed(
    tmp_path: Path,
) -> None:
    ledger = CostLedger()
    request_id = uuid4()

    def reconcile() -> None:
        ledger.record_reconciliation(
            request_id=request_id,
            run_id="test-run",
            workflow="login_discovery",
            phase=WorkflowPhase.ACTION_SELECTION,
            model_id="amazon.nova-micro-v1:0",
            source=UsageSource.MOCK,
            input_tokens=12,
            output_tokens=3,
        )

    reconcile()
    with pytest.raises(ValueError, match="already reconciled"):
        reconcile()

    app = create_app(data_root=tmp_path)
    client = TestClient(app)
    created = client.post(
        "/api/scans",
        json={
            "target": {
                "target_url": "http://127.0.0.1:8001/login",
                "permitted_origins": ["http://127.0.0.1:8001"],
            },
            "selected_checks": [CheckId.LOGIN_ENUMERATION.value],
            "discovery_mode": "bedrock",
        },
    )
    scan_id = created.json()["scan_id"]
    (tmp_path / scan_id / "cost-ledger.ndjson").write_text(
        '{"invalid":', encoding="utf-8"
    )
    reloaded = create_app(data_root=tmp_path)
    status = TestClient(reloaded).get(f"/api/scans/{scan_id}").json()
    assert status["state"] == "failed"
    assert "ledger" in status["error"].lower()


def test_evaluation_budget_counts_outstanding_reservations(tmp_path: Path) -> None:
    attempt_root = tmp_path / "A-attempt-1"
    store = CostLedgerStore(attempt_root / "scan" / "cost-ledger.ndjson")
    ledger = CostLedger()
    store.append(
        ledger.record_reservation(
            request_id=uuid4(),
            run_id="evaluation",
            workflow="login_discovery",
            phase=WorkflowPhase.ACTION_SELECTION,
            model_id="amazon.nova-micro-v1:0",
            source=UsageSource.MOCK,
            reserved_cost_usd=Decimal("0.4"),
        )
    )
    budget = EvaluationBudget(0.5)
    budget.charge_attempt(attempt_root)
    assert budget.remaining_usd == pytest.approx(0.1)


def test_secret_redaction_in_outbound_observation() -> None:
    """Test 7: Secret redaction in outbound prompt / model observation."""
    with run_app_server(create_controlled_app(EvaluationMode.SECURE)) as origin:
        target = TargetScope(
            target_url=f"{origin}/login",
            permitted_origins=[origin],
        )
        secret_password = KNOWN_PASSWORD
        runtime_secrets = RuntimeSecrets(
            {
                "user-ref": KNOWN_USERNAME,
                "pass-ref": secret_password,
            }
        )

        observed_payloads: list[PageObservationForModel] = []

        class RecordingClient:
            def __init__(self) -> None:
                self.double = DeterministicModelDouble()

            def estimate_maximum_cost(
                self, observation: PageObservationForModel
            ) -> float:
                return 0.001

            def choose_action(self, observation: PageObservationForModel) -> Any:
                observed_payloads.append(observation)
                return self.double.choose_action(observation)

        asyncio.run(
            execute_ai_verified_login_flow(
                scan_id=uuid4(),
                target=target,
                runtime_secrets=runtime_secrets,
                username_reference="user-ref",
                password_reference="pass-ref",
                protected_resource=f"{origin}/account",
                account_marker_selector='[data-testid="account-marker"]',
                account_marker_description="Account marker",
                action_client=RecordingClient(),
                limits=ExecutionLimits(maximum_ai_decisions=5),
            )
        )

        assert len(observed_payloads) > 0
        for obs in observed_payloads:
            sanitized = obs.sanitized_dict()
            sanitized_str = str(sanitized)
            assert secret_password not in sanitized_str, (
                "Secret password leaked in observation payload"
            )
            for ctrl in obs.controls:
                assert ctrl.text != secret_password
                assert ctrl.placeholder != secret_password


def test_synchronous_validation_failure_on_unconfigured_bedrock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 8: Synchronous validation failure on unconfigured Bedrock."""
    # When action_client_factory is None and no AWS credentials exist,
    # the scan transitions safely.
    monkeypatch.setattr(
        "authflowguard.scan_manager.validate_bedrock_configuration",
        lambda: (False, "Test AWS configuration is absent"),
    )
    app = create_app(data_root=tmp_path, action_client_factory=None)
    client = TestClient(app)

    scan_res = client.post(
        "/api/scans",
        json={
            "target": {
                "target_url": "http://127.0.0.1:8001/login",
                "permitted_origins": ["http://127.0.0.1:8001"],
            },
            "selected_checks": [CheckId.LOGIN_ENUMERATION.value],
            "discovery_mode": "bedrock",
        },
    )
    assert scan_res.status_code == 201
    scan_id = scan_res.json()["scan_id"]

    start_res = client.post(
        f"/api/scans/{scan_id}/start",
        json={
            "runtime_secrets": {"username": "user", "password": "pass"},
            "username_reference": "username",
            "password_reference": "password",
            "nonexistent_identifier_reference": "missing",
            "failure_password_reference": "failure",
            "protected_resource": "http://127.0.0.1:8001/account",
            "account_marker_selector": "#marker",
            "account_marker_description": "marker",
        },
    )
    assert start_res.status_code == 409
    status = client.get(f"/api/scans/{scan_id}").json()
    assert status["state"] == "created"
    assert app.state.scan_manager.get_scan(UUID(scan_id)).future is None


@pytest.mark.parametrize(
    ("limit_name", "limit_value"),
    [
        ("maximum_ai_decisions", 101),
        ("maximum_active_seconds", 1801),
        ("maximum_inference_cost_usd", 1.01),
    ],
)
def test_bedrock_server_caps_reject_before_worker_starts(
    tmp_path: Path, limit_name: str, limit_value: float
) -> None:
    app = create_app(
        data_root=tmp_path,
        action_client_factory=lambda: DeterministicModelDouble(),
    )
    client = TestClient(app)
    created = client.post(
        "/api/scans",
        json={
            "target": {
                "target_url": "http://127.0.0.1:8001/login",
                "permitted_origins": ["http://127.0.0.1:8001"],
            },
            "selected_checks": [CheckId.LOGIN_ENUMERATION.value],
            "discovery_mode": "bedrock",
            "limits": {limit_name: limit_value},
        },
    )
    assert created.status_code == 201
    scan_id = created.json()["scan_id"]
    started = client.post(
        f"/api/scans/{scan_id}/start",
        json={
            "runtime_secrets": {"username": "u", "password": "p"},
            "username_reference": "username",
            "password_reference": "password",
            "nonexistent_identifier_reference": "missing",
            "failure_password_reference": "failure",
            "protected_resource": "http://127.0.0.1:8001/account",
            "account_marker_selector": "#marker",
            "account_marker_description": "marker",
        },
    )
    assert started.status_code == 409
    assert app.state.scan_manager.get_scan(UUID(scan_id)).future is None


def test_failed_discovery_keeps_events_and_model_usage(tmp_path: Path) -> None:
    with run_app_server(create_controlled_app(EvaluationMode.SECURE)) as origin:
        errors = [
            BedrockResponseError(
                "Invalid structured action",
                input_tokens=20,
                output_tokens=4,
                actual_cost_usd=0.00002,
            )
            for _ in range(3)
        ]
        app = create_app(
            data_root=tmp_path,
            action_client_factory=lambda: DeterministicModelDouble(
                scripted_actions=errors
            ),
        )
        client = TestClient(app)
        created = client.post(
            "/api/scans",
            json={
                "target": {
                    "target_url": f"{origin}/login",
                    "permitted_origins": [origin],
                },
                "selected_checks": [CheckId.LOGIN_ENUMERATION.value],
                "discovery_mode": "bedrock",
            },
        )
        scan_id = created.json()["scan_id"]
        started = client.post(
            f"/api/scans/{scan_id}/start",
            json={
                "runtime_secrets": {
                    "username": KNOWN_USERNAME,
                    "password": KNOWN_PASSWORD,
                },
                "username_reference": "username",
                "password_reference": "password",
                "nonexistent_identifier_reference": "missing",
                "failure_password_reference": "failure",
                "protected_resource": f"{origin}/account",
                "account_marker_selector": '[data-testid="account-marker"]',
                "account_marker_description": "Account marker",
            },
        )
        assert started.status_code == 200
        app.state.scan_manager.get_scan(UUID(scan_id)).future.result(timeout=30)
        snapshot = client.get(f"/api/scans/{scan_id}").json()
        events = client.get(f"/api/scans/{scan_id}/events").json()
        assert snapshot["state"] == "awaiting_guidance"
        assert snapshot["model_request_count"] == 3
        assert snapshot["total_input_tokens"] == 60
        assert snapshot["total_output_tokens"] == 12
        assert snapshot["unresolved_reservations_usd"] == 0
        assert any(event["kind"] == "error" for event in events)


def test_reload_persisted_scan_with_cost_ledger_and_provenance(tmp_path: Path) -> None:
    """Test 9: Reload persisted scan from disk with cost ledger and provenance."""
    with run_app_server(create_controlled_app(EvaluationMode.SECURE)) as origin:
        app = create_app(
            data_root=tmp_path,
            action_client_factory=lambda: DeterministicModelDouble(),
        )
        client = TestClient(app)

        scan_res = client.post(
            "/api/scans",
            json={
                "target": {
                    "target_url": f"{origin}/login",
                    "permitted_origins": [origin],
                },
                "selected_checks": [CheckId.LOGIN_ENUMERATION.value],
                "discovery_mode": "bedrock",
                "reuse_saved_profile": False,
            },
        )
        scan_id = scan_res.json()["scan_id"]

        client.post(
            f"/api/scans/{scan_id}/start",
            json={
                "runtime_secrets": {
                    "username": KNOWN_USERNAME,
                    "password": KNOWN_PASSWORD,
                    "missing": "missing@example.test",
                    "failure": "wrong-password",
                },
                "username_reference": "username",
                "password_reference": "password",
                "nonexistent_identifier_reference": "missing",
                "failure_password_reference": "failure",
                "protected_resource": f"{origin}/account",
                "account_marker_selector": '[data-testid="account-marker"]',
                "account_marker_description": "Account marker",
            },
        )

        # Wait until scan completes
        orig_record = app.state.scan_manager.get_scan(UUID(scan_id))
        if orig_record.future is not None:
            orig_record.future.result(timeout=60)

        status = client.get(f"/api/scans/{scan_id}").json()
        assert status.get("state") == "completed", f"Scan did not complete: {status}"

        # Create a new ScanManager instance on the same data_root
        new_manager = ScanManager(data_root=tmp_path)
        reloaded_record = new_manager.get_scan(UUID(scan_id))

        assert reloaded_record.state is ScanState.COMPLETED
        assert reloaded_record.provenance is not None
        assert reloaded_record.provenance.requested_mode is DiscoveryMode.BEDROCK
        assert reloaded_record.provenance.actual_engine == "bedrock"
        assert reloaded_record.provenance.usage_source == "mock"
        assert reloaded_record.cost_ledger is not None
        assert len(reloaded_record.cost_ledger.entries) >= 6
        assert reloaded_record.estimated_cost_usd > 0
        assert reloaded_record.total_input_tokens > 0
        assert reloaded_record.total_output_tokens > 0
