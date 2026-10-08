"""CHK-002/003 browser isolation, normalization and offline analysis contracts."""

import asyncio
import json
import socket
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.parse import parse_qs
from uuid import uuid4

import pytest
import uvicorn
from authflowguard import models
from authflowguard.checks.form_enumeration import (
    CLIENT_STATE_FIELDS,
    LABELS,
    REPEAT_LABEL,
    FormEnumerationRun,
    normalize_response,
)
from authflowguard.checks.registration_enumeration import (
    analyse_registration_enumeration,
    run_registration_enumeration_check,
)
from authflowguard.checks.reset_request_enumeration import (
    analyse_reset_request_enumeration,
    run_reset_request_enumeration_check,
)
from authflowguard.evaluation_targets.controlled_app import (
    KNOWN_USERNAME,
    EvaluationMode,
    create_controlled_app,
)
from authflowguard.evidence import EvidenceStore
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
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

CHECKS = (CheckId.REGISTRATION_ENUMERATION, CheckId.RESET_REQUEST_ENUMERATION)
ANALYSERS = {
    CheckId.REGISTRATION_ENUMERATION: analyse_registration_enumeration,
    CheckId.RESET_REQUEST_ENUMERATION: analyse_reset_request_enumeration,
}
UNKNOWN = "disposable@example.test"
UNKNOWN_REPEAT = "disposable-repeat@example.test"
PASSWORD = "disposable-password-123!"


@contextmanager
def serve(application: FastAPI) -> Iterator[str]:
    listening = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening.bind(("127.0.0.1", 0))
    listening.listen()
    origin = f"http://127.0.0.1:{listening.getsockname()[1]}"
    server = uvicorn.Server(
        uvicorn.Config(application, log_level="error", lifespan="off")
    )
    thread = Thread(target=server.run, kwargs={"sockets": [listening]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        if not server.started:
            raise RuntimeError("Test server did not start")
        yield origin
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listening.close()


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
                )
            ]
        },
    )


async def run_check(
    check: CheckId,
    profile: AuthProfile,
    *,
    form_url: str | None = None,
    cancel_requested: Callable[[], bool] = lambda: False,
) -> FormEnumerationRun:
    secrets = RuntimeSecrets(
        {"known": KNOWN_USERNAME, "missing": UNKNOWN, "password": PASSWORD}
    )
    try:
        if check is CheckId.REGISTRATION_ENUMERATION:
            return await run_registration_enumeration_check(
                profile=profile,
                scan_id=uuid4(),
                runtime_secrets=secrets,
                known_identifier_reference="known",
                nonexistent_identifier_reference="missing",
                registration_password_reference="password",
                form_url=form_url,
                cancel_requested=cancel_requested,
            )
        return await run_reset_request_enumeration_check(
            profile=profile,
            scan_id=uuid4(),
            runtime_secrets=secrets,
            known_identifier_reference="known",
            nonexistent_identifier_reference="missing",
            form_url=form_url,
            cancel_requested=cancel_requested,
        )
    finally:
        secrets.discard_all()


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("mode", list(EvaluationMode))
def test_browser_outcomes_use_fresh_csrf_and_sessions_and_redact_evidence(
    check: CheckId,
    mode: EvaluationMode,
    tmp_path: Path,
) -> None:
    app = create_controlled_app(mode)
    submissions: list[tuple[str, dict[str, list[str]]]] = []

    @app.middleware("http")
    async def record_submissions(request: Request, call_next: Any) -> Any:
        if request.method == "POST":
            submissions.append(
                (
                    request.headers.get("cookie", ""),
                    parse_qs((await request.body()).decode()),
                )
            )
        return await call_next(request)

    with serve(app) as origin:
        profile = profile_for(origin)
        run = asyncio.run(run_check(check, profile))
        result = ANALYSERS[check](run.evidence, profile, SecurityPolicy())

    assert not run.evidence.errors
    assert result.outcome is (
        CheckOutcome.FINDING_CONFIRMED
        if mode is EvaluationMode.VULNERABLE
        else CheckOutcome.NO_ISSUE_OBSERVED
    )
    assert result.check_id is check
    assert result.owasp_reference == "WSTG-IDNT-04"
    assert result.evidence_references == [
        run.evidence.evidence_id,
        *run.evidence.event_ids,
    ]
    assert len(submissions) == 2
    assert submissions[0][0] and submissions[0][0] != submissions[1][0]
    assert submissions[0][1]["csrf_token"] != submissions[1][1]["csrf_token"]
    assert all(event.check_id is check for event in run.events)
    assert all(
        f"{label}:submit" in run.evidence.coverage.completed_steps for label in LABELS
    )
    store = EvidenceStore(tmp_path)
    store.create_scan(run.evidence.scan_id)
    store.save_evidence(run.evidence)
    for event in run.events:
        store.append_event(event)
    serialized = run.evidence.model_dump_json() + "".join(
        e.model_dump_json() for e in run.events
    )
    serialized += "".join(path.read_text() for path in tmp_path.rglob("*.*"))
    for secret in [
        KNOWN_USERNAME,
        UNKNOWN,
        PASSWORD,
        *[s[0] for s in submissions],
        *[s[1]["csrf_token"][0] for s in submissions],
    ]:
        assert secret not in serialized
    assert "authorization" not in serialized.lower()
    if check is CheckId.REGISTRATION_ENUMERATION:
        assert app.state.controlled.users[UNKNOWN] == PASSWORD
        # The fixture instance is discarded here, including the created account.


def make_evidence(check: CheckId, different: bool = False) -> models.TestRunEvidence:
    signature = {
        "status_code": 202,
        "final_status_code": 202,
        "normalized_body_fingerprint": "a" * 64,
        "title_fingerprint": "b" * 64,
        "redirect_path_fingerprint": "c" * 64,
        "control_fingerprint": "d" * 64,
        "safe_visible_messages": [],
        "submission_observed": True,
    }
    unknown = dict(signature)
    if different:
        unknown["normalized_body_fingerprint"] = "e" * 64
    return models.TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=uuid4(),
        check_id=check,
        profile_version="1.0",
        observations={
            LABELS[0]: signature,
            LABELS[1]: unknown,
            "captured_at": "2026-09-13T00:00:00+00:00",
        },
    )


@pytest.mark.parametrize("check", CHECKS)
def test_analyser_is_fully_deterministic_and_offline(
    check: CheckId, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = make_evidence(check, different=True)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Offline analysis attempted live I/O or secret access")

    monkeypatch.setattr(
        "authflowguard.checks.form_enumeration.async_playwright", forbidden
    )
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(RuntimeSecrets, "resolve", forbidden)
    profile = profile_for("https://app.example")
    first = ANALYSERS[check](evidence, profile, SecurityPolicy())
    assert first == ANALYSERS[check](evidence, profile, SecurityPolicy())
    assert first.outcome is CheckOutcome.FINDING_CONFIRMED
    assert (
        ANALYSERS[check](
            evidence, profile, SecurityPolicy(account_existence_is_private=False)
        ).outcome
        is CheckOutcome.NO_ISSUE_OBSERVED
    )


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize(
    "malformation",
    ["missing", "empty", "invalid_status", "invalid_hash", "not_submitted"],
)
def test_incomplete_or_malformed_evidence_is_inconclusive(
    check: CheckId, malformation: str
) -> None:
    evidence = make_evidence(check)
    if malformation == "missing":
        del evidence.observations[LABELS[1]]
    elif malformation == "empty":
        evidence.observations[LABELS[1]] = {}
    else:
        field, value = {
            "invalid_status": ("status_code", "202"),
            "invalid_hash": ("normalized_body_fingerprint", None),
            "not_submitted": ("submission_observed", False),
        }[malformation]
        evidence.observations[LABELS[1]][field] = value
    assert (
        ANALYSERS[check](
            evidence, profile_for("https://app.example"), SecurityPolicy()
        ).outcome
        is CheckOutcome.INCONCLUSIVE
    )


@pytest.mark.parametrize("check", CHECKS)
def test_error_evidence_never_becomes_a_secure_result(check: CheckId) -> None:
    evidence = make_evidence(check)
    evidence.errors = ["TimeoutError"]
    assert (
        ANALYSERS[check](
            evidence, profile_for("https://app.example"), SecurityPolicy()
        ).outcome
        is CheckOutcome.EXECUTION_ERROR
    )


@pytest.mark.parametrize("check", CHECKS)
def test_status_only_difference_is_detected(check: CheckId) -> None:
    evidence = make_evidence(check)
    evidence.observations[LABELS[1]]["status_code"] = 200
    result = ANALYSERS[check](
        evidence, profile_for("https://app.example"), SecurityPolicy()
    )
    assert result.outcome is CheckOutcome.FINDING_CONFIRMED
    assert "status_code" in result.explanation


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("status", [400, 429, 503])
def test_offline_analyser_rejects_failed_http_responses(
    check: CheckId, status: int
) -> None:
    evidence = make_evidence(check)
    for label in LABELS:
        evidence.observations[label]["status_code"] = status
    result = ANALYSERS[check](
        evidence, profile_for("https://app.example"), SecurityPolicy()
    )
    assert result.outcome is CheckOutcome.EXECUTION_ERROR


def custom_form_app(check: CheckId, problem: str = "") -> FastAPI:
    app = FastAPI()
    app.state.submissions = []

    @app.get("/form")
    async def form() -> HTMLResponse:
        if problem == "missing_form":
            return HTMLResponse("<h1>No form here</h1>")
        identifier = (
            ""
            if problem == "missing_username"
            else '<input type="email" name="username">'
        )
        password = (
            '<input type="password" name="password">'
            if check is CheckId.REGISTRATION_ENUMERATION
            else ""
        )
        script = 'onsubmit="event.preventDefault()"' if problem == "timeout" else ""
        return HTMLResponse(
            f'<form method="post" action="/form" {script}>'
            f'{identifier}{password}<input type="hidden" name="csrf_token" '
            f'value="{uuid4()}">'
            '<button type="submit">Continue</button></form>'
        )

    @app.post("/form")
    async def submit(request: Request) -> HTMLResponse:
        values = parse_qs((await request.body()).decode())
        app.state.submissions.append(values)
        if problem == "unexpected_response":
            return HTMLResponse("Service unavailable", status_code=503)
        identifier = values["username"][0]
        token = values["csrf_token"][0]
        # Secrets echoed into body and title must never enter persisted events.
        return HTMLResponse(
            f"<title>{identifier} {token}</title><h1>Check your email</h1>"
            f"<p>{identifier} {token} {PASSWORD}</p><p>request_id: {uuid4()}</p>"
            f"<p>2026-09-13T12:00:0{len(app.state.submissions)}Z</p>",
            status_code=202,
        )

    return app


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize(
    "problem", ["missing_form", "missing_username", "timeout", "unexpected_response"]
)
def test_browser_failures_produce_execution_error(
    check: CheckId, problem: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "authflowguard.checks.form_enumeration.ATTEMPT_TIMEOUT_MS", 1000
    )
    with serve(custom_form_app(check, problem)) as origin:
        profile = profile_for(origin)
        run = asyncio.run(run_check(check, profile, form_url=f"{origin}/form"))
    assert run.evidence.errors
    assert (
        ANALYSERS[check](run.evidence, profile, SecurityPolicy()).outcome
        is CheckOutcome.EXECUTION_ERROR
    )


@pytest.mark.parametrize("check", CHECKS)
def test_navigation_failure_is_an_execution_error(check: CheckId) -> None:
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{unavailable.getsockname()[1]}"
        profile = profile_for(origin)
        run = asyncio.run(run_check(check, profile, form_url=f"{origin}/form"))
    assert run.evidence.errors
    assert (
        ANALYSERS[check](run.evidence, profile, SecurityPolicy()).outcome
        is CheckOutcome.EXECUTION_ERROR
    )


@pytest.mark.parametrize("check", CHECKS)
def test_browser_normalizes_dynamic_tokens_without_leaking_values(
    check: CheckId,
) -> None:
    app = custom_form_app(check)
    with serve(app) as origin:
        profile = profile_for(origin)
        run = asyncio.run(run_check(check, profile, form_url=f"{origin}/form"))
    assert not run.evidence.errors
    assert (
        ANALYSERS[check](run.evidence, profile, SecurityPolicy()).outcome
        is CheckOutcome.NO_ISSUE_OBSERVED
    )
    serialized = json.dumps(
        [
            run.evidence.model_dump(mode="json"),
            *[e.model_dump(mode="json") for e in run.events],
        ]
    )
    for values in app.state.submissions:
        assert values["csrf_token"][0] not in serialized
    for value in (KNOWN_USERNAME, UNKNOWN, PASSWORD):
        assert value not in serialized


def test_dynamic_normalization_preserves_account_state_difference() -> None:
    first = normalize_response(
        "No account exists. csrf_token: aaa nonce=bbb tracking_id: 123", []
    )
    second = normalize_response(
        "No account exists. csrf_token: ccc nonce=ddd tracking_id: 456", []
    )
    assert first == second
    assert (
        sha256(first.encode()).hexdigest()
        != sha256(normalize_response("Check your email", []).encode()).hexdigest()
    )


@pytest.mark.parametrize("check", CHECKS)
def test_cancellation_stops_before_second_submission(check: CheckId) -> None:
    app = custom_form_app(check)
    with serve(app) as origin:
        profile = profile_for(origin)
        run = asyncio.run(
            run_check(
                check,
                profile,
                form_url=f"{origin}/form",
                cancel_requested=lambda: bool(app.state.submissions),
            )
        )
    assert len(app.state.submissions) == 1
    assert run.evidence.errors == ["EnumerationCancelledError"]
    assert (
        ANALYSERS[check](run.evidence, profile, SecurityPolicy()).outcome
        is CheckOutcome.EXECUTION_ERROR
    )


@pytest.mark.parametrize("check", CHECKS)
def test_missing_form_link_and_out_of_scope_form_url_are_not_guessed(
    check: CheckId,
) -> None:
    with serve(custom_form_app(check)) as origin:
        profile = profile_for(origin)
        run = asyncio.run(run_check(check, profile))
        outside = asyncio.run(
            run_check(check, profile, form_url="https://outside.example/form")
        )
    assert run.evidence.errors == ["ValueError"]
    assert outside.evidence.errors == ["ValueError"]


@pytest.mark.parametrize("check", CHECKS)
def test_analyser_rejects_the_other_check_evidence(check: CheckId) -> None:
    other = next(value for value in CHECKS if value is not check)
    with pytest.raises(ValueError, match="different security check"):
        ANALYSERS[check](
            make_evidence(other), profile_for("https://app.example"), SecurityPolicy()
        )


@pytest.mark.parametrize("check", CHECKS)
def test_discovers_nonstandard_route_from_visible_link(check: CheckId) -> None:
    app = custom_form_app(check)

    @app.get("/login")
    async def login() -> HTMLResponse:
        label = (
            "Create account"
            if check is CheckId.REGISTRATION_ENUMERATION
            else "Forgot password"
        )
        return HTMLResponse(f'<a href="/form">{label}</a>')

    with serve(app) as origin:
        run = asyncio.run(run_check(check, profile_for(origin)))
    assert not run.evidence.errors
    assert len(app.state.submissions) == 2
    assert run.evidence.observations["form_url_source"] == "keyword_search"


def client_form_app(vulnerable: bool, noisy: bool = False) -> FastAPI:
    """A single-page app: no native POST form, JSON requests, a debounced
    reset lookup and a custom dropdown. Every registration returns a new
    record id, which must not read as a difference. A noisy app also adds a
    random reference string to every response, which normalization cannot
    recognize."""

    app = FastAPI()
    registered = {KNOWN_USERNAME}

    def body(values: dict[str, Any]) -> dict[str, Any]:
        return {**values, "ref": uuid4().hex} if noisy else values

    @app.get("/app")
    async def page() -> HTMLResponse:
        return HTMLResponse(CLIENT_APP_PAGE)

    @app.post("/api/users")
    async def register(request: Request) -> JSONResponse:
        email = (await request.json())["email"]
        if vulnerable and email in registered:
            return JSONResponse(
                body({"error": "email must be unique"}), status_code=400
            )
        registered.add(email)
        return JSONResponse(
            body({"id": len(registered) * 7, "status": "ok"}), status_code=201
        )

    @app.get("/api/question")
    async def question(email: str) -> JSONResponse:
        if vulnerable and email in registered:
            return JSONResponse(body({"question": "Pet?"}))
        return JSONResponse(body({}))

    return app


CLIENT_APP_PAGE = """<!doctype html><title>Shop</title><div id="view"></div>
<script>
const view = document.getElementById("view");
function render() {
  if (location.hash === "#/register") {
    view.innerHTML = `<form>
      <input id="emailControl" type="text" aria-label="Email address">
      <input type="password"><input type="password">
      <div role="combobox" tabindex="0" id="question">Choose a question</div>
      <div id="options" hidden><div role="option" id="pet">Pet?</div></div>
      <input id="answer" type="text" aria-label="Answer">
      <button type="submit">Register</button></form><p id="out"></p>`;
    const question = document.getElementById("question");
    const options = document.getElementById("options");
    question.onkeydown = (event) => {
      if (event.key === "Enter") { options.hidden = false; }
    };
    document.getElementById("pet").onclick = () => {
      question.textContent = "Pet?";
      options.hidden = true;
    };
    view.querySelector("form").onsubmit = async (event) => {
      event.preventDefault();
      const email = document.getElementById("emailControl").value;
      const response = await fetch("/api/users", {method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({email})});
      if (response.ok) { location.hash = "#/login"; }
      else {
        document.getElementById("out").textContent = (await response.json()).error;
      }
    };
  } else if (location.hash === "#/forgot-password") {
    view.innerHTML = `<input id="email" type="email">
      <input id="securityAnswer" type="password" disabled>
      <button type="submit" disabled>Change</button>`;
    let timer;
    document.getElementById("email").oninput = (event) => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const response = await fetch(
          "/api/question?email=" + encodeURIComponent(event.target.value));
        const body = await response.json();
        document.getElementById("securityAnswer").disabled = !body.question;
      }, 600);
    };
  } else {
    view.innerHTML = "<p>Signed out</p>";
  }
}
window.onhashchange = render;
render();
</script>"""


@pytest.mark.parametrize(
    ("check", "vulnerable", "expected"),
    [
        # New record ids and volatile content alone must not read as
        # enumeration.
        (CheckId.REGISTRATION_ENUMERATION, False, CheckOutcome.INCONCLUSIVE),
        # The debounced lookup's account state still shows through the
        # volatile content.
        (CheckId.RESET_REQUEST_ENUMERATION, True, CheckOutcome.FINDING_CONFIRMED),
    ],
)
def test_client_rendered_forms_are_compared(
    check: CheckId, vulnerable: bool, expected: CheckOutcome
) -> None:
    """Both checks capture a noisy single-page app in a real browser.

    Every vulnerable/noisy combination is covered offline by the client form
    analysis tests below, so the browser runs only one case per check.
    """
    route = (
        "register" if check is CheckId.REGISTRATION_ENUMERATION else "forgot-password"
    )
    with serve(client_form_app(vulnerable, noisy=True)) as origin:
        profile = profile_for(origin)
        run = asyncio.run(run_check(check, profile, form_url=f"{origin}/app#/{route}"))

    assert run.evidence.errors == []
    observations = run.evidence.observations
    assert observations[LABELS[0]]["interaction"] == "client"
    assert observations[REPEAT_LABEL]["interaction"] == "client"
    saved = run.evidence.model_dump_json()
    assert KNOWN_USERNAME not in saved
    assert UNKNOWN not in saved
    assert UNKNOWN_REPEAT not in saved
    assert PASSWORD not in saved
    assert ANALYSERS[check](run.evidence, profile, SecurityPolicy()).outcome is expected


def client_signature(
    responses: list[list[Any]],
    submitted: list[list[Any]] | None = None,
    *,
    control: str = "a" * 64,
) -> dict[str, Any]:
    def state(background: list[list[Any]]) -> dict[str, Any]:
        return {
            "background_responses": background,
            **{field: "a" * 64 for field in CLIENT_STATE_FIELDS[1:]},
        }

    return {
        "interaction": "client",
        "reaction": {**state(responses), "control_fingerprint": control},
        "submission_observed": submitted is not None,
        "submission": state(submitted) if submitted is not None else None,
        "safe_visible_messages": [],
    }


LOOKUP = ["GET", "b" * 64, 200, "c" * 64]


@pytest.mark.parametrize(
    ("check", "known", "unknown", "expected"),
    [
        # Nothing reacted to either identifier: nothing was compared.
        (
            CheckId.RESET_REQUEST_ENUMERATION,
            client_signature([]),
            client_signature([]),
            CheckOutcome.INCONCLUSIVE,
        ),
        (
            CheckId.RESET_REQUEST_ENUMERATION,
            client_signature([LOOKUP]),
            client_signature([LOOKUP]),
            CheckOutcome.NO_ISSUE_OBSERVED,
        ),
        # The disposable registration was rejected: a difference proves nothing.
        (
            CheckId.REGISTRATION_ENUMERATION,
            client_signature([], [["POST", "b" * 64, 400, "c" * 64]]),
            client_signature([], [["POST", "b" * 64, 400, "d" * 64]]),
            CheckOutcome.INCONCLUSIVE,
        ),
        (
            CheckId.REGISTRATION_ENUMERATION,
            client_signature([], [["POST", "b" * 64, 400, "c" * 64]]),
            client_signature([], [["POST", "b" * 64, 201, "d" * 64]]),
            CheckOutcome.FINDING_CONFIRMED,
        ),
        (
            CheckId.REGISTRATION_ENUMERATION,
            client_signature([], [["POST", "b" * 64, 503, "c" * 64]]),
            client_signature([], [["POST", "b" * 64, 201, "d" * 64]]),
            CheckOutcome.EXECUTION_ERROR,
        ),
    ],
)
def test_client_form_analysis_requires_an_exercised_form(
    check: CheckId,
    known: dict[str, Any],
    unknown: dict[str, Any],
    expected: CheckOutcome,
) -> None:
    evidence = models.TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=uuid4(),
        check_id=check,
        profile_version="1.0",
        observations={LABELS[0]: known, LABELS[1]: unknown},
        coverage={"limitations": ["Fixture evidence."]},
    )
    result = ANALYSERS[check](evidence, profile_for("http://app"), SecurityPolicy())
    assert result.outcome is expected


REGISTERED = ["POST", "b" * 64, 201, "c" * 64]
REGISTRATION = CheckId.REGISTRATION_ENUMERATION
RESET = CheckId.RESET_REQUEST_ENUMERATION
# A vulnerable reset form enables its next field for a known account.
ENABLED = "e" * 64


def lookup(body: str) -> list[Any]:
    return ["GET", "b" * 64, 200, body * 64]


@pytest.mark.parametrize(
    ("check", "known", "unknown", "repeat", "expected"),
    [
        # Registration: a secure, quiet app answers every identifier alike.
        (
            REGISTRATION,
            client_signature([], [REGISTERED]),
            client_signature([], [REGISTERED]),
            client_signature([], [REGISTERED]),
            CheckOutcome.NO_ISSUE_OBSERVED,
        ),
        # Only the body differs, and it differs between nonexistent
        # identifiers too: volatile content, not account state.
        (
            REGISTRATION,
            client_signature([], [["POST", "b" * 64, 201, "d" * 64]]),
            client_signature([], [REGISTERED]),
            client_signature([], [["POST", "b" * 64, 201, "e" * 64]]),
            CheckOutcome.INCONCLUSIVE,
        ),
        # The body is volatile, but the status differs only for the known
        # identifier.
        (
            REGISTRATION,
            client_signature([], [["POST", "b" * 64, 400, "d" * 64]]),
            client_signature([], [REGISTERED]),
            client_signature([], [["POST", "b" * 64, 201, "e" * 64]]),
            CheckOutcome.FINDING_CONFIRMED,
        ),
        # The nonexistent attempts agree, so the known difference is stable.
        (
            REGISTRATION,
            client_signature([], [["POST", "b" * 64, 201, "d" * 64]]),
            client_signature([], [REGISTERED]),
            client_signature([], [REGISTERED]),
            CheckOutcome.FINDING_CONFIRMED,
        ),
        (
            REGISTRATION,
            client_signature([], [REGISTERED]),
            client_signature([], [REGISTERED]),
            {"interaction": "client"},
            CheckOutcome.INCONCLUSIVE,
        ),
        # Reset: a vulnerable, quiet app answers the known account's lookup
        # differently, and the nonexistent lookups agree.
        (
            RESET,
            client_signature([lookup("c")], control=ENABLED),
            client_signature([lookup("d")]),
            client_signature([lookup("d")]),
            CheckOutcome.FINDING_CONFIRMED,
        ),
        # A secure, quiet app answers every lookup alike.
        (
            RESET,
            client_signature([lookup("d")]),
            client_signature([lookup("d")]),
            client_signature([lookup("d")]),
            CheckOutcome.NO_ISSUE_OBSERVED,
        ),
        # Every lookup body is volatile, but only the known account enables
        # the next field.
        (
            RESET,
            client_signature([lookup("c")], control=ENABLED),
            client_signature([lookup("d")]),
            client_signature([lookup("e")]),
            CheckOutcome.FINDING_CONFIRMED,
        ),
        # Volatile lookup bodies alone must not read as enumeration.
        (
            RESET,
            client_signature([lookup("c")]),
            client_signature([lookup("d")]),
            client_signature([lookup("e")]),
            CheckOutcome.INCONCLUSIVE,
        ),
    ],
)
def test_client_form_analysis_ignores_volatile_differences(
    check: CheckId,
    known: dict[str, Any],
    unknown: dict[str, Any],
    repeat: dict[str, Any],
    expected: CheckOutcome,
) -> None:
    evidence = models.TestRunEvidence(
        evidence_id=uuid4(),
        scan_id=uuid4(),
        check_id=check,
        profile_version="1.0",
        observations={
            LABELS[0]: known,
            LABELS[1]: unknown,
            REPEAT_LABEL: repeat,
        },
        coverage={"limitations": ["Fixture evidence."]},
    )
    result = ANALYSERS[check](evidence, profile_for("http://app"), SecurityPolicy())
    assert result.outcome is expected
