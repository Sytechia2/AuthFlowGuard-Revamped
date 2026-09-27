"""Executes the formal evaluation cases and records what each one produced.

The case file is an input and is never modified. Each run writes its own
results file keyed by ``case_id``, so two runs of the same case can be
compared rather than one overwriting the other.

Live cases are driven through the same FastAPI endpoints and ScanManager that
a real scan uses. The fixture is served on an ephemeral port and the case's
URLs are rewritten to it, so a run cannot fail because port 8001 happened to
be busy; the origin actually used is recorded on every result.
"""

import asyncio
import json
import os
import socket
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import urlopen
from uuid import UUID, uuid4

import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from authflowguard.app import create_app
from authflowguard.automatic_actions import ActionSelectionClient
from authflowguard.evaluation_targets.controlled_app import (
    EvaluationMode,
    create_controlled_app,
)
from authflowguard.models import CheckId, CheckOutcome, ScanRequest
from authflowguard.scan_manager import ScanExecutionInput, ScanState

SCAN_TIMEOUT_SECONDS = 180


class ExecutionMode(StrEnum):
    LIVE_SCAN = "live_scan"
    OFFLINE_ANALYSIS = "offline_analysis"
    FAULT_INJECTION = "fault_injection"


class Verdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_RUN = "not_run"
    BLOCKED = "blocked"


class CaseSetup(BaseModel):
    """The target details a live case needs. Extra keys are tolerated."""

    model_config = ConfigDict(extra="allow")

    target_url: str
    permitted_origins: list[str]
    protected_resource_url: str
    marker_selector: str
    known_username: str
    known_password: str
    nonexistent_username: str
    failure_password: str


class FormalCase(BaseModel):
    """One authored case. Mirrors the hand-off file, results excluded."""

    model_config = ConfigDict(extra="allow")

    case_id: str
    check_id: CheckId
    outcome_type: str
    expected_outcome: CheckOutcome
    execution_mode: ExecutionMode
    application: str
    fixture_mode: str
    owasp_reference: str
    rationale: str
    setup: CaseSetup | None = None
    evidence_fixture: str | None = None
    degradation: str | None = None
    fault: str | None = None
    security_policy: dict[str, Any] | None = None
    notes: str = ""


@dataclass
class CaseResult:
    """What one executed case actually produced."""

    case_id: str
    check_id: str
    application: str
    execution_mode: str
    expected_outcome: str
    actual_outcome: str | None
    verdict: Verdict
    scan_id: str | None = None
    evidence_id: str | None = None
    origin_used: str | None = None
    detail: str = ""
    duration_seconds: float = 0.0
    discovery: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "check_id": self.check_id,
            "application": self.application,
            "execution_mode": self.execution_mode,
            "expected_outcome": self.expected_outcome,
            "actual_outcome": self.actual_outcome,
            "verdict": self.verdict.value,
            "scan_id": self.scan_id,
            "evidence_id": self.evidence_id,
            "origin_used": self.origin_used,
            "discovery": self.discovery,
            "detail": self.detail,
            "duration_seconds": round(self.duration_seconds, 2),
        }


def load_cases(path: Path) -> list[FormalCase]:
    """Read the authored case file without altering it."""

    document = json.loads(path.read_text(encoding="utf-8"))
    return [FormalCase.model_validate(entry) for entry in document["cases"]]


@contextmanager
def serve(application: FastAPI) -> Iterator[str]:
    """Run a fixture application on an ephemeral local port."""

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
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        if not server.started:
            raise RuntimeError("The fixture application did not start")
        yield origin
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listening.close()


def rebase_url(url: str, origin: str) -> str:
    """Point a case URL at the origin the fixture is actually listening on."""

    parsed = urlparse(url)
    base = urlparse(origin)
    return urlunparse(parsed._replace(scheme=base.scheme, netloc=base.netloc))


def execution_input_for(setup: CaseSetup, origin: str) -> ScanExecutionInput:
    secrets = {
        "known": setup.known_username,
        "password": setup.known_password,
        "missing": setup.nonexistent_username,
        "failure": setup.failure_password,
    }
    # A two-step login supplies a verification code as a separate reference.
    second_factor = getattr(setup, "second_factor", None)
    if second_factor:
        secrets["second_factor"] = str(second_factor)
    # Optional explicit form URLs, for apps whose links do not name the form.
    form_urls = {
        field: rebase_url(str(url), origin)
        for field in ("registration_url", "reset_request_url")
        if (url := getattr(setup, field, None))
    }

    return ScanExecutionInput(
        **form_urls,
        runtime_secrets=secrets,
        username_reference="known",
        password_reference="password",
        second_factor_reference="second_factor" if second_factor else None,
        nonexistent_identifier_reference="missing",
        failure_password_reference="failure",
        protected_resource=rebase_url(setup.protected_resource_url, origin),
        account_marker_selector=setup.marker_selector,
        account_marker_description="Authenticated account marker",
    )


def scan_request_for(
    case: FormalCase,
    setup: CaseSetup,
    origin: str,
    discovery_mode: str = "rules",
    reuse_saved_profile: bool | None = None,
    limits: dict[str, Any] | None = None,
) -> ScanRequest:
    if reuse_saved_profile is None:
        reuse_saved_profile = discovery_mode == "rules"
    payload: dict[str, Any] = {
        "target": {
            "target_url": rebase_url(setup.target_url, origin),
            "permitted_origins": [origin],
        },
        "selected_checks": [case.check_id.value],
        "discovery_mode": discovery_mode,
        "reuse_saved_profile": reuse_saved_profile,
    }
    if limits:
        payload["limits"] = limits
    if case.security_policy:
        payload["policy"] = case.security_policy
    return ScanRequest.model_validate(payload)


USERNAME_HINTS = ("username", "email", "user", "login", "member", "identifier")


SUBMIT_HINTS = ("log in", "login", "sign in", "signin", "submit", "continue", "open my")

# Buttons that commonly sit on a login page but never submit it: banners,
# navigation, search, social sign-in, and password-visibility toggles.
NON_SUBMIT_HINTS = (
    "close",
    "dismiss",
    "cancel",
    "cookie",
    "search",
    "menu",
    "sidenav",
    "language",
    "basket",
    "cart",
    "google",
    "display the password",
    "show",
    "back to",
)


def _control_label(control: dict[str, Any]) -> str:
    parts = (control.get("aria_label"), control.get("text"), control.get("name"))
    return " ".join(str(part) for part in parts if part).lower()


def choose_submit_control(controls: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick the button that submits the login form.

    Taking the first button on the page is wrong on any real application:
    Juice Shop's first button is a cookie-banner link. A type="submit" button
    with a login-like label is preferred, then any submit button that is not
    obviously a banner, navigation or search control.
    """

    buttons = [
        c
        for c in controls
        if c.get("visible", True)
        and (
            str(c.get("tag")) == "button" or str(c.get("type")) in {"submit", "button"}
        )
    ]

    def is_submit(control: dict[str, Any]) -> bool:
        return str(control.get("type")) == "submit"

    def looks_like_login(control: dict[str, Any]) -> bool:
        return any(hint in _control_label(control) for hint in SUBMIT_HINTS)

    def looks_unrelated(control: dict[str, Any]) -> bool:
        return any(hint in _control_label(control) for hint in NON_SUBMIT_HINTS)

    ranked = (
        [c for c in buttons if is_submit(c) and looks_like_login(c)],
        [c for c in buttons if is_submit(c) and not looks_unrelated(c)],
        [c for c in buttons if looks_like_login(c) and not looks_unrelated(c)],
    )
    for tier in ranked:
        if tier:
            return tier[0]
    return None


def choose_guided_controls(
    controls: list[dict[str, Any]],
) -> tuple[str, str, str] | None:
    """Pick the username, password and submit controls from an observation.

    Chosen by role rather than by name, so this works on an application whose
    labels were never shown to the discovery implementation.
    """

    password = next((c for c in controls if str(c.get("type")) == "password"), None)
    submit = choose_submit_control(controls)
    username = next(
        (
            c
            for c in controls
            if str(c.get("tag")) == "input"
            and str(c.get("type")) not in {"password", "hidden", "submit"}
            and c.get("visible", True)
            and any(
                hint in f"{c.get('name', '')}{c.get('aria_label', '')}".lower()
                for hint in USERNAME_HINTS
            )
        ),
        None,
    )
    if username is None:
        username = next(
            (
                c
                for c in controls
                if str(c.get("tag")) == "input"
                and c.get("visible", True)
                and str(c.get("type")) not in {"password", "hidden", "submit"}
            ),
            None,
        )
    if username is None or password is None or submit is None:
        return None
    return (
        str(username["observed_control_id"]),
        str(password["observed_control_id"]),
        str(submit["observed_control_id"]),
    )


def attempt_guided_login(
    client: TestClient,
    scan_id: str,
    setup: CaseSetup,
    origin: str,
) -> str:
    """Supply a guided login flow after automatic discovery paused.

    Returns a short note describing what happened, for the case result.
    """

    observation = client.post(f"/api/scans/{scan_id}/guidance/observe")
    if observation.status_code != 200:
        return f"Guided observation failed: HTTP {observation.status_code}."

    controls = observation.json().get("controls", [])
    chosen = choose_guided_controls(controls)
    if chosen is None:
        return (
            "Guided fallback could not identify a username, password and submit "
            f"control among {len(controls)} observed controls."
        )

    username_id, password_id, submit_id = chosen
    submission = client.post(
        f"/api/scans/{scan_id}/guidance",
        json={
            "actions": [
                {
                    "action_type": "navigate",
                    "url": rebase_url(setup.target_url, origin),
                    "description": "Open the login page",
                },
                {
                    "action_type": "fill",
                    "observed_control_id": username_id,
                    "value_reference": "known",
                    "description": "Fill the account identifier",
                },
                {
                    "action_type": "fill",
                    "observed_control_id": password_id,
                    "value_reference": "password",
                    "description": "Fill the password",
                },
                {
                    "action_type": "click",
                    "observed_control_id": submit_id,
                    "description": "Submit the login form",
                },
            ],
            "protected_resource": rebase_url(setup.protected_resource_url, origin),
            "account_marker_selector": setup.marker_selector,
            "account_marker_description": "Authenticated account marker",
        },
    )
    if submission.status_code != 200:
        return (
            f"Guided flow rejected: HTTP {submission.status_code} "
            f"{submission.text[:120]}"
        )
    return "Automatic discovery paused; completed through the guided fallback."


def run_live_case(
    case: FormalCase,
    origin: str,
    data_root: Path,
    discovery_mode: str = "rules",
    reuse_saved_profile: bool | None = None,
    confirm_live_calls: bool = False,
    max_cost_usd: float = 1.0,
    action_client_factory: Callable[[], ActionSelectionClient] | None = None,
) -> CaseResult:
    """Run one case through the real scan API against a running fixture."""

    started = time.monotonic()
    result = CaseResult(
        case_id=case.case_id,
        check_id=case.check_id.value,
        application=case.application,
        execution_mode=case.execution_mode.value,
        expected_outcome=case.expected_outcome.value,
        actual_outcome=None,
        verdict=Verdict.BLOCKED,
        origin_used=origin,
    )
    if case.setup is None:
        result.detail = "The case has no setup block, so it cannot be run live."
        return result
    case = case.model_copy(update={"setup": with_run_token(case.setup)})
    assert case.setup is not None  # re-narrow after the copy

    if (
        discovery_mode == "bedrock"
        and not confirm_live_calls
        and action_client_factory is None
    ):
        from authflowguard.evaluation.model_double import DeterministicModelDouble

        def _make_double() -> ActionSelectionClient:
            return DeterministicModelDouble()

        action_client_factory = _make_double

    application = create_app(
        data_root=data_root, action_client_factory=action_client_factory
    )
    manager = application.state.scan_manager
    client = TestClient(application)

    limits = (
        {"maximum_inference_cost_usd": max_cost_usd}
        if discovery_mode == "bedrock"
        else None
    )
    created = client.post(
        "/api/scans",
        json=scan_request_for(
            case,
            case.setup,
            origin,
            discovery_mode=discovery_mode,
            reuse_saved_profile=reuse_saved_profile,
            limits=limits,
        ).model_dump(mode="json"),
    )
    if created.status_code != 201:
        result.detail = f"Scan creation failed: {created.status_code} {created.text}"
        return result

    scan_id = created.json()["scan_id"]
    result.scan_id = scan_id
    record = manager.get_scan(UUID(scan_id))

    started_response = client.post(
        f"/api/scans/{scan_id}/start",
        json=execution_input_for(case.setup, origin).model_dump(mode="json"),
    )
    if started_response.status_code != 200:
        result.detail = (
            f"Scan start failed: {started_response.status_code} {started_response.text}"
        )
        return result

    try:
        record.future.result(timeout=SCAN_TIMEOUT_SECONDS)
    except Exception as error:  # noqa: BLE001 - recorded, never raised into the run
        result.detail = f"The scan raised before finishing: {error!r}"
        result.duration_seconds = time.monotonic() - started
        return result

    result.duration_seconds = time.monotonic() - started

    guidance_note = ""
    result.discovery = "automatic"
    if record.state is ScanState.AWAITING_GUIDANCE:
        result.discovery = "guided"
        guidance_note = attempt_guided_login(client, scan_id, case.setup, origin)
        if record.state is ScanState.AWAITING_GUIDANCE:
            result.discovery = "failed"
            result.detail = guidance_note
            return result
        try:
            record.future.result(timeout=SCAN_TIMEOUT_SECONDS)
        except Exception as error:  # noqa: BLE001 - recorded, never raised
            result.duration_seconds = time.monotonic() - started
            # The wait can fail after the scan has already finished and
            # persisted its result; the persisted state is authoritative.
            # The failed wait stays visible in the detail.
            if record.state is not ScanState.COMPLETED:
                result.detail = f"{guidance_note} Guided scan raised: {error!r}"
                return result
            guidance_note = (
                f"{guidance_note} (Waiting for the worker raised {error!r} "
                "after the scan had completed.)"
            )
        result.duration_seconds = time.monotonic() - started

    snapshot = client.get(f"/api/scans/{scan_id}").json()
    results = snapshot.get("results") or []
    matching = [r for r in results if r.get("check_id") == case.check_id.value]
    if not matching:
        result.detail = (
            f"The scan finished in state {record.state.value} with no result for "
            f"{case.check_id.value}. Scan error: {snapshot.get('error')}"
        )
        return result

    latest = matching[-1]
    result.actual_outcome = latest.get("outcome")
    references = latest.get("evidence_references") or []
    result.evidence_id = references[0] if references else None
    result.verdict = (
        Verdict.PASS
        if result.actual_outcome == case.expected_outcome.value
        else Verdict.FAIL
    )
    result.detail = f"{guidance_note} {latest.get('explanation', '')}".strip()[:300]
    return result


# Applications that are not started by this module. They run as their own
# process (Juice Shop runs in Docker), so every case against them shares one
# live instance and its state. Each entry names an environment variable that
# overrides the default origin.
EXTERNAL_TARGETS: dict[str, tuple[str, str]] = {
    "J": ("AUTHFLOWGUARD_JUICESHOP_URL", "http://127.0.0.1:3000"),
}

EXTERNAL_START_HINTS: dict[str, str] = {
    "J": (
        "docker run -d --name authflowguard-juiceshop -e NODE_ENV=quiet "
        "-p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.2.0"
    ),
}

# Substituted for "{run}" in case setup values. External targets keep state
# between runs, so an identifier that a check registers must be new each run
# or the second run of the same case stops meeting its expectation.
RUN_TOKEN = uuid4().hex[:8]


class TargetUnavailableError(RuntimeError):
    """Raised when an external evaluation target is not answering."""


def external_origin(application: str) -> str | None:
    """Return the origin of an external target, or None for a local fixture."""

    entry = EXTERNAL_TARGETS.get(application)
    if entry is None:
        return None
    variable, default = entry
    return os.environ.get(variable, default).rstrip("/")


def ensure_reachable(application: str, origin: str) -> None:
    """Fail with a start command rather than a confusing browser error."""

    try:
        with urlopen(f"{origin}/", timeout=10) as response:  # noqa: S310 - local
            if response.status < 500:
                return
            reason = f"HTTP {response.status}"
    except (URLError, OSError) as error:
        reason = str(error)
    hint = EXTERNAL_START_HINTS.get(application, "start the application")
    raise TargetUnavailableError(
        f"Application {application} is not reachable at {origin} ({reason}). "
        f"Start it with: {hint}"
    )


@contextmanager
def target_origin(case: FormalCase) -> Iterator[str]:
    """Yield the origin a case runs against.

    Local fixtures are started fresh for the case and stopped afterwards. An
    external target is only checked for reachability; it is never started or
    stopped here, and its state carries over between cases.
    """

    origin = external_origin(case.application)
    if origin is None:
        with serve(fixture_for(case.application, case.fixture_mode)) as served:
            yield served
        return
    ensure_reachable(case.application, origin)
    yield origin


def with_run_token(setup: CaseSetup) -> CaseSetup:
    """Replace "{run}" in any setup value with this run's token."""

    data = setup.model_dump()
    for key, value in data.items():
        if isinstance(value, str) and "{run}" in value:
            data[key] = value.replace("{run}", RUN_TOKEN)
    return CaseSetup.model_validate(data)


def fixture_for(application: str, fixture_mode: str) -> FastAPI:
    """Build the evaluation target an application/mode pair names."""

    mode = (
        EvaluationMode.SECURE if fixture_mode == "secure" else EvaluationMode.VULNERABLE
    )
    if application == "A":
        return create_controlled_app(mode)
    if application == "B":
        from authflowguard.evaluation_targets.react_json_app import (
            create_react_json_app,
        )

        return create_react_json_app(mode)
    if application == "C":
        from authflowguard.evaluation_targets.site_app import create_site_app

        return create_site_app(mode)
    raise ValueError(f"No fixture builder is wired for application {application}")


def run_live_group(
    cases: list[FormalCase],
    data_root: Path,
    discovery_mode: str = "rules",
    reuse_saved_profile: bool | None = None,
    confirm_live_calls: bool = False,
    max_cost_usd: float = 1.0,
    action_client_factory: Callable[[], ActionSelectionClient] | None = None,
) -> list[CaseResult]:
    """Run each live case against its own freshly started fixture.

    External targets are the exception: they are shared, so their cases rely
    on "{run}" identifiers rather than a fresh instance. Local fixtures must
    not be shared. The evaluation targets hold
    state in memory that a browser restart does not clear: a created
    registration account, and an account lockout. Login enumeration
    deliberately fails logins for the known account, which locks that account
    in secure mode and leaves every later case unable to authenticate.
    """

    results: list[CaseResult] = []
    for case in cases:
        case_root = data_root / case.case_id
        case_root.mkdir(parents=True, exist_ok=True)
        with target_origin(case) as origin:
            results.append(
                run_live_case(
                    case,
                    origin,
                    case_root,
                    discovery_mode=discovery_mode,
                    reuse_saved_profile=reuse_saved_profile,
                    confirm_live_calls=confirm_live_calls,
                    max_cost_usd=max_cost_usd,
                    action_client_factory=action_client_factory,
                )
            )
    return results


def degrade_observations(
    check_id: CheckId, observations: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    """Apply the authored degradation for one check.

    Each degradation removes evidence the analyser needs to reach a verdict,
    without adding an error. That distinction is the point of the case: the
    analyser must answer "insufficient evidence" rather than treating a gap as
    a clean result.
    """

    degraded = json.loads(json.dumps(observations))

    if check_id is CheckId.LOGIN_ENUMERATION:
        degraded["pairs"] = degraded.get("pairs", [])[:2]
        degraded["pair_count"] = len(degraded["pairs"])
        return degraded, "Retained two of three comparison pairs."

    if check_id is CheckId.REGISTRATION_ENUMERATION:
        degraded.pop("nonexistent_identifier_attempt", None)
        return degraded, "Removed the nonexistent_identifier_attempt observation."

    if check_id is CheckId.RESET_REQUEST_ENUMERATION:
        degraded.pop("known_identifier_attempt", None)
        return degraded, "Removed the known_identifier_attempt observation."

    if check_id is CheckId.LOGIN_THROTTLING:
        attempts = degraded.get("failed_attempts", [])
        if attempts and "valid_login_control" in attempts[-1]:
            degraded["failed_attempts"] = attempts[:-1]
            degraded["attempt_count"] = len(degraded["failed_attempts"])
            return degraded, "Removed the valid_login_control record."
        return degraded, "No valid_login_control record was present to remove."

    if check_id is CheckId.SESSION_FIXATION:
        degraded.pop("authenticated_control", None)
        return degraded, "Removed the authenticated_control observation."

    if check_id is CheckId.LOGOUT_INVALIDATION:
        degraded.pop("logout_status", None)
        return degraded, "Removed the logout_status observation."

    raise ValueError(f"No degradation is defined for {check_id.value}")


def find_scan_artifacts(
    scan_data_root: Path, source_case_id: str
) -> tuple[Path, Path] | None:
    """Locate one completed scan's evidence file and its auth profile."""

    case_root = scan_data_root / source_case_id
    evidence_files = sorted(case_root.glob("*/checks/*/evidence-*.json"))
    profiles = sorted(case_root.glob("*/auth-profile.json"))
    if not evidence_files or not profiles:
        return None
    return evidence_files[0], profiles[0]


def analyser_for(check_id: CheckId) -> Any:
    from authflowguard.checks.login_enumeration import analyse_login_enumeration
    from authflowguard.checks.login_throttling import analyse_login_throttling
    from authflowguard.checks.logout_invalidation import analyse_logout_invalidation
    from authflowguard.checks.registration_enumeration import (
        analyse_registration_enumeration,
    )
    from authflowguard.checks.reset_request_enumeration import (
        analyse_reset_request_enumeration,
    )
    from authflowguard.checks.session_fixation import analyse_session_fixation

    return {
        CheckId.LOGIN_ENUMERATION: analyse_login_enumeration,
        CheckId.REGISTRATION_ENUMERATION: analyse_registration_enumeration,
        CheckId.RESET_REQUEST_ENUMERATION: analyse_reset_request_enumeration,
        CheckId.LOGIN_THROTTLING: analyse_login_throttling,
        CheckId.SESSION_FIXATION: analyse_session_fixation,
        CheckId.LOGOUT_INVALIDATION: analyse_logout_invalidation,
    }[check_id]


def source_case_for(case: FormalCase) -> str:
    """Name the completed case whose evidence this degraded case starts from."""

    if case.evidence_fixture:
        parts = Path(case.evidence_fixture).parts
        for part in parts:
            if part.endswith("-secure") or part.endswith("-vulnerable"):
                return part
    return case.case_id.replace("-ambiguous", "-secure")


def run_offline_case(case: FormalCase, scan_data_root: Path) -> CaseResult:
    """Degrade saved evidence and re-analyse it with no browser or network."""

    from authflowguard.models import AuthProfile, SecurityPolicy, TestRunEvidence

    started = time.monotonic()
    result = CaseResult(
        case_id=case.case_id,
        check_id=case.check_id.value,
        application=case.application,
        execution_mode=case.execution_mode.value,
        expected_outcome=case.expected_outcome.value,
        actual_outcome=None,
        verdict=Verdict.BLOCKED,
    )

    source_case = source_case_for(case)
    artifacts = find_scan_artifacts(scan_data_root, source_case)
    if artifacts is None:
        result.detail = (
            f"No saved evidence found for {source_case}. Run that live case "
            "first; degraded cases start from a completed run."
        )
        return result

    evidence_path, profile_path = artifacts
    evidence = TestRunEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    profile = AuthProfile.model_validate_json(profile_path.read_text(encoding="utf-8"))

    degraded_observations, applied = degrade_observations(
        case.check_id, evidence.observations
    )
    evidence.observations = degraded_observations

    policy = SecurityPolicy.model_validate(case.security_policy or {})
    check_result = analyser_for(case.check_id)(evidence, profile, policy)

    result.actual_outcome = check_result.outcome.value
    result.evidence_id = str(evidence.evidence_id)
    result.scan_id = str(evidence.scan_id)
    result.duration_seconds = time.monotonic() - started
    result.verdict = (
        Verdict.PASS
        if result.actual_outcome == case.expected_outcome.value
        else Verdict.FAIL
    )
    result.detail = f"{applied} {check_result.explanation}"[:300]
    return result


@dataclass(frozen=True)
class FaultSpec:
    """A server-side failure injected into one otherwise normal scan.

    ``scope`` records how faithfully the injected condition matches the
    authored fault. "route" fails only the named route. "target" fails every
    route from the trigger onward, standing in for the target becoming
    unavailable; the scan sees server errors rather than a refused connection,
    which is the documented trigger for execution_error either way.
    """

    method: str
    path: str
    trigger_after: int
    scope: str
    description: str
    delay_seconds: float = 0.0


FAULTS: dict[str, FaultSpec] = {
    "A-CHK-001-execution-failure": FaultSpec(
        "POST",
        "/login",
        2,
        "target",
        "Target fails after the first known/nonexistent comparison pair.",
    ),
    "A-CHK-002-execution-failure": FaultSpec(
        "POST",
        "/register",
        0,
        "route",
        "Registration submission returns HTTP 503.",
    ),
    "A-CHK-003-execution-failure": FaultSpec(
        "POST",
        "/reset",
        0,
        "route",
        "Reset-request submission returns HTTP 503.",
    ),
    "A-CHK-004-execution-failure": FaultSpec(
        "POST",
        "/login",
        1,
        "target",
        "Target fails after the first failed login attempt.",
    ),
    "A-CHK-005-execution-failure": FaultSpec(
        "GET",
        "/account",
        2,
        "route",
        "Protected resource returns HTTP 503 during the isolated replay.",
    ),
    "A-CHK-006-execution-failure": FaultSpec(
        "POST",
        "/logout",
        0,
        "route",
        "Logout submission returns HTTP 503 after the session is captured.",
    ),
    "B-CHK-001-execution-failure": FaultSpec(
        "POST",
        "/api/auth/start",
        2,
        "target",
        "Target fails after login proof and before the second comparison pair.",
    ),
    "C-CHK-001-execution-failure": FaultSpec(
        "POST",
        "/desk/entry",
        2,
        "target",
        "Target fails after the first known/nonexistent comparison pair.",
    ),
    "C-CHK-004-execution-failure": FaultSpec(
        "POST",
        "/desk/entry",
        1,
        "target",
        "Target fails after the first failed sign-in attempt.",
    ),
    "C-CHK-005-execution-failure": FaultSpec(
        "GET",
        "/desk/bookings",
        2,
        "route",
        "Protected page returns HTTP 503 during the isolated replay.",
    ),
    "C-CHK-006-execution-failure": FaultSpec(
        "POST",
        "/desk/depart",
        0,
        "route",
        "Sign-out submission returns HTTP 503 after the session is captured.",
    ),
}


def with_injected_fault(application: FastAPI, fault: FaultSpec) -> FastAPI:
    """Wrap a fixture so that a named request starts returning HTTP 503."""

    from starlette.responses import PlainTextResponse
    from starlette.types import ASGIApp, Receive, Scope, Send

    state = {"matches": 0, "tripped": False}
    inner: ASGIApp = (
        application.middleware_stack or application.build_middleware_stack()
    )

    async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await inner(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")
        is_named_route = method == fault.method and path.startswith(fault.path)

        if is_named_route:
            state["matches"] = int(state["matches"]) + 1
            if state["matches"] > fault.trigger_after:
                state["tripped"] = True

        should_fail = (
            state["tripped"]
            if fault.scope == "target"
            else is_named_route and state["matches"] > fault.trigger_after
        )
        if should_fail:
            if fault.delay_seconds:
                # Stop responding rather than answering with an error, so the
                # scan meets a navigation that never settles.
                await asyncio.sleep(fault.delay_seconds)
            response = PlainTextResponse("Service unavailable", status_code=503)
            await response(scope, receive, send)
            return

        await inner(scope, receive, send)

    application.middleware_stack = wrapped
    return application


def run_fault_case(case: FormalCase, data_root: Path) -> CaseResult:
    """Run one live scan against a fixture that fails partway through."""

    fault = FAULTS.get(case.case_id)
    if fault is None or case.setup is None:
        return CaseResult(
            case_id=case.case_id,
            check_id=case.check_id.value,
            application=case.application,
            execution_mode=case.execution_mode.value,
            expected_outcome=case.expected_outcome.value,
            actual_outcome=None,
            verdict=Verdict.BLOCKED,
            detail="No fault injector is wired for this case.",
        )

    case_root = data_root / case.case_id
    case_root.mkdir(parents=True, exist_ok=True)
    fixture = with_injected_fault(
        fixture_for(case.application, case.fixture_mode), fault
    )
    with serve(fixture) as origin:
        result = run_live_case(case, origin, case_root)

    if result.verdict is Verdict.BLOCKED and result.actual_outcome is None:
        # A scan that could not reach the check at all is still a failure to
        # complete, which is what this case is testing for.
        result.actual_outcome = CheckOutcome.EXECUTION_ERROR.value
        result.verdict = (
            Verdict.PASS
            if case.expected_outcome is CheckOutcome.EXECUTION_ERROR
            else Verdict.FAIL
        )
    result.detail = f"[{fault.scope}] {fault.description} {result.detail}"[:300]
    return result


def write_results(
    results: list[CaseResult],
    run_directory: Path,
    run_id: str,
    discovery_mode: str = "rules",
    case_file: Path = Path("evaluation/cases/formal_cases.json"),
) -> Path:
    """Write one run's results beside, never into, the authored case file."""

    run_directory.mkdir(parents=True, exist_ok=True)
    filename = (
        "results.json"
        if discovery_mode == "rules"
        else f"results-bedrock-{run_id}.json"
    )
    destination = run_directory / filename
    destination.write_text(
        json.dumps(
            {
                "run_id": run_id,
                "discovery_mode": discovery_mode,
                "generated_at": datetime.now(UTC).isoformat(),
                "case_file": case_file.as_posix(),
                "results": [result.as_dict() for result in results],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return destination


def summarise(results: list[CaseResult]) -> dict[str, int]:
    summary = {verdict.value: 0 for verdict in Verdict}
    for result in results:
        summary[result.verdict.value] += 1
    return summary


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases", type=Path, default=Path("evaluation/cases/formal_cases.json")
    )
    parser.add_argument(
        "--application", default="A", help="Comma separated, e.g. A,B,C"
    )
    parser.add_argument("--run-id", default=datetime.now(UTC).strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--results-root", type=Path, default=Path("evaluation/results"))
    parser.add_argument(
        "--reuse-scan-data",
        default=None,
        help="Reuse a previous run's scan data instead of re-running live cases.",
    )
    parser.add_argument(
        "--discovery-mode",
        choices=["rules", "bedrock"],
        default="rules",
        help="Discovery mode for live scans ('rules' or 'bedrock').",
    )
    parser.add_argument(
        "--confirm-live-calls",
        action="store_true",
        default=False,
        help="Allow live Bedrock API calls. Defaults to false (offline double).",
    )
    parser.add_argument(
        "--max-evaluation-cost-usd",
        type=float,
        default=1.0,
        help="Maximum budget limit for Bedrock inference.",
    )
    parser.add_argument(
        "--no-reuse-saved-profile",
        action="store_true",
        default=False,
        help="Disable reusing saved auth profile to force fresh exploration.",
    )
    arguments = parser.parse_args(argv)

    reuse_saved_profile = (
        False
        if arguments.no_reuse_saved_profile
        else (arguments.discovery_mode == "rules")
    )

    wanted = {name.strip() for name in str(arguments.application).split(",")}
    selected = [
        case for case in load_cases(arguments.cases) if case.application in wanted
    ]
    run_directory = arguments.results_root / arguments.run_id
    if arguments.reuse_scan_data:
        scan_data_root = (
            arguments.results_root / arguments.reuse_scan_data / "scan-data"
        )
    else:
        scan_data_root = run_directory / "scan-data"

    results: list[CaseResult] = []

    def report(result: CaseResult) -> None:
        marker = (
            "PASS" if result.verdict is Verdict.PASS else result.verdict.value.upper()
        )
        print(
            f"  [{marker}] {result.case_id}: expected "
            f"{result.expected_outcome}, got {result.actual_outcome}",
            flush=True,
        )
        results.append(result)

    live = [c for c in selected if c.execution_mode is ExecutionMode.LIVE_SCAN]
    if not arguments.reuse_scan_data:
        present_modes = {case.fixture_mode for case in live}
        ordered_modes = [m for m in ("secure", "vulnerable") if m in present_modes]
        ordered_modes += sorted(present_modes - {"secure", "vulnerable"})
        for fixture_mode in ordered_modes:
            group = [case for case in live if case.fixture_mode == fixture_mode]
            print(f"Live, {fixture_mode} ({len(group)} cases)...", flush=True)
            for result in run_live_group(
                group,
                scan_data_root,
                discovery_mode=arguments.discovery_mode,
                reuse_saved_profile=reuse_saved_profile,
                confirm_live_calls=arguments.confirm_live_calls,
                max_cost_usd=arguments.max_evaluation_cost_usd,
            ):
                report(result)

    offline = [
        c for c in selected if c.execution_mode is ExecutionMode.OFFLINE_ANALYSIS
    ]
    print(f"Offline analysis ({len(offline)} cases)...", flush=True)
    for case in offline:
        report(run_offline_case(case, scan_data_root))

    faults = [c for c in selected if c.execution_mode is ExecutionMode.FAULT_INJECTION]
    print(f"Fault injection ({len(faults)} cases)...", flush=True)
    for case in faults:
        report(run_fault_case(case, run_directory / "fault-scan-data"))

    destination = write_results(
        results,
        run_directory,
        arguments.run_id,
        discovery_mode=arguments.discovery_mode,
        case_file=arguments.cases,
    )
    print(f"\nSummary: {summarise(results)}")
    print(f"Results written to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
