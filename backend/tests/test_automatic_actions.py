"""Offline-model and real-browser tests for automatic action orchestration."""

import asyncio
import socket
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from threading import Thread
from uuid import uuid4

import pytest
import uvicorn
from authflowguard.automatic_actions import (
    AutomaticActionResult,
    AutomaticActionStatus,
    AutomaticBrowserController,
)
from authflowguard.bedrock import BedrockActionDecision, PageObservationForModel
from authflowguard.evaluation_targets.controlled_app import (
    KNOWN_PASSWORD,
    KNOWN_USERNAME,
    EvaluationMode,
    create_controlled_app,
)
from authflowguard.models import (
    BrowserAction,
    BrowserActionType,
    EvidenceKind,
    ExecutionLimits,
    TargetScope,
)
from authflowguard.secrets import RuntimeSecrets
from playwright.async_api import Page, async_playwright


class FakeActionClient:
    def __init__(
        self,
        outcomes: Sequence[BrowserAction | Exception],
        *,
        reserved_cost: float = 0.01,
        actual_cost: float = 0.001,
        delay_seconds: float = 0.0,
    ) -> None:
        self._outcomes = list(outcomes)
        self.reserved_cost = reserved_cost
        self.actual_cost = actual_cost
        self.delay_seconds = delay_seconds
        self.observations: list[PageObservationForModel] = []
        self.choose_calls = 0

    def estimate_maximum_cost(self, observation: PageObservationForModel) -> float:
        return self.reserved_cost

    def choose_action(
        self, observation: PageObservationForModel
    ) -> BedrockActionDecision:
        self.choose_calls += 1
        self.observations.append(observation)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return BedrockActionDecision(
            action=outcome,
            input_tokens=10,
            output_tokens=5,
            actual_cost_usd=self.actual_cost,
            reserved_cost_usd=self.reserved_cost,
        )


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


def login_actions() -> list[BrowserAction]:
    return [
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


async def account_marker_is_visible(page: Page) -> bool:
    marker = page.locator('[data-testid="account-marker"]')
    return await marker.count() == 1 and await marker.is_visible()


async def run_controller(
    origin: str,
    client: FakeActionClient,
    limits: ExecutionLimits,
) -> AutomaticActionResult:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        target = TargetScope(
            target_url=f"{origin}/login",
            permitted_origins=[origin],
        )
        controller = AutomaticBrowserController(
            page=page,
            target=target,
            runtime_secrets=RuntimeSecrets(
                {
                    "login-username": KNOWN_USERNAME,
                    "login-password": KNOWN_PASSWORD,
                }
            ),
            scan_id=uuid4(),
            action_client=client,
            limits=limits,
            credential_references=["login-username", "login-password"],
        )
        try:
            return await controller.run(account_marker_is_visible)
        finally:
            await context.close()
            await browser.close()


def test_bedrock_decisions_drive_browser_actions_until_completion() -> None:
    client = FakeActionClient(login_actions())
    with run_controlled_server() as origin:
        result = asyncio.run(
            run_controller(
                origin,
                client,
                ExecutionLimits(
                    maximum_ai_decisions=10,
                    maximum_inference_cost_usd=0.25,
                ),
            )
        )

    assert result.status is AutomaticActionStatus.COMPLETED
    assert result.decision_attempts == 3
    assert result.failed_attempts == 0
    assert result.accounted_cost_usd == pytest.approx(0.003)
    assert len(result.decisions) == 3
    assert result.traffic
    assert all(
        observation.credential_references == ["login-username", "login-password"]
        for observation in client.observations
    )
    observed_control_ids = [
        {control.observed_control_id for control in observation.controls}
        for observation in client.observations
    ]
    assert "control-5" in observed_control_ids[0]
    assert "control-4" not in observed_control_ids[0]
    assert "control-5" not in observed_control_ids[1]
    assert "control-6" not in observed_control_ids[2]
    assert client.observations[1].completed_fill_controls == ["control-5"]
    assert client.observations[2].completed_fill_controls == [
        "control-5",
        "control-6",
    ]
    persisted_output = "".join(event.model_dump_json() for event in result.events)
    assert KNOWN_USERNAME not in persisted_output
    assert KNOWN_PASSWORD not in persisted_output


def test_model_observation_redacts_credentials_echoed_by_the_page() -> None:
    canary = "model-credential-canary-2-2"

    class FakePage:
        url = f"https://app.example/login?echo={canary}"

        async def title(self) -> str:
            return f"Welcome {canary}"

    class FakeRecorder:
        async def read_controls(self, _page: object) -> list[dict[str, object]]:
            return [
                {
                    "observed_control_id": "control-1",
                    "tag": "input",
                    "name": f"username-{canary}",
                    "type": "text",
                    "placeholder": f"Enter {canary}",
                    "autocomplete": "username",
                    "aria_label": canary,
                    "value_present": True,
                    "visible": True,
                }
            ]

    controller = AutomaticBrowserController(
        page=FakePage(),  # type: ignore[arg-type]
        target=TargetScope(
            target_url="https://app.example/login",
            permitted_origins=["https://app.example"],
        ),
        runtime_secrets=RuntimeSecrets({"username": canary}),
        scan_id=uuid4(),
        action_client=FakeActionClient([]),
        limits=ExecutionLimits(),
        credential_references=["username"],
    )
    controller._recorder = FakeRecorder()  # type: ignore[assignment]

    observation = asyncio.run(controller._observe_page(False, set()))

    serialized = observation.model_dump_json()
    assert canary not in serialized
    assert "[redacted]" in serialized
    assert observation.credential_references == ["username"]


def test_failed_action_is_retried_with_a_fresh_decision() -> None:
    invalid_action = BrowserAction(
        action_type=BrowserActionType.CLICK,
        observed_control_id="control-999",
        description="Use a stale control",
    )
    client = FakeActionClient([invalid_action, *login_actions()])
    with run_controlled_server() as origin:
        result = asyncio.run(
            run_controller(
                origin,
                client,
                ExecutionLimits(
                    maximum_ai_decisions=10,
                    maximum_action_retries=2,
                    maximum_inference_cost_usd=0.25,
                ),
            )
        )

    assert result.status is AutomaticActionStatus.COMPLETED
    assert result.decision_attempts == 4
    assert result.failed_attempts == 1
    assert [
        observation.previous_attempt_failed for observation in client.observations
    ] == [False, True, False, False]
    assert (
        len([event for event in result.events if event.kind is EvidenceKind.ERROR]) == 1
    )
    failure = next(
        event
        for event in result.events
        if event.redacted_details.get("error_type") is not None
    )
    assert failure.redacted_details["failure_phase"] == "browser_execution"


def test_three_failed_attempts_request_guidance_without_exposing_errors() -> None:
    client = FakeActionClient([RuntimeError("secret one-time value")] * 3)
    with run_controlled_server() as origin:
        result = asyncio.run(
            run_controller(
                origin,
                client,
                ExecutionLimits(
                    maximum_ai_decisions=10,
                    maximum_action_retries=2,
                    maximum_inference_cost_usd=0.25,
                ),
            )
        )

    assert result.status is AutomaticActionStatus.GUIDANCE_REQUIRED
    assert result.decision_attempts == 3
    assert result.failed_attempts == 3
    assert result.accounted_cost_usd == pytest.approx(0.03)
    failures = [
        event
        for event in result.events
        if event.redacted_details.get("error_type") is not None
    ]
    assert all(
        failure.redacted_details["failure_phase"] == "model_selection"
        for failure in failures
    )
    assert "secret one-time value" not in "".join(
        event.model_dump_json() for event in result.events
    )


def test_decision_limit_stops_additional_model_calls() -> None:
    client = FakeActionClient(login_actions())
    with run_controlled_server() as origin:
        result = asyncio.run(
            run_controller(
                origin,
                client,
                ExecutionLimits(
                    maximum_ai_decisions=1,
                    maximum_inference_cost_usd=0.25,
                ),
            )
        )

    assert result.status is AutomaticActionStatus.DECISION_LIMIT_REACHED
    assert result.decision_attempts == 1
    assert client.choose_calls == 1


def test_cost_limit_is_checked_before_calling_the_model() -> None:
    client = FakeActionClient(login_actions(), reserved_cost=0.3)
    with run_controlled_server() as origin:
        result = asyncio.run(
            run_controller(
                origin,
                client,
                ExecutionLimits(
                    maximum_ai_decisions=10,
                    maximum_inference_cost_usd=0.25,
                ),
            )
        )

    assert result.status is AutomaticActionStatus.COST_LIMIT_REACHED
    assert result.decision_attempts == 0
    assert client.choose_calls == 0


def test_active_time_limit_stops_a_slow_model_request() -> None:
    client = FakeActionClient(login_actions(), delay_seconds=1.2)
    with run_controlled_server() as origin:
        result = asyncio.run(
            run_controller(
                origin,
                client,
                ExecutionLimits(
                    maximum_ai_decisions=10,
                    maximum_active_seconds=1,
                    maximum_inference_cost_usd=0.25,
                ),
            )
        )

    assert result.status is AutomaticActionStatus.ACTIVE_TIME_LIMIT_REACHED
    assert result.decision_attempts == 1
    assert result.accounted_cost_usd == pytest.approx(0.01)
