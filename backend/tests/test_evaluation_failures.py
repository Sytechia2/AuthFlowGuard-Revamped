"""Failure-handling cases required by EVA-006 that the suite did not cover.

The governing rule is that a failure must produce an explicit outcome and must
never be reported as a security pass. These cover the model service being
unavailable, which no existing test exercised.
"""

import asyncio
from uuid import uuid4

import pytest
from authflowguard.automatic_actions import (
    AutomaticActionStatus,
    AutomaticBrowserController,
)
from authflowguard.models import ExecutionLimits, TargetScope
from authflowguard.secrets import RuntimeSecrets
from playwright.async_api import Page, async_playwright
from test_automatic_actions import FakeActionClient, run_controlled_server

pytestmark = pytest.mark.slow


class ModelServiceUnavailableError(RuntimeError):
    """Stands in for Bedrock being unreachable or refusing the request."""


async def run_against_outage(
    page: Page, origin: str, outcomes: list[Exception]
) -> tuple[AutomaticActionStatus, str, int]:
    target = TargetScope(target_url=f"{origin}/login", permitted_origins=[origin])
    client = FakeActionClient(outcomes)
    controller = AutomaticBrowserController(
        page=page,
        target=target,
        runtime_secrets=RuntimeSecrets({"known": "someone@example.test"}),
        scan_id=uuid4(),
        action_client=client,
        limits=ExecutionLimits(
            maximum_ai_decisions=6,
            maximum_action_retries=2,
            maximum_active_seconds=30,
        ),
        credential_references=["known"],
        password_references=frozenset(),
    )

    await page.goto(f"{origin}/login", wait_until="domcontentloaded")

    async def never_complete(_: Page) -> bool:
        return False

    result = await controller.run(never_complete)
    return result.status, result.reason, client.choose_calls


def test_model_service_outage_requests_guidance_and_never_reports_success() -> None:
    """An unreachable model must escalate, not quietly finish or crash.

    EVA-006 requires a model outage to produce an explicit outcome. The failure
    mode this guards against is a controller that swallows the error and lets a
    scan continue as though discovery had succeeded.
    """

    async def scenario() -> tuple[AutomaticActionStatus, str, int]:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                page = await browser.new_page()
                with run_controlled_server() as origin:
                    return await run_against_outage(
                        page,
                        origin,
                        [
                            ModelServiceUnavailableError("Bedrock is unreachable")
                            for _ in range(6)
                        ],
                    )
            finally:
                await browser.close()

    status, reason, choose_calls = asyncio.run(scenario())

    assert status is not AutomaticActionStatus.COMPLETED
    assert status is AutomaticActionStatus.GUIDANCE_REQUIRED
    assert choose_calls >= 1, "The controller never attempted a model request"
    assert reason, "An escalation must explain itself"


def test_model_outage_reason_does_not_leak_the_underlying_error() -> None:
    """The escalation message must not carry raw service detail.

    Page and service text is untrusted and may contain account or
    infrastructure detail, so it must not be passed through to the operator
    verbatim.
    """

    secret_marker = "arn:aws:bedrock:us-east-1:123456789012:model/secret"

    async def scenario() -> str:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                page = await browser.new_page()
                with run_controlled_server() as origin:
                    _, reason, _ = await run_against_outage(
                        page,
                        origin,
                        [ModelServiceUnavailableError(secret_marker) for _ in range(6)],
                    )
                    return reason
            finally:
                await browser.close()

    reason = asyncio.run(scenario())

    assert secret_marker not in reason
    assert "123456789012" not in reason


@pytest.mark.parametrize("failures", [1, 3])
def test_a_recovering_model_service_does_not_strand_the_scan(failures: int) -> None:
    """A transient outage must not permanently end a scan.

    The retry allowance exists so that one failed model request is not treated
    as a terminal condition.
    """

    async def scenario() -> int:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                page = await browser.new_page()
                with run_controlled_server() as origin:
                    _, _, calls = await run_against_outage(
                        page,
                        origin,
                        [
                            ModelServiceUnavailableError("temporary")
                            for _ in range(failures)
                        ],
                    )
                    return calls
            finally:
                await browser.close()

    assert asyncio.run(scenario()) >= 1


def test_a_target_that_stops_responding_never_reports_a_security_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A protected resource that hangs must not be read as a clean result.

    EVA-006 requires a timeout to produce an explicit outcome. The dangerous
    failure is a navigation that never settles being treated as "nothing
    observed", which would read as no_issue_observed.

    The scan runs in a thread rather than a worker process, so the test can
    shorten the browser's 30-second default timeout. The hang still outlasts
    that timeout, so the scan meets the same never-settling navigation in
    seconds rather than half a minute.
    """

    import functools
    from pathlib import Path

    from authflowguard import authentication
    from authflowguard.app import create_app
    from authflowguard.evaluation import case_runner
    from authflowguard.evaluation.case_runner import (
        FaultSpec,
        fixture_for,
        load_cases,
        run_live_case,
        serve,
        with_injected_fault,
    )
    from authflowguard.models import CheckOutcome
    from playwright.async_api import Browser, BrowserContext

    browser_timeout_ms = 3_000
    open_context = authentication._new_context

    async def short_timeout_context(browser: Browser) -> BrowserContext:
        context = await open_context(browser)
        context.set_default_timeout(browser_timeout_ms)
        return context

    monkeypatch.setattr(authentication, "_new_context", short_timeout_context)
    monkeypatch.setattr(
        case_runner,
        "create_app",
        functools.partial(create_app, worker_backend="thread"),
    )

    case = next(
        c
        for c in load_cases(
            Path(__file__).resolve().parents[2] / "evaluation/cases/formal_cases.json"
        )
        if c.case_id == "A-CHK-005-secure"
    )
    hang = FaultSpec(
        "GET",
        "/account",
        0,
        "route",
        "Protected resource stops responding.",
        delay_seconds=2 * browser_timeout_ms / 1000,
    )

    import tempfile

    with tempfile.TemporaryDirectory() as temporary:
        fixture = with_injected_fault(fixture_for("A", "secure"), hang)
        with serve(fixture) as origin:
            result = run_live_case(case, origin, Path(temporary))

    assert result.actual_outcome != CheckOutcome.NO_ISSUE_OBSERVED.value, (
        "A target that stopped responding was reported as a security pass"
    )
    assert result.actual_outcome in (None, CheckOutcome.EXECUTION_ERROR.value)
    assert result.detail, "A timeout must be explained, not left silent"
    # The browser's own time limit ended the scan, not some unrelated failure.
    assert "time limit" in result.detail
