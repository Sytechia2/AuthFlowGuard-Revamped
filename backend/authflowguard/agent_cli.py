"""Run a bounded live-Bedrock authentication session from the command line."""

from __future__ import annotations

import argparse
import asyncio
import getpass
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from botocore.exceptions import BotoCoreError, ClientError
from playwright.async_api import BrowserContext, Page, async_playwright

from authflowguard.action_executor import ActionExecutionResult
from authflowguard.automatic_actions import (
    AutomaticActionResult,
    AutomaticActionStatus,
    AutomaticBrowserController,
)
from authflowguard.bedrock import (
    BedrockActionClient,
    BedrockActionDecision,
    BedrockConfiguration,
    BedrockResponseError,
)
from authflowguard.cancellation import close_resources
from authflowguard.models import EvidenceKind, ExecutionLimits, TargetScope
from authflowguard.secrets import RuntimeSecrets
from authflowguard.usage_ledger import DurableUsageLedger

DEFAULT_USERNAME_REFERENCE = "login-username"
DEFAULT_PASSWORD_REFERENCE = "login-password"


def read_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-url", required=True)
    parser.add_argument(
        "--permitted-origin",
        action="append",
        dest="permitted_origins",
        help="Allowed origin; repeat for separate frontend and API origins.",
    )
    parser.add_argument("--account-marker-selector", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--model-id", default="amazon.nova-micro-v1:0")
    parser.add_argument("--maximum-ai-decisions", type=int, default=40)
    parser.add_argument("--maximum-action-retries", type=int, default=2)
    parser.add_argument("--maximum-active-seconds", type=int, default=900)
    parser.add_argument("--maximum-cost-usd", type=float, default=0.25)
    parser.add_argument(
        "--run-id",
        type=UUID,
        help="Stable run identity used to resume the same durable cost budget.",
    )
    parser.add_argument(
        "--usage-root",
        type=Path,
        default=Path(".authflowguard-cli"),
        help="Directory for durable per-run usage ledgers.",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Show Chromium while the agent works.",
    )
    parser.add_argument(
        "--confirm-live-calls",
        action="store_true",
        help="Required acknowledgement that Bedrock requests may incur charges.",
    )
    return parser.parse_args(argv)


def build_target(target_url: str, permitted_origins: list[str] | None) -> TargetScope:
    origins = permitted_origins or [_origin_from_url(target_url)]
    return TargetScope(target_url=target_url, permitted_origins=origins)


def _origin_from_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("The target URL must be an absolute HTTP or HTTPS URL")
    return f"{parsed.scheme}://{parsed.netloc}"


def print_progress(
    decision: BedrockActionDecision,
    execution: ActionExecutionResult,
) -> None:
    print(f"Decision: {decision.action.action_type.value}")
    if decision.action.observed_control_id is not None:
        print(f"  Control: {decision.action.observed_control_id}")
    print(f"  Page: {execution.page_url_after}")
    print(f"  Tokens: {decision.input_tokens} input, {decision.output_tokens} output")
    print(f"  Estimated cost: ${decision.actual_cost_usd:.8f}")


async def marker_is_visible(page: Page, selector: str) -> bool:
    marker = page.locator(selector)
    return await marker.count() > 0 and await marker.first.is_visible()


async def run_live_session(
    arguments: argparse.Namespace,
    username: str,
    password: str,
) -> AutomaticActionResult:
    target = build_target(arguments.target_url, arguments.permitted_origins)
    limits = ExecutionLimits(
        maximum_ai_decisions=arguments.maximum_ai_decisions,
        maximum_action_retries=arguments.maximum_action_retries,
        maximum_active_seconds=arguments.maximum_active_seconds,
        maximum_inference_cost_usd=arguments.maximum_cost_usd,
    )
    configuration = BedrockConfiguration(
        aws_profile=arguments.profile,
        aws_region=arguments.region,
        model_id=arguments.model_id,
        maximum_estimated_cost_usd=arguments.maximum_cost_usd,
    )
    runtime_secrets = RuntimeSecrets(
        {
            DEFAULT_USERNAME_REFERENCE: username,
            DEFAULT_PASSWORD_REFERENCE: password,
        }
    )
    run_id = arguments.run_id or uuid4()
    usage_ledger = DurableUsageLedger(
        arguments.usage_root / str(run_id) / "usage.ndjson",
        run_id,
        arguments.maximum_cost_usd,
    )

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=not arguments.headed)
        context: BrowserContext | None = None
        try:
            context = await browser.new_context()
            page = await context.new_page()

            async def completion_check(current_page: Page) -> bool:
                return await marker_is_visible(
                    current_page,
                    arguments.account_marker_selector,
                )

            controller = AutomaticBrowserController(
                page=page,
                target=target,
                runtime_secrets=runtime_secrets,
                scan_id=run_id,
                action_client=BedrockActionClient(
                    configuration,
                    usage_accountant=usage_ledger,
                ),
                limits=limits,
                credential_references=[
                    DEFAULT_USERNAME_REFERENCE,
                    DEFAULT_PASSWORD_REFERENCE,
                ],
                progress_callback=print_progress,
            )
            return await controller.run(completion_check)
        finally:
            runtime_secrets.discard_all()
            await close_resources(context, browser)


def print_summary(result: AutomaticActionResult) -> None:
    print(f"Final status: {result.status.value}")
    print(f"Reason: {result.reason}")
    print(f"Model decisions attempted: {result.decision_attempts}")
    print(f"Failed attempts: {result.failed_attempts}")
    print(f"Accounted inference cost: ${result.accounted_cost_usd:.8f}")
    failures = [
        event
        for event in result.events
        if event.kind is EvidenceKind.ERROR
        and event.redacted_details.get("error_type") is not None
    ]
    for failure in failures:
        details = failure.redacted_details
        diagnostic = (
            f"Attempt {details['attempt']}: {details['failure_phase']} "
            f"failed with {details['error_type']}"
        )
        safe_reason = details.get("safe_reason")
        if safe_reason is not None:
            diagnostic += f" ({safe_reason})"
        action_type = details.get("action_type")
        if action_type is not None:
            diagnostic += f" [action={action_type}"
            control_id = details.get("observed_control_id")
            if control_id is not None:
                diagnostic += f", control={control_id}"
            diagnostic += "]"
        print(diagnostic)


def main(argv: list[str] | None = None) -> int:
    arguments = read_arguments(argv)
    if not arguments.confirm_live_calls:
        raise SystemExit(
            "Add --confirm-live-calls to acknowledge billable Bedrock requests."
        )

    username = input("Login username (kept in memory only): ")
    password = getpass.getpass("Login password (kept in memory only): ")
    if not username or not password:
        raise SystemExit("Both login credentials are required.")

    try:
        result = asyncio.run(run_live_session(arguments, username, password))
    except (BotoCoreError, ClientError, BedrockResponseError) as error:
        raise SystemExit(f"Live agent failed: {type(error).__name__}") from error

    print_summary(result)
    return 0 if result.status is AutomaticActionStatus.COMPLETED else 2


if __name__ == "__main__":
    raise SystemExit(main())
