"""Tests for the live-agent command-line boundary without contacting AWS."""

import pytest
from authflowguard.agent_cli import build_target, main, read_arguments
from pydantic import ValidationError


def required_arguments() -> list[str]:
    return [
        "--target-url",
        "http://127.0.0.1:8001/login",
        "--account-marker-selector",
        '[data-testid="account-marker"]',
        "--profile",
        "authflowguard-dev",
        "--region",
        "us-east-1",
    ]


def test_cli_requires_explicit_confirmation_before_prompting_or_calling_aws() -> None:
    with pytest.raises(SystemExit, match="confirm-live-calls"):
        main(required_arguments())


def test_cli_defaults_match_the_scan_limits_and_nova_micro() -> None:
    arguments = read_arguments(required_arguments())

    assert arguments.model_id == "amazon.nova-micro-v1:0"
    assert arguments.maximum_ai_decisions == 40
    assert arguments.maximum_action_retries == 2
    assert arguments.maximum_active_seconds == 900
    assert arguments.maximum_cost_usd == 0.25
    assert arguments.headed is False


def test_target_defaults_to_its_own_origin_and_accepts_explicit_api_origins() -> None:
    default_target = build_target("http://127.0.0.1:8001/login", None)
    explicit_target = build_target(
        "https://app.example/login",
        ["https://app.example", "https://api.example"],
    )

    assert [str(origin) for origin in default_target.permitted_origins] == [
        "http://127.0.0.1:8001/"
    ]
    assert [str(origin) for origin in explicit_target.permitted_origins] == [
        "https://app.example/",
        "https://api.example/",
    ]


def test_target_rejects_non_http_addresses() -> None:
    with pytest.raises(ValueError, match="absolute HTTP"):
        build_target("file:///temporary/login.html", None)

    with pytest.raises(ValidationError):
        build_target("https://app.example/login", ["not-an-origin"])
