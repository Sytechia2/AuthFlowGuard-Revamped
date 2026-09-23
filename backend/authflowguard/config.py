"""Server-side configuration and safe capabilities discovery for Bedrock."""

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from authflowguard.bedrock import MODEL_PRICES_USD_PER_1000_TOKENS

DEFAULT_AWS_PROFILE = "authflowguard-dev"
DEFAULT_AWS_REGION = "us-east-1"
DEFAULT_BEDROCK_MODEL_ID = "amazon.nova-micro-v1:0"
DEFAULT_MAX_ESTIMATED_COST_USD = 0.001
DEFAULT_MAX_OUTPUT_TOKENS = 128

SERVER_MAX_DECISIONS = 100
SERVER_MAX_SECONDS = 1800
SERVER_MAX_COST_USD = 1.0

MODEL_DISPLAY_NAMES = {
    "amazon.nova-micro-v1:0": "Amazon Nova Micro",
    "amazon.nova-lite-v1:0": "Amazon Nova Lite",
}


class BedrockServerSettings(BaseModel):
    """Server-side settings loaded from environment or local defaults."""

    model_config = ConfigDict(extra="forbid")

    aws_profile: str = Field(default=DEFAULT_AWS_PROFILE, min_length=1)
    aws_region: str = Field(default=DEFAULT_AWS_REGION, min_length=1)
    model_id: str = Field(default=DEFAULT_BEDROCK_MODEL_ID, min_length=1)
    max_output_tokens: int = Field(default=DEFAULT_MAX_OUTPUT_TOKENS, ge=1, le=256)
    maximum_estimated_cost_usd: float = Field(
        default=DEFAULT_MAX_ESTIMATED_COST_USD, gt=0
    )
    server_max_decisions: int = Field(default=SERVER_MAX_DECISIONS, gt=0)
    server_max_seconds: int = Field(default=SERVER_MAX_SECONDS, gt=0)
    server_max_cost_usd: float = Field(default=SERVER_MAX_COST_USD, gt=0)


def load_server_settings() -> BedrockServerSettings:
    """Read configuration from server environment variables with fallback defaults."""
    return BedrockServerSettings(
        aws_profile=os.getenv("AFG_AWS_PROFILE", DEFAULT_AWS_PROFILE),
        aws_region=os.getenv("AFG_AWS_REGION", DEFAULT_AWS_REGION),
        model_id=os.getenv("AFG_BEDROCK_MODEL_ID", DEFAULT_BEDROCK_MODEL_ID),
        max_output_tokens=int(
            os.getenv("AFG_MAX_OUTPUT_TOKENS", str(DEFAULT_MAX_OUTPUT_TOKENS))
        ),
        maximum_estimated_cost_usd=float(
            os.getenv("AFG_MAX_ESTIMATED_COST_USD", str(DEFAULT_MAX_ESTIMATED_COST_USD))
        ),
        server_max_decisions=int(
            os.getenv("AFG_SERVER_MAX_DECISIONS", str(SERVER_MAX_DECISIONS))
        ),
        server_max_seconds=int(
            os.getenv("AFG_SERVER_MAX_SECONDS", str(SERVER_MAX_SECONDS))
        ),
        server_max_cost_usd=float(
            os.getenv("AFG_SERVER_MAX_COST_USD", str(SERVER_MAX_COST_USD))
        ),
    )


def is_bedrock_configured(settings: BedrockServerSettings | None = None) -> bool:
    """Check if Bedrock parameters and profile configuration exist locally.

    Note: "configured" indicates valid local parameter settings; it explicitly
    does not verify live network reachability, active SSO token, or AWS quotas.
    """
    cfg = settings or load_server_settings()
    if cfg.model_id not in MODEL_PRICES_USD_PER_1000_TOKENS:
        return False
    if not cfg.aws_region or not cfg.aws_profile:
        return False

    # Check if explicit AWS credentials exist in env
    has_env_credentials = bool(
        os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
    )
    if has_env_credentials:
        return True

    # Check if AWS config/credentials files exist in ~/.aws
    aws_dir = Path.home() / ".aws"
    config_file = aws_dir / "config"
    credentials_file = aws_dir / "credentials"
    if config_file.exists() or credentials_file.exists():
        return True

    return False


def validate_bedrock_configuration(
    settings: BedrockServerSettings | None = None,
) -> tuple[bool, str | None]:
    """Validate settings and return (is_valid, error_reason_if_invalid)."""
    cfg = settings or load_server_settings()
    if cfg.model_id not in MODEL_PRICES_USD_PER_1000_TOKENS:
        return False, f"Model '{cfg.model_id}' has no configured pricing table entry."
    if not is_bedrock_configured(cfg):
        return (
            False,
            f"AWS profile '{cfg.aws_profile}' or credentials are not configured.",
        )
    return True, None


def get_capabilities(
    settings: BedrockServerSettings | None = None,
) -> dict[str, Any]:
    """Return a safe capability description without leaking credentials."""
    cfg = settings or load_server_settings()
    configured = is_bedrock_configured(cfg)
    model_name = MODEL_DISPLAY_NAMES.get(cfg.model_id, cfg.model_id)

    return {
        "bedrock_configured": configured,
        "model_id": cfg.model_id,
        "model_name": model_name,
        "pricing_configured": cfg.model_id in MODEL_PRICES_USD_PER_1000_TOKENS,
        "note": (
            "Configured locally; live access and AWS service quotas are verified "
            "only when requests are dispatched."
            if configured
            else "AWS profile or credentials are not configured on the backend."
        ),
        "default_limits": {
            "maximum_ai_decisions": 40,
            "maximum_active_seconds": 900,
            "maximum_inference_cost_usd": 0.25,
        },
        "server_max_limits": {
            "maximum_ai_decisions": cfg.server_max_decisions,
            "maximum_active_seconds": cfg.server_max_seconds,
            "maximum_inference_cost_usd": cfg.server_max_cost_usd,
        },
    }
