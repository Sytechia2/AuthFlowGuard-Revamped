"""Versioned, bounded messages exchanged with spawned scan workers."""

from enum import StrEnum
from typing import Any, Final, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from authflowguard.models import AuthProfile, ScanRequest

WORKER_PROTOCOL_VERSION: Final[Literal[1]] = 1


class WorkerOperation(StrEnum):
    SCAN = "scan"
    GUIDED_SCAN = "guided_scan"
    OBSERVE_GUIDANCE = "observe_guidance"


class WorkerMessageType(StrEnum):
    READY = "ready"
    PROGRESS = "progress"
    COMPLETED = "completed"
    GUIDANCE_REQUIRED = "guidance_required"
    OBSERVATION = "observation"
    CANCELLED = "cancelled"
    FAILED = "failed"
    CLEANUP_ACK = "cleanup_ack"
    USAGE_RESERVE = "usage_reserve"
    USAGE_DISPATCHED = "usage_dispatched"
    USAGE_SETTLE = "usage_settle"
    USAGE_RELEASE = "usage_release"


class WorkerCommand(BaseModel):
    """One immutable command transferred through spawn's private pipe."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal[1] = WORKER_PROTOCOL_VERSION
    correlation_id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    worker_generation: int = Field(ge=1)
    operation: WorkerOperation
    data_root: str
    request: ScanRequest
    execution: dict[str, Any] | None = None
    guidance: dict[str, Any] | None = None
    observation_url: str | None = None
    saved_profile: AuthProfile | None = None


class WorkerMessage(BaseModel):
    """A validated worker response that never includes raw exception text."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal[1] = WORKER_PROTOCOL_VERSION
    correlation_id: UUID
    scan_id: UUID
    worker_generation: int = Field(ge=1)
    sequence: int = Field(ge=1)
    message_type: WorkerMessageType
    error_code: str | None = None
    error: str | None = None
    continuation_execution: dict[str, Any] | None = None
    observation: dict[str, Any] | None = None
    completed_checks: list[str] = Field(default_factory=list)
    active_check: str | None = None
    cleanup_confirmed: bool = False
    attempt_id: UUID | None = None
    model_id: str | None = None
    region: str | None = None
    reserved_cost_usd: float | None = Field(default=None, ge=0)
    actual_cost_usd: float | None = Field(default=None, ge=0)
    input_price_usd_per_1000_tokens: float | None = Field(default=None, ge=0)
    output_price_usd_per_1000_tokens: float | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    safe_reason: str | None = None


class WorkerAcknowledgement(BaseModel):
    """Parent acknowledgement proving an accounting transition is durable."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal[1] = WORKER_PROTOCOL_VERSION
    correlation_id: UUID
    scan_id: UUID
    worker_generation: int = Field(ge=1)
    attempt_id: UUID
    message_type: WorkerMessageType
    accepted: bool
    error_code: str | None = None
