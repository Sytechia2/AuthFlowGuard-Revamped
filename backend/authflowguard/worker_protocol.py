"""Versioned, bounded messages exchanged with spawned scan workers."""

from enum import StrEnum
from typing import Any, Final, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from authflowguard.models import AuthProfile, DiscoveryProvenance, ScanRequest

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
    provenance: DiscoveryProvenance | None = None
    execution: dict[str, Any] | None = None
    guidance: dict[str, Any] | None = None
    observation_url: str | None = None
    saved_profile: AuthProfile | None = None


class WorkerProgress(BaseModel):
    """Live execution state the API parent mirrors while a worker runs.

    Model usage figures are display copies; the durable cost ledger written by
    the worker remains the source of truth after the worker exits.
    """

    model_config = ConfigDict(extra="forbid")

    phase: str
    active_check: str | None = None
    completed_checks: list[str] = Field(default_factory=list)
    decision_count: int = Field(default=0, ge=0)
    model_request_count: int = Field(default=0, ge=0)
    total_input_tokens: int = Field(default=0, ge=0)
    total_output_tokens: int = Field(default=0, ge=0)
    estimated_cost_usd: float = Field(default=0.0, ge=0)
    unresolved_reservations_usd: float = Field(default=0.0, ge=0)
    stop_reason: str | None = None
    provenance: DiscoveryProvenance | None = None


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
    progress: WorkerProgress | None = None
    cleanup_confirmed: bool = False
