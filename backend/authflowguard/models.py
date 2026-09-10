"""Shared data contracts used by the backend, worker, analysers, and interface.

These models represent data that may be saved to disk. Live passwords, cookies,
and bearer tokens therefore do not belong in this module. Runtime-only secret
handling will use a separate component.
"""

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


SCHEMA_VERSION = "1.0"


class ContractModel(BaseModel):
    """Base configuration shared by every persisted contract."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class CheckId(StrEnum):
    LOGIN_ENUMERATION = "login_enumeration"
    REGISTRATION_ENUMERATION = "registration_enumeration"
    RESET_REQUEST_ENUMERATION = "reset_request_enumeration"
    LOGIN_THROTTLING = "login_throttling"
    SESSION_FIXATION = "session_fixation"
    LOGOUT_INVALIDATION = "logout_invalidation"


class CheckOutcome(StrEnum):
    FINDING_CONFIRMED = "finding_confirmed"
    NO_ISSUE_OBSERVED = "no_issue_observed"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    EXECUTION_ERROR = "execution_error"


class BrowserActionType(StrEnum):
    NAVIGATE = "navigate"
    CLICK = "click"
    FILL = "fill"
    SELECT = "select"
    PRESS_KEY = "press_key"
    WAIT = "wait"


class ActionWaitCondition(StrEnum):
    LOAD = "load"
    DOM_CONTENT_LOADED = "domcontentloaded"
    NETWORK_IDLE = "networkidle"
    CONTROL_VISIBLE = "control_visible"
    CONTROL_HIDDEN = "control_hidden"


class AuthFeature(StrEnum):
    LOGIN = "login"
    REGISTRATION = "registration"
    RESET_REQUEST = "reset_request"
    LOGOUT = "logout"


class FeatureStatus(StrEnum):
    FOUND = "found"
    VERIFIED = "verified"
    ABSENT = "absent"
    UNSUPPORTED = "unsupported"


class DiscoverySource(StrEnum):
    AUTOMATIC = "automatic"
    GUIDED = "guided"


class EvidenceKind(StrEnum):
    ACTION = "action"
    REQUEST = "request"
    RESPONSE = "response"
    PAGE_STATE = "page_state"
    STORAGE_CHANGE = "storage_change"
    SCREENSHOT = "screenshot"
    ERROR = "error"


class CredentialReference(ContractModel):
    """A name that the runtime secret store resolves for the current scan."""

    reference_id: str = Field(min_length=1)
    purpose: str = Field(min_length=1)


class ExecutionLimits(ContractModel):
    maximum_ai_decisions: int = Field(default=40, ge=0)
    maximum_action_retries: int = Field(default=2, ge=0)
    maximum_active_seconds: int = Field(default=900, gt=0)
    maximum_inference_cost_usd: float = Field(default=0.25, ge=0)


class SecurityPolicy(ContractModel):
    account_existence_is_private: bool = True
    expected_lockout_threshold: int | None = Field(default=None, gt=0)


class TargetScope(ContractModel):
    target_url: HttpUrl
    permitted_origins: list[HttpUrl] = Field(min_length=1)


class ScanRequest(ContractModel):
    schema_version: str = SCHEMA_VERSION
    target: TargetScope
    selected_checks: list[CheckId] = Field(min_length=1)
    credential_references: list[CredentialReference] = Field(default_factory=list)
    disposable_identifier_references: list[CredentialReference] = Field(
        default_factory=list
    )
    policy: SecurityPolicy = Field(default_factory=SecurityPolicy)
    limits: ExecutionLimits = Field(default_factory=ExecutionLimits)

    @model_validator(mode="after")
    def selected_checks_must_be_unique(self) -> "ScanRequest":
        if len(self.selected_checks) != len(set(self.selected_checks)):
            raise ValueError("selected_checks must not contain duplicates")
        return self


class BrowserAction(ContractModel):
    schema_version: str = SCHEMA_VERSION
    action_id: UUID = Field(default_factory=uuid4)
    action_type: BrowserActionType
    observed_control_id: str | None = None
    url: HttpUrl | None = None
    value_reference: str | None = None
    option_value: str | None = None
    key: str | None = None
    wait_for: ActionWaitCondition | None = None
    description: str = Field(min_length=1)

    @model_validator(mode="after")
    def required_fields_must_match_action_type(self) -> "BrowserAction":
        if self.action_type is BrowserActionType.NAVIGATE and self.url is None:
            raise ValueError("A navigate action requires url")

        control_actions = {
            BrowserActionType.CLICK,
            BrowserActionType.FILL,
            BrowserActionType.SELECT,
        }
        if self.action_type in control_actions and self.observed_control_id is None:
            raise ValueError(f"A {self.action_type.value} action requires observed_control_id")

        if self.action_type is BrowserActionType.FILL and self.value_reference is None:
            raise ValueError("A fill action requires value_reference")

        if self.action_type is BrowserActionType.SELECT and self.option_value is None:
            raise ValueError("A select action requires option_value")

        if self.action_type is BrowserActionType.PRESS_KEY and self.key is None:
            raise ValueError("A press_key action requires key")

        if self.action_type is BrowserActionType.WAIT:
            if self.wait_for is None:
                raise ValueError("A wait action requires wait_for")

            control_waits = {
                ActionWaitCondition.CONTROL_VISIBLE,
                ActionWaitCondition.CONTROL_HIDDEN,
            }
            if self.wait_for in control_waits and self.observed_control_id is None:
                raise ValueError(
                    f"A {self.wait_for.value} wait requires observed_control_id"
                )

        return self


class TrafficReference(ContractModel):
    request_event_id: UUID
    response_event_id: UUID | None = None
    authentication_action_id: UUID | None = None


class SessionReference(ContractModel):
    """Nonreversible identity for observed session state, never its live value."""

    storage_type: str = Field(min_length=1)
    name: str = Field(min_length=1)
    value_fingerprint: str = Field(min_length=1)
    observed_event_id: UUID


class ProtectedResourceCheck(ContractModel):
    resource: str = Field(min_length=1)
    authenticated_evidence_ids: list[UUID] = Field(min_length=1)
    anonymous_evidence_ids: list[UUID] = Field(min_length=1)
    account_marker_description: str = Field(min_length=1)


class DiscoveryRecord(ContractModel):
    feature: AuthFeature
    source: DiscoverySource
    verified: bool
    evidence_ids: list[UUID] = Field(default_factory=list)
    notes: str | None = None


class AuthProfile(ContractModel):
    schema_version: str = SCHEMA_VERSION
    target: TargetScope
    features: dict[AuthFeature, FeatureStatus]
    authentication_steps: dict[AuthFeature, list[BrowserAction]] = Field(
        default_factory=dict
    )
    relevant_traffic: list[TrafficReference] = Field(default_factory=list)
    session_references: list[SessionReference] = Field(default_factory=list)
    protected_resource_check: ProtectedResourceCheck | None = None
    discovery_history: list[DiscoveryRecord] = Field(default_factory=list)


class EvidenceEvent(ContractModel):
    schema_version: str = SCHEMA_VERSION
    event_id: UUID
    scan_id: UUID
    check_id: CheckId | None = None
    action_id: UUID | None = None
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    kind: EvidenceKind
    summary: str = Field(min_length=1)
    redacted_details: dict[str, Any] = Field(default_factory=dict)


class Coverage(ContractModel):
    attempted_steps: list[str] = Field(default_factory=list)
    completed_steps: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class TestRunEvidence(ContractModel):
    schema_version: str = SCHEMA_VERSION
    evidence_id: UUID
    scan_id: UUID
    check_id: CheckId
    profile_version: str
    event_ids: list[UUID] = Field(default_factory=list)
    observations: dict[str, Any] = Field(default_factory=dict)
    control_comparisons: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)


class CheckResult(ContractModel):
    schema_version: str = SCHEMA_VERSION
    result_id: UUID
    scan_id: UUID
    check_id: CheckId
    outcome: CheckOutcome
    owasp_reference: str = Field(min_length=1)
    analyser_version: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    evidence_references: list[UUID] = Field(default_factory=list)
    coverage_limitations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
