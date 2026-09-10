"""Build authentication profiles from explicit browser evidence."""

from dataclasses import dataclass

from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    DiscoveryRecord,
    DiscoverySource,
    EvidenceEvent,
    FeatureStatus,
    ProtectedResourceCheck,
    SessionReference,
    TargetScope,
    TrafficReference,
)


@dataclass(frozen=True)
class ProtectedResourceObservation:
    evidence: EvidenceEvent
    account_marker_present: bool


def build_verified_login_profile(
    target: TargetScope,
    login_steps: list[BrowserAction],
    protected_resource: str,
    account_marker_description: str,
    authenticated_observation: ProtectedResourceObservation,
    anonymous_observation: ProtectedResourceObservation,
    discovery_source: DiscoverySource,
    traffic: list[TrafficReference] | None = None,
    session_references: list[SessionReference] | None = None,
) -> AuthProfile:
    """Create a verified profile only when the two required controls agree."""

    if not authenticated_observation.account_marker_present:
        raise ValueError(
            "Authenticated access was not verified: the account marker was absent"
        )

    if anonymous_observation.account_marker_present:
        raise ValueError(
            "Authenticated access was not verified: the account marker was also "
            "present anonymously"
        )

    if authenticated_observation.evidence.scan_id != anonymous_observation.evidence.scan_id:
        raise ValueError("Authentication observations must belong to the same scan")

    authenticated_event_id = authenticated_observation.evidence.event_id
    anonymous_event_id = anonymous_observation.evidence.event_id

    return AuthProfile(
        target=target,
        features={AuthFeature.LOGIN: FeatureStatus.VERIFIED},
        authentication_steps={AuthFeature.LOGIN: login_steps},
        relevant_traffic=traffic or [],
        session_references=session_references or [],
        protected_resource_check=ProtectedResourceCheck(
            resource=protected_resource,
            authenticated_evidence_ids=[authenticated_event_id],
            anonymous_evidence_ids=[anonymous_event_id],
            account_marker_description=account_marker_description,
        ),
        discovery_history=[
            DiscoveryRecord(
                feature=AuthFeature.LOGIN,
                source=discovery_source,
                verified=True,
                evidence_ids=[authenticated_event_id, anonymous_event_id],
            )
        ],
    )
