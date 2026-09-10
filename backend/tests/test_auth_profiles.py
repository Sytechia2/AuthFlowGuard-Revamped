"""Tests for converting browser evidence into verified auth information."""

from uuid import uuid4

import pytest

from authflowguard.auth_profiles import (
    ProtectedResourceObservation,
    build_verified_login_profile,
)
from authflowguard.models import (
    AuthFeature,
    BrowserAction,
    BrowserActionType,
    DiscoverySource,
    EvidenceEvent,
    EvidenceKind,
    FeatureStatus,
    TargetScope,
)


def make_page_evidence(scan_id, summary: str) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=uuid4(),
        scan_id=scan_id,
        kind=EvidenceKind.PAGE_STATE,
        summary=summary,
    )


def test_verified_profile_requires_authenticated_and_anonymous_comparison() -> None:
    scan_id = uuid4()
    authenticated_evidence = make_page_evidence(scan_id, "Authenticated page")
    anonymous_evidence = make_page_evidence(scan_id, "Anonymous page")
    target = TargetScope(
        target_url="https://app.example/login",
        permitted_origins=["https://app.example"],
    )
    login_steps = [
        BrowserAction(
            action_type=BrowserActionType.NAVIGATE,
            url="https://app.example/login",
            description="Open the login page",
        )
    ]

    profile = build_verified_login_profile(
        target=target,
        login_steps=login_steps,
        protected_resource="https://app.example/account",
        account_marker_description="The page contains the test account display name",
        authenticated_observation=ProtectedResourceObservation(
            evidence=authenticated_evidence,
            account_marker_present=True,
        ),
        anonymous_observation=ProtectedResourceObservation(
            evidence=anonymous_evidence,
            account_marker_present=False,
        ),
        discovery_source=DiscoverySource.AUTOMATIC,
    )

    assert profile.features[AuthFeature.LOGIN] is FeatureStatus.VERIFIED
    assert profile.protected_resource_check is not None
    assert profile.protected_resource_check.authenticated_evidence_ids == [
        authenticated_evidence.event_id
    ]
    assert profile.protected_resource_check.anonymous_evidence_ids == [
        anonymous_evidence.event_id
    ]


def test_profile_is_rejected_when_marker_is_visible_anonymously() -> None:
    scan_id = uuid4()
    authenticated_evidence = make_page_evidence(scan_id, "Authenticated page")
    anonymous_evidence = make_page_evidence(scan_id, "Anonymous page")
    target = TargetScope(
        target_url="https://app.example/login",
        permitted_origins=["https://app.example"],
    )

    with pytest.raises(ValueError, match="also present anonymously"):
        build_verified_login_profile(
            target=target,
            login_steps=[],
            protected_resource="https://app.example/account",
            account_marker_description="A marker that is not actually private",
            authenticated_observation=ProtectedResourceObservation(
                evidence=authenticated_evidence,
                account_marker_present=True,
            ),
            anonymous_observation=ProtectedResourceObservation(
                evidence=anonymous_evidence,
                account_marker_present=True,
            ),
            discovery_source=DiscoverySource.AUTOMATIC,
        )
