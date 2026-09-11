"""Tests for converting browser evidence into verified auth information."""

from uuid import UUID, uuid4

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


def make_page_evidence(scan_id: UUID, summary: str) -> EvidenceEvent:
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
            login_steps=[make_login_step()],
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


def make_login_step() -> BrowserAction:
    return BrowserAction(
        action_type=BrowserActionType.NAVIGATE,
        url="https://app.example/login",
        description="Open the login page",
    )


def test_profile_rejects_missing_authenticated_marker() -> None:
    scan_id = uuid4()

    with pytest.raises(ValueError, match="account marker was absent"):
        build_verified_login_profile(
            target=TargetScope(
                target_url="https://app.example/login",
                permitted_origins=["https://app.example"],
            ),
            login_steps=[make_login_step()],
            protected_resource="https://app.example/account",
            account_marker_description="The account name",
            authenticated_observation=ProtectedResourceObservation(
                evidence=make_page_evidence(scan_id, "Authenticated page"),
                account_marker_present=False,
            ),
            anonymous_observation=ProtectedResourceObservation(
                evidence=make_page_evidence(scan_id, "Anonymous page"),
                account_marker_present=False,
            ),
            discovery_source=DiscoverySource.AUTOMATIC,
        )


def test_profile_requires_independent_observations_from_the_same_scan() -> None:
    target = TargetScope(
        target_url="https://app.example/login",
        permitted_origins=["https://app.example"],
    )
    shared_evidence = make_page_evidence(uuid4(), "Reused page evidence")

    with pytest.raises(ValueError, match="must be independent"):
        build_verified_login_profile(
            target=target,
            login_steps=[make_login_step()],
            protected_resource="https://app.example/account",
            account_marker_description="The account name",
            authenticated_observation=ProtectedResourceObservation(
                evidence=shared_evidence,
                account_marker_present=True,
            ),
            anonymous_observation=ProtectedResourceObservation(
                evidence=shared_evidence,
                account_marker_present=False,
            ),
            discovery_source=DiscoverySource.AUTOMATIC,
        )

    with pytest.raises(ValueError, match="same scan"):
        build_verified_login_profile(
            target=target,
            login_steps=[make_login_step()],
            protected_resource="https://app.example/account",
            account_marker_description="The account name",
            authenticated_observation=ProtectedResourceObservation(
                evidence=make_page_evidence(uuid4(), "Authenticated page"),
                account_marker_present=True,
            ),
            anonymous_observation=ProtectedResourceObservation(
                evidence=make_page_evidence(uuid4(), "Anonymous page"),
                account_marker_present=False,
            ),
            discovery_source=DiscoverySource.AUTOMATIC,
        )


def test_profile_rejects_empty_flow_and_out_of_scope_resource() -> None:
    scan_id = uuid4()
    target = TargetScope(
        target_url="https://app.example/login",
        permitted_origins=["https://app.example"],
    )
    authenticated = ProtectedResourceObservation(
        evidence=make_page_evidence(scan_id, "Authenticated page"),
        account_marker_present=True,
    )
    anonymous = ProtectedResourceObservation(
        evidence=make_page_evidence(scan_id, "Anonymous page"),
        account_marker_present=False,
    )

    with pytest.raises(ValueError, match="at least one login step"):
        build_verified_login_profile(
            target=target,
            login_steps=[],
            protected_resource="https://app.example/account",
            account_marker_description="The account name",
            authenticated_observation=authenticated,
            anonymous_observation=anonymous,
            discovery_source=DiscoverySource.AUTOMATIC,
        )

    with pytest.raises(ValueError, match="outside permitted_origins"):
        build_verified_login_profile(
            target=target,
            login_steps=[make_login_step()],
            protected_resource="https://attacker.test/account",
            account_marker_description="The account name",
            authenticated_observation=authenticated,
            anonymous_observation=anonymous,
            discovery_source=DiscoverySource.AUTOMATIC,
        )


def test_profile_requires_page_evidence_and_sanitizes_the_resource_url() -> None:
    scan_id = uuid4()
    target = TargetScope(
        target_url="https://app.example/login",
        permitted_origins=["https://app.example"],
    )
    request_evidence = EvidenceEvent(
        event_id=uuid4(),
        scan_id=scan_id,
        kind=EvidenceKind.REQUEST,
        summary="This is traffic rather than page-state evidence",
    )

    with pytest.raises(ValueError, match="page-state evidence"):
        build_verified_login_profile(
            target=target,
            login_steps=[make_login_step()],
            protected_resource="https://app.example/account",
            account_marker_description="The account name",
            authenticated_observation=ProtectedResourceObservation(
                evidence=request_evidence,
                account_marker_present=True,
            ),
            anonymous_observation=ProtectedResourceObservation(
                evidence=make_page_evidence(scan_id, "Anonymous page"),
                account_marker_present=False,
            ),
            discovery_source=DiscoverySource.AUTOMATIC,
        )

    profile = build_verified_login_profile(
        target=target,
        login_steps=[make_login_step()],
        protected_resource=(
            "https://user:password@app.example/account?token=secret#private"
        ),
        account_marker_description="The account name",
        authenticated_observation=ProtectedResourceObservation(
            evidence=make_page_evidence(scan_id, "Authenticated page"),
            account_marker_present=True,
        ),
        anonymous_observation=ProtectedResourceObservation(
            evidence=make_page_evidence(scan_id, "Anonymous page"),
            account_marker_present=False,
        ),
        discovery_source=DiscoverySource.AUTOMATIC,
    )

    assert profile.protected_resource_check is not None
    assert profile.protected_resource_check.resource == "https://app.example/account"
    assert "password" not in profile.model_dump_json()
