"""Build authentication profiles from explicit browser evidence."""

from dataclasses import dataclass

from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    DiscoveryRecord,
    DiscoverySource,
    EvidenceEvent,
    EvidenceKind,
    FeatureStatus,
    ProtectedResourceCheck,
    SessionReference,
    TargetScope,
    TrafficReference,
)
from authflowguard.scope import (
    url_is_in_scope,
    url_without_query_keeping_route,
    url_without_query_or_fragment,
)

# The features found after the login, each saved with its own steps.
FORM_FEATURES = (AuthFeature.REGISTRATION, AuthFeature.RESET_REQUEST)
DISCOVERED_FEATURES = (*FORM_FEATURES, AuthFeature.LOGOUT)
FORM_DESCRIPTIONS = {
    AuthFeature.REGISTRATION: "Open the registration form",
    AuthFeature.RESET_REQUEST: "Open the password-reset request form",
}


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
    control_signatures: dict[str, str] | None = None,
    step_control_signatures: list[dict[str, str]] | None = None,
) -> AuthProfile:
    """Create a verified profile only when the two required controls agree."""

    if not login_steps:
        raise ValueError("A verified login profile requires at least one login step")

    if not url_is_in_scope(protected_resource, target):
        raise ValueError("The protected resource is outside permitted_origins")

    observations = [authenticated_observation, anonymous_observation]
    if any(
        observation.evidence.kind is not EvidenceKind.PAGE_STATE
        for observation in observations
    ):
        raise ValueError("Authentication observations must be page-state evidence")

    if not authenticated_observation.account_marker_present:
        raise ValueError(
            "Authenticated access was not verified: the account marker was absent"
        )

    if anonymous_observation.account_marker_present:
        raise ValueError(
            "Authenticated access was not verified: the account marker was also "
            "present anonymously"
        )

    if (
        authenticated_observation.evidence.scan_id
        != anonymous_observation.evidence.scan_id
    ):
        raise ValueError("Authentication observations must belong to the same scan")

    if (
        authenticated_observation.evidence.event_id
        == anonymous_observation.evidence.event_id
    ):
        raise ValueError("Authenticated and anonymous observations must be independent")

    authenticated_event_id = authenticated_observation.evidence.event_id
    anonymous_event_id = anonymous_observation.evidence.event_id

    return AuthProfile(
        target=target,
        features={AuthFeature.LOGIN: FeatureStatus.VERIFIED},
        authentication_steps={AuthFeature.LOGIN: login_steps},
        relevant_traffic=traffic or [],
        session_references=session_references or [],
        control_signatures=control_signatures or {},
        step_control_signatures=step_control_signatures or [],
        protected_resource_check=ProtectedResourceCheck(
            resource=url_without_query_or_fragment(protected_resource),
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


def login_discovery_source(profile: AuthProfile) -> DiscoverySource | None:
    """How the login was found: the latest login record, whatever came after."""

    for record in reversed(profile.discovery_history):
        if record.feature is AuthFeature.LOGIN:
            return record.source
    return None


def saved_form_url(profile: AuthProfile, feature: AuthFeature) -> str | None:
    """The saved, in-scope address of a registration or reset form, if any."""

    if feature not in FORM_FEATURES or profile.features.get(feature) not in {
        FeatureStatus.FOUND,
        FeatureStatus.VERIFIED,
    }:
        return None
    for action in profile.authentication_steps.get(feature, []):
        if action.action_type is BrowserActionType.NAVIGATE and action.url:
            url = str(action.url)
            return url if url_is_in_scope(url, profile.target) else None
    return None


def saved_logout_steps(profile: AuthProfile) -> list[BrowserAction]:
    """The verified logout flow, or nothing when none was saved."""

    if profile.features.get(AuthFeature.LOGOUT) is not FeatureStatus.VERIFIED:
        return []
    return list(profile.authentication_steps.get(AuthFeature.LOGOUT, []))


def _with_feature(
    profile: AuthProfile,
    feature: AuthFeature,
    status: FeatureStatus,
    steps: list[BrowserAction],
    record: DiscoveryRecord,
) -> AuthProfile:
    history = [
        item for item in profile.discovery_history if item.feature is not feature
    ]
    return profile.model_copy(
        update={
            "features": {**profile.features, feature: status},
            "authentication_steps": {**profile.authentication_steps, feature: steps},
            # The login record stays where it was; the feature's record follows.
            "discovery_history": [*history, record],
        }
    )


def with_form_link(
    profile: AuthProfile,
    feature: AuthFeature,
    form_url: str,
    source: DiscoverySource,
    notes: str,
) -> AuthProfile:
    """Save the address a registration or reset link opens.

    The query is removed and a client-side route kept. The feature is
    ``found``: the address was validated, not yet exercised.
    """

    if feature not in FORM_FEATURES:
        raise ValueError("Only registration and reset forms are saved by address")
    if not url_is_in_scope(form_url, profile.target):
        raise ValueError("The form address is outside permitted_origins")
    navigation = BrowserAction(
        action_type=BrowserActionType.NAVIGATE,
        url=url_without_query_keeping_route(form_url),
        description=FORM_DESCRIPTIONS[feature],
    )
    return _with_feature(
        profile,
        feature,
        FeatureStatus.FOUND,
        [navigation],
        DiscoveryRecord(feature=feature, source=source, verified=False, notes=notes),
    )


def with_logout_flow(
    profile: AuthProfile,
    steps: list[BrowserAction],
    source: DiscoverySource,
    notes: str,
) -> AuthProfile:
    """Save a logout flow that was shown to sign the account out."""

    if not steps:
        raise ValueError("A logout flow needs at least one step")
    return _with_feature(
        profile,
        AuthFeature.LOGOUT,
        FeatureStatus.VERIFIED,
        steps,
        DiscoveryRecord(
            feature=AuthFeature.LOGOUT, source=source, verified=True, notes=notes
        ),
    )


def with_features_of(profile: AuthProfile, saved: AuthProfile) -> AuthProfile:
    """Keep the registration, reset and logout features a saved profile had."""

    for feature in DISCOVERED_FEATURES:
        status = saved.features.get(feature)
        steps = saved.authentication_steps.get(feature)
        if status is None or not steps:
            continue
        record = next(
            (
                item
                for item in reversed(saved.discovery_history)
                if item.feature is feature
            ),
            None,
        )
        if record is None:
            continue
        profile = _with_feature(profile, feature, status, list(steps), record)
    return profile
