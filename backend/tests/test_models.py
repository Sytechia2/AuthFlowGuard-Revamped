"""Tests for the shared persisted data contracts."""

from uuid import uuid4

import pytest
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    CheckId,
    CheckOutcome,
    CheckResult,
    CredentialReference,
    FeatureStatus,
    ScanRequest,
    TargetScope,
)
from pydantic import ValidationError


def make_target_scope() -> TargetScope:
    return TargetScope(
        target_url="https://test.example/login",
        permitted_origins=["https://test.example"],
    )


def test_scan_request_uses_references_instead_of_live_credentials() -> None:
    request = ScanRequest(
        target=make_target_scope(),
        selected_checks=[CheckId.LOGIN_ENUMERATION],
        credential_references=[
            CredentialReference(
                reference_id="primary-account-password",
                purpose="Password for the primary test account",
            )
        ],
    )

    saved_json = request.model_dump_json()

    assert "primary-account-password" in saved_json
    assert "actual-secret-password" not in saved_json

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CredentialReference.model_validate(
            {
                "reference_id": "primary-account-password",
                "purpose": "Password for the primary test account",
                "live_value": "actual-secret-password",
            }
        )


def test_scan_request_rejects_duplicate_checks() -> None:
    with pytest.raises(ValidationError, match="must not contain duplicates"):
        ScanRequest(
            target=make_target_scope(),
            selected_checks=[
                CheckId.LOGIN_ENUMERATION,
                CheckId.LOGIN_ENUMERATION,
            ],
        )


def test_auth_profile_round_trips_through_json() -> None:
    profile = AuthProfile(
        target=make_target_scope(),
        features={AuthFeature.LOGIN: FeatureStatus.VERIFIED},
        authentication_steps={
            AuthFeature.LOGIN: [
                BrowserAction(
                    action_type=BrowserActionType.FILL,
                    observed_control_id="password-field",
                    value_reference="primary-account-password",
                    description="Fill the password field from the runtime secret store",
                )
            ]
        },
    )

    restored_profile = AuthProfile.model_validate_json(profile.model_dump_json())

    assert restored_profile == profile
    assert restored_profile.authentication_steps[AuthFeature.LOGIN][
        0
    ].value_reference == ("primary-account-password")


def test_contracts_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        TargetScope.model_validate(
            {
                "target_url": "https://test.example/login",
                "permitted_origins": ["https://test.example"],
                "password": "a secret that must not be stored",
            }
        )


@pytest.mark.parametrize(
    ("action_type", "extra_fields"),
    [
        (BrowserActionType.NAVIGATE, {"url": "https://test.example", "key": "Enter"}),
        (
            BrowserActionType.CLICK,
            {"observed_control_id": "control-1", "value_reference": "secret"},
        ),
        (
            BrowserActionType.FILL,
            {
                "observed_control_id": "control-1",
                "value_reference": "secret",
                "option_value": "admin",
            },
        ),
    ],
)
def test_browser_action_rejects_fields_for_a_different_action_type(
    action_type: BrowserActionType,
    extra_fields: dict[str, str],
) -> None:
    with pytest.raises(ValidationError, match="action cannot use"):
        BrowserAction(
            action_type=action_type,
            description="An action with contradictory fields",
            **extra_fields,
        )


def test_check_result_round_trips_without_changing_the_verdict() -> None:
    result = CheckResult(
        result_id=uuid4(),
        scan_id=uuid4(),
        check_id=CheckId.LOGOUT_INVALIDATION,
        outcome=CheckOutcome.INCONCLUSIVE,
        owasp_reference="WSTG-SESS-06",
        analyser_version="1.0.0",
        explanation="The protected resource could not be verified.",
        coverage_limitations=["No account-specific marker was available."],
    )

    restored_result = CheckResult.model_validate_json(result.model_dump_json())

    assert restored_result == result
    assert restored_result.outcome is CheckOutcome.INCONCLUSIVE
