"""CHK-003: reset-request account enumeration (WSTG-IDNT-04)."""

from collections.abc import Callable
from uuid import UUID

from authflowguard.checks.form_enumeration import (
    FormEnumerationRun,
    analyse_form_enumeration,
    run_form_enumeration_check,
)
from authflowguard.models import (
    AuthProfile,
    CheckId,
    CheckResult,
    SecurityPolicy,
    TestRunEvidence,
)
from authflowguard.secrets import RuntimeSecrets


async def run_reset_request_enumeration_check(
    *,
    profile: AuthProfile,
    scan_id: UUID,
    runtime_secrets: RuntimeSecrets,
    known_identifier_reference: str,
    nonexistent_identifier_reference: str,
    form_url: str | None = None,
    cancel_requested: Callable[[], bool] = lambda: False,
) -> FormEnumerationRun:
    return await run_form_enumeration_check(
        check_id=CheckId.RESET_REQUEST_ENUMERATION,
        profile=profile,
        scan_id=scan_id,
        runtime_secrets=runtime_secrets,
        known_identifier_reference=known_identifier_reference,
        nonexistent_identifier_reference=nonexistent_identifier_reference,
        form_url=form_url,
        cancel_requested=cancel_requested,
    )


def analyse_reset_request_enumeration(
    evidence: TestRunEvidence,
    profile: AuthProfile,
    policy: SecurityPolicy,
) -> CheckResult:
    return analyse_form_enumeration(
        evidence, profile, policy, check_id=CheckId.RESET_REQUEST_ENUMERATION
    )
