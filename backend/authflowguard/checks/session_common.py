"""Shared browser and redaction helpers for session-management checks."""

import hashlib
import json
from collections.abc import Callable
from typing import Any, cast
from uuid import UUID, uuid4

from playwright.async_api import Browser, BrowserContext, Page

from authflowguard.action_executor import BrowserActionExecutor, install_scope_guard
from authflowguard.control_safety import flow_step
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    CheckId,
    EvidenceEvent,
    EvidenceKind,
    TargetScope,
)
from authflowguard.page_settling import goto_and_settle
from authflowguard.scope import url_is_in_scope
from authflowguard.secrets import RuntimeSecrets


async def new_scoped_context(browser: Browser, target: TargetScope) -> BrowserContext:
    """Open a context that aborts requests outside permitted_origins.

    The checks open some pages directly rather than through the executor, so
    each context gets the executor's scope guard before any page loads.
    """

    context = await browser.new_context(service_workers="block")
    await install_scope_guard(context, target)
    return context


def login_steps_for(profile: AuthProfile) -> list[BrowserAction]:
    if profile.features.get(AuthFeature.LOGIN) != "verified":
        raise ValueError("The auth profile has no verified login feature")
    steps = profile.authentication_steps.get(AuthFeature.LOGIN, [])
    if not steps:
        raise ValueError("The auth profile has no saved login flow")
    return steps


def adapt_login_steps(
    steps: list[BrowserAction], username_reference: str, password_reference: str
) -> list[BrowserAction]:
    fill_index = 0
    adapted: list[BrowserAction] = []
    for step in steps:
        if step.action_type is BrowserActionType.FILL:
            val_ref = (step.value_reference or "").lower()
            if "user" in val_ref or "login" in val_ref or "email" in val_ref:
                reference = username_reference
            elif "pass" in val_ref:
                reference = password_reference
            else:
                reference = (
                    username_reference if fill_index == 0 else password_reference
                )
            adapted.append(step.model_copy(update={"value_reference": reference}))
            fill_index += 1
        else:
            adapted.append(step)
    if fill_index < 2:
        raise ValueError("The saved login flow needs username and password fills")
    return adapted


async def execute_login_steps(
    *,
    page: Page,
    profile: AuthProfile,
    scan_id: UUID,
    steps: list[BrowserAction],
    secrets: RuntimeSecrets,
    password_reference: str,
    events: list[EvidenceEvent],
    check_id: CheckId,
    cancel_requested: Callable[[], bool],
) -> None:
    executor = BrowserActionExecutor(
        page,
        profile.target,
        secrets,
        scan_id,
        password_references=frozenset({password_reference}),
    )
    for step_number, step in enumerate(steps, start=1):
        if cancel_requested():
            raise RuntimeError("Session check execution cancelled")
        with flow_step(step_number):
            result = await executor.execute(
                step.model_copy(update={"action_id": uuid4()})
            )
        for event in result.events:
            events.append(event.model_copy(update={"check_id": check_id}))


def cookie_snapshot(cookies: list[Any]) -> dict[str, Any]:
    entries = [
        {
            "name": str(cookie.get("name", "")),
            "domain": str(cookie.get("domain", "")),
            "path": str(cookie.get("path", "")),
            "value_fingerprint": hashlib.sha256(
                str(cookie.get("value", "")).encode("utf-8")
            ).hexdigest(),
        }
        for cookie in cookies
    ]
    entries.sort(key=lambda item: (item["name"], item["domain"], item["path"]))
    return {
        "count": len(entries),
        "names": [entry["name"] for entry in entries],
        "fingerprint": hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


async def protected_state(
    page: Page, resource: str, marker_selector: str, target: TargetScope
) -> dict[str, Any]:
    response = await goto_and_settle(page, resource)
    # The scope guard does not see a redirect's later hops, so a resource
    # that redirected outside scope is never read or recorded.
    if not url_is_in_scope(page.url, target):
        raise ValueError("The protected resource led outside permitted_origins")
    status = response.status if response is not None else None
    marker_present = await page.locator(marker_selector).count() > 0
    return {
        "status": status,
        "marker_present": marker_present,
        "url": page.url.split("?", 1)[0].split("#", 1)[0],
    }


def check_event(
    scan_id: UUID, check_id: CheckId, kind: EvidenceKind, summary: str, **details: Any
) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=uuid4(),
        scan_id=scan_id,
        check_id=check_id,
        kind=kind,
        summary=summary,
        redacted_details=details,
    )


def replay_server_error(
    authenticated: dict[str, Any], replay: dict[str, Any], anonymous: dict[str, Any]
) -> bool:
    """Whether a server error prevents a trustworthy replay verdict.

    A 5xx normally means the procedure failed. Some applications, however,
    answer every signed-out request to a protected page with a 5xx. When the
    replay receives exactly the anonymous control's status, that status is
    how the application rejects signed-out visitors, not a failure. When the
    replay shows the account marker, an anonymous 5xx without the marker still
    proves the marker is not public.
    """

    authenticated_status = cast(int, authenticated["status"])
    replay_status = cast(int, replay["status"])
    anonymous_status = cast(int, anonymous["status"])
    if authenticated_status >= 500:
        return True
    if replay_status >= 500:
        return replay_status != anonymous_status
    if anonymous_status >= 500:
        replay_authenticated = replay_status == 200 and bool(
            replay.get("marker_present")
        )
        return not replay_authenticated or bool(anonymous.get("marker_present"))
    return False


def replay_rejected(replay: dict[str, Any], anonymous: dict[str, Any]) -> bool:
    """Whether the replay was refused like a signed-out visitor."""

    if anonymous.get("marker_present"):
        return False
    replay_status = cast(int, replay["status"])
    if replay_status in {401, 403}:
        return True
    return (
        replay_status >= 500
        and replay_status == anonymous["status"]
        and not replay.get("marker_present")
    )
