"""Shared browser and redaction helpers for session-management checks."""

import hashlib
import json
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

from playwright.async_api import Page

from authflowguard.action_executor import BrowserActionExecutor
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    CheckId,
    EvidenceEvent,
    EvidenceKind,
)
from authflowguard.page_settling import goto_and_settle
from authflowguard.secrets import RuntimeSecrets


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
    events: list[EvidenceEvent],
    check_id: CheckId,
    cancel_requested: Callable[[], bool],
) -> None:
    executor = BrowserActionExecutor(page, profile.target, secrets, scan_id)
    for step in steps:
        if cancel_requested():
            raise RuntimeError("Session check execution cancelled")
        result = await executor.execute(step.model_copy(update={"action_id": uuid4()}))
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
    page: Page, resource: str, marker_selector: str
) -> dict[str, Any]:
    response = await goto_and_settle(page, resource)
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
