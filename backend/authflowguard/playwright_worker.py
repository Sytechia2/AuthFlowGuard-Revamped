"""Scope-restricted Playwright observation and evidence capture."""

from dataclasses import dataclass
from hashlib import sha256
from typing import TypedDict
from uuid import UUID, uuid4

from playwright.async_api import (
    BrowserContext,
    Page,
    Request,
    Response,
    Route,
    async_playwright,
)

from authflowguard.models import (
    EvidenceEvent,
    EvidenceKind,
    SessionReference,
    TargetScope,
    TrafficReference,
)
from authflowguard.scope import url_is_in_scope, url_without_query_or_fragment


@dataclass(frozen=True)
class PlaywrightObservation:
    """The persisted, nonsecret output of one browser observation."""

    events: list[EvidenceEvent]
    traffic: list[TrafficReference]
    session_references: list[SessionReference]


class SafeControlDescription(TypedDict):
    """Control metadata safe to persist or include in a model request."""

    observed_control_id: str
    tag: str
    id: str | None
    name: str | None
    type: str | None
    placeholder: str | None
    autocomplete: str | None
    aria_label: str | None
    text: str | None
    role: str | None
    value_present: bool | None
    visible: bool


class PlaywrightWorker:
    """Open one page and convert browser observations into shared evidence."""

    async def observe(
        self, scan_id: UUID, target: TargetScope
    ) -> PlaywrightObservation:
        target_url = str(target.target_url)
        if not url_is_in_scope(target_url, target):
            raise ValueError("The target URL is not included in permitted_origins")

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context()

            try:
                return await self._observe_in_context(scan_id, target, context)
            finally:
                await context.close()
                await browser.close()

    async def _observe_in_context(
        self,
        scan_id: UUID,
        target: TargetScope,
        context: BrowserContext,
    ) -> PlaywrightObservation:
        events: list[EvidenceEvent] = []
        traffic: list[TrafficReference] = []
        request_event_ids: dict[int, UUID] = {}

        async def keep_request_inside_scope(route: Route) -> None:
            if url_is_in_scope(route.request.url, target):
                await route.continue_()
            else:
                await route.abort("blockedbyclient")

        await context.route("**/*", keep_request_inside_scope)
        page = await context.new_page()

        def record_request(request: Request) -> None:
            if not url_is_in_scope(request.url, target):
                return

            event = EvidenceEvent(
                event_id=uuid4(),
                scan_id=scan_id,
                kind=EvidenceKind.REQUEST,
                summary="The browser sent an in-scope request.",
                redacted_details={
                    "url": url_without_query_or_fragment(request.url),
                    "method": request.method,
                    "resource_type": request.resource_type,
                },
            )
            events.append(event)
            request_event_ids[id(request)] = event.event_id

        def record_response(response: Response) -> None:
            if not url_is_in_scope(response.url, target):
                return

            event = EvidenceEvent(
                event_id=uuid4(),
                scan_id=scan_id,
                kind=EvidenceKind.RESPONSE,
                summary="The browser received an in-scope response.",
                redacted_details={
                    "url": url_without_query_or_fragment(response.url),
                    "status": response.status,
                },
            )
            events.append(event)

            request_event_id = request_event_ids.get(id(response.request))
            if request_event_id is not None:
                traffic.append(
                    TrafficReference(
                        request_event_id=request_event_id,
                        response_event_id=event.event_id,
                    )
                )

        page.on("request", record_request)
        page.on("response", record_response)

        await page.goto(str(target.target_url), wait_until="domcontentloaded")
        await page.wait_for_timeout(50)

        page_event = await self.record_page_state(scan_id, page)
        events.append(page_event)

        storage_event, session_references = await self.record_session_state(
            scan_id,
            context,
            page,
        )
        events.append(storage_event)

        return PlaywrightObservation(
            events=events,
            traffic=traffic,
            session_references=session_references,
        )

    async def record_page_state(
        self,
        scan_id: UUID,
        page: Page,
    ) -> EvidenceEvent:
        controls = await self.read_controls(page)

        return EvidenceEvent(
            event_id=uuid4(),
            scan_id=scan_id,
            kind=EvidenceKind.PAGE_STATE,
            summary="The browser recorded the visible page controls.",
            redacted_details={
                "url": url_without_query_or_fragment(page.url),
                "title": await page.title(),
                "controls": controls,
            },
        )

    async def read_controls(self, page: Page) -> list[SafeControlDescription]:
        """Describe controls without reading their live values."""
        locator = page.locator("input, button, select, textarea, a[href]")
        controls: list[SafeControlDescription] = []

        for index in range(await locator.count()):
            control = locator.nth(index)
            tag = await control.evaluate("element => element.tagName.toLowerCase()")
            control_type = await control.get_attribute("type")
            value_present: bool | None = None
            if tag in {"input", "textarea"} and control_type not in {
                "button",
                "checkbox",
                "file",
                "radio",
                "reset",
                "submit",
            }:
                value_present = bool(await control.input_value())
            text: str | None = None
            if tag in {"button", "a"} or control_type in {"button", "submit"}:
                try:
                    raw_text = await control.inner_text(timeout=500)
                    text = " ".join(raw_text.split())[:60] if raw_text else None
                except Exception:
                    text = None
            controls.append(
                {
                    "observed_control_id": f"control-{index + 1}",
                    "tag": tag,
                    "id": await control.get_attribute("id"),
                    "name": await control.get_attribute("name"),
                    "type": control_type,
                    "placeholder": await control.get_attribute("placeholder"),
                    "autocomplete": await control.get_attribute("autocomplete"),
                    "aria_label": await control.get_attribute("aria-label"),
                    "text": text,
                    "role": await control.get_attribute("role"),
                    "value_present": value_present,
                    "visible": await control.is_visible(),
                }
            )

        return controls

    async def record_session_state(
        self,
        scan_id: UUID,
        context: BrowserContext,
        page: Page,
    ) -> tuple[EvidenceEvent, list[SessionReference]]:
        """Fingerprint session state without returning any live values."""
        storage_event = EvidenceEvent(
            event_id=uuid4(),
            scan_id=scan_id,
            kind=EvidenceKind.STORAGE_CHANGE,
            summary="The browser recorded nonsecret session-state references.",
            redacted_details={},
        )

        session_references: list[SessionReference] = []
        cookies = await context.cookies()
        for cookie in cookies:
            session_references.append(
                self._make_session_reference(
                    scan_id=scan_id,
                    storage_type="cookie",
                    name=cookie["name"],
                    live_value=cookie["value"],
                    observed_event_id=storage_event.event_id,
                )
            )

        browser_storage = await page.evaluate(
            """
            () => ({
                localStorage: Object.entries(localStorage),
                sessionStorage: Object.entries(sessionStorage),
            })
            """
        )
        self._add_browser_storage_references(
            session_references,
            scan_id,
            storage_event.event_id,
            browser_storage,
        )

        storage_event.redacted_details = {
            "reference_count": len(session_references),
            "storage_types": sorted(
                {reference.storage_type for reference in session_references}
            ),
        }
        return storage_event, session_references

    def _add_browser_storage_references(
        self,
        session_references: list[SessionReference],
        scan_id: UUID,
        observed_event_id: UUID,
        browser_storage: dict[str, list[list[str]]],
    ) -> None:
        storage_names = {
            "localStorage": "local_storage",
            "sessionStorage": "session_storage",
        }

        for playwright_name, saved_name in storage_names.items():
            for name, live_value in browser_storage.get(playwright_name, []):
                session_references.append(
                    self._make_session_reference(
                        scan_id=scan_id,
                        storage_type=saved_name,
                        name=name,
                        live_value=live_value,
                        observed_event_id=observed_event_id,
                    )
                )

    def _make_session_reference(
        self,
        scan_id: UUID,
        storage_type: str,
        name: str,
        live_value: str,
        observed_event_id: UUID,
    ) -> SessionReference:
        fingerprint_input = f"{scan_id}:{storage_type}:{name}:{live_value}"
        fingerprint = sha256(fingerprint_input.encode("utf-8")).hexdigest()

        return SessionReference(
            storage_type=storage_type,
            name=name,
            value_fingerprint=fingerprint,
            observed_event_id=observed_event_id,
        )
