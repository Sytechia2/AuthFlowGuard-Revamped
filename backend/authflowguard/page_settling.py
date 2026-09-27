"""Bounded waits that let JavaScript applications settle between actions.

Server-rendered pages are ready at ``domcontentloaded``. Single-page
applications are not: they fetch data before building their forms, and they
submit forms with background requests that set session state when they
complete. The waits here track only those background requests, so a
server-rendered page pays a fraction of a second, and every wait is bounded
so a busy page costs time but never blocks a scan.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from playwright.async_api import Page, Request, Response

BACKGROUND_REQUEST_TIMEOUT_SECONDS = 5.0
QUIET_WINDOW_SECONDS = 0.1
BACKGROUND_RESOURCE_TYPES = frozenset({"fetch", "xhr"})


@asynccontextmanager
async def background_requests_settled(page: Page) -> AsyncIterator[None]:
    """Wait for background requests started inside the block to finish.

    A client-side login sets its session cookie when its request completes,
    which can be after the click that started it has returned, and a
    client-side page builds its form only after its data requests complete.
    ``networkidle`` does not help after a click: it resolves at once when the
    page was already idle.
    """

    pending: set[Request] = set()
    started_count = 0

    def started(request: Request) -> None:
        nonlocal started_count
        if request.resource_type in BACKGROUND_RESOURCE_TYPES:
            pending.add(request)
            started_count += 1

    def finished(request: Request) -> None:
        pending.discard(request)

    page.on("request", started)
    page.on("requestfinished", finished)
    page.on("requestfailed", finished)
    try:
        yield
        loop = asyncio.get_running_loop()
        deadline = loop.time() + BACKGROUND_REQUEST_TIMEOUT_SECONDS
        while loop.time() < deadline:
            if pending:
                await asyncio.sleep(0.05)
                continue
            # A quiet window lets the page dispatch work queued by the action
            # and run response handlers, which may start follow-up requests.
            seen = started_count
            await asyncio.sleep(QUIET_WINDOW_SECONDS)
            if not pending and started_count == seen:
                break
    finally:
        page.remove_listener("request", started)
        page.remove_listener("requestfinished", finished)
        page.remove_listener("requestfailed", finished)


async def goto_and_settle(page: Page, url: str) -> Response | None:
    """Navigate, then wait for the requests a client-side app makes to render."""

    async with background_requests_settled(page):
        return await page.goto(url, wait_until="load")
