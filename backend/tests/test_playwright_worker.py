"""Browser-level tests for redacted Playwright observations."""

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import uuid4

from authflowguard.models import EvidenceKind, TargetScope
from authflowguard.playwright_worker import PlaywrightWorker

TEST_COOKIE_VALUE = "live-cookie-secret-value"
TEST_STORAGE_VALUE = "live-storage-secret-value"
TEST_SESSION_STORAGE_VALUE = "live-session-storage-secret-value"
TEST_INPUT_VALUE = "prefilled-account-secret"


class ControlledPageHandler(BaseHTTPRequestHandler):
    outside_pixel_url = "http://outside.invalid/pixel?private=value"

    def do_GET(self) -> None:
        page = f"""<!doctype html>
        <html>
            <head><title>Controlled Login</title></head>
            <body>
                <form>
                    <input id="username" name="username" autocomplete="username"
                           value="{TEST_INPUT_VALUE}">
                    <input id="password" name="password" type="password"
                           autocomplete="current-password">
                    <button id="login-button" type="submit">Log in</button>
                </form>
                <img src="{self.outside_pixel_url}" alt="">
                <script>
                    localStorage.setItem("access_state", "{TEST_STORAGE_VALUE}");
                    sessionStorage.setItem(
                        "csrf_state", "{TEST_SESSION_STORAGE_VALUE}"
                    );
                </script>
            </body>
        </html>"""
        encoded_page = page.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded_page)))
        self.send_header("Set-Cookie", f"session_id={TEST_COOKIE_VALUE}; HttpOnly")
        self.end_headers()
        self.wfile.write(encoded_page)

    def log_message(self, format: str, *args: object) -> None:
        return


class OutsidePageHandler(BaseHTTPRequestHandler):
    request_count = 0

    def do_GET(self) -> None:
        type(self).request_count += 1
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def run_server(handler_type: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_type)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join()


def test_worker_records_controls_and_nonsecret_session_references() -> None:
    OutsidePageHandler.request_count = 0

    with run_server(OutsidePageHandler) as outside_origin:
        ControlledPageHandler.outside_pixel_url = (
            f"{outside_origin}/pixel?private=must-not-be-requested"
        )

        with run_server(ControlledPageHandler) as origin:
            scan_id = uuid4()
            target = TargetScope(
                target_url=f"{origin}/login?temporary_code=must-not-be-saved",
                permitted_origins=[origin],
            )

            observation = asyncio.run(PlaywrightWorker().observe(scan_id, target))

    assert OutsidePageHandler.request_count == 0

    page_events = [
        event for event in observation.events if event.kind is EvidenceKind.PAGE_STATE
    ]
    assert len(page_events) == 1
    assert page_events[0].redacted_details["title"] == "Controlled Login"
    controls = page_events[0].redacted_details["controls"]
    assert [control["observed_control_id"] for control in controls] == [
        "control-1",
        "control-2",
        "control-3",
    ]
    assert controls[0]["name"] == "username"
    assert controls[1]["type"] == "password"
    assert all("value" not in control for control in controls)

    storage_types = {
        reference.storage_type for reference in observation.session_references
    }
    assert storage_types == {"cookie", "local_storage", "session_storage"}
    assert all(
        len(reference.value_fingerprint) == 64
        and set(reference.value_fingerprint) <= set("0123456789abcdef")
        for reference in observation.session_references
    )
    assert len(
        {reference.value_fingerprint for reference in observation.session_references}
    ) == len(observation.session_references)

    assert all(event.scan_id == scan_id for event in observation.events)
    assert all(event.action_id is None for event in observation.events)

    event_ids = {event.event_id for event in observation.events}
    for traffic_reference in observation.traffic:
        assert traffic_reference.request_event_id in event_ids
        assert traffic_reference.response_event_id in event_ids

    storage_event_ids = {
        event.event_id
        for event in observation.events
        if event.kind is EvidenceKind.STORAGE_CHANGE
    }
    assert all(
        reference.observed_event_id in storage_event_ids
        for reference in observation.session_references
    )

    saved_evidence = "".join(event.model_dump_json() for event in observation.events)
    saved_references = "".join(
        reference.model_dump_json() for reference in observation.session_references
    )
    saved_output = saved_evidence + saved_references

    assert "temporary_code" not in saved_output
    assert "must-not-be-saved" not in saved_output
    assert TEST_COOKIE_VALUE not in saved_output
    assert TEST_STORAGE_VALUE not in saved_output
    assert TEST_SESSION_STORAGE_VALUE not in saved_output
    assert TEST_INPUT_VALUE not in saved_output
    assert "must-not-be-requested" not in saved_output
    assert observation.traffic
