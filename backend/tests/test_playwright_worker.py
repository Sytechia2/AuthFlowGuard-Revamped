"""Browser-level tests for redacted Playwright observations."""

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import uuid4

from authflowguard.models import EvidenceKind, TargetScope
from authflowguard.playwright_worker import PlaywrightWorker


TEST_COOKIE_VALUE = "live-cookie-secret-value"
TEST_STORAGE_VALUE = "live-storage-secret-value"


class ControlledPageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        page = f"""<!doctype html>
        <html>
            <head><title>Controlled Login</title></head>
            <body>
                <form>
                    <input id="username" name="username" autocomplete="username">
                    <input id="password" name="password" type="password"
                           autocomplete="current-password">
                    <button id="login-button" type="submit">Log in</button>
                </form>
                <img src="http://outside.invalid/pixel?private=value" alt="">
                <script>
                    localStorage.setItem("access_state", "{TEST_STORAGE_VALUE}");
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

    def log_message(self, format: str, *args) -> None:
        return


@contextmanager
def run_controlled_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ControlledPageHandler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join()


def test_worker_records_controls_and_nonsecret_session_references() -> None:
    with run_controlled_server() as origin:
        target = TargetScope(
            target_url=f"{origin}/login?temporary_code=must-not-be-saved",
            permitted_origins=[origin],
        )

        observation = asyncio.run(PlaywrightWorker().observe(uuid4(), target))

    page_events = [
        event for event in observation.events if event.kind is EvidenceKind.PAGE_STATE
    ]
    assert len(page_events) == 1
    assert page_events[0].redacted_details["title"] == "Controlled Login"
    assert len(page_events[0].redacted_details["controls"]) == 3

    storage_types = {
        reference.storage_type for reference in observation.session_references
    }
    assert storage_types == {"cookie", "local_storage"}

    saved_evidence = "".join(
        event.model_dump_json() for event in observation.events
    )
    saved_references = "".join(
        reference.model_dump_json() for reference in observation.session_references
    )
    saved_output = saved_evidence + saved_references

    assert "temporary_code" not in saved_output
    assert "must-not-be-saved" not in saved_output
    assert TEST_COOKIE_VALUE not in saved_output
    assert TEST_STORAGE_VALUE not in saved_output
    assert "outside.invalid" not in saved_output
    assert observation.traffic
