"""FastAPI entry point for the local AuthFlowGuard backend."""

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from authflowguard.automatic_actions import ActionSelectionClient
from authflowguard.config import get_capabilities
from authflowguard.models import ScanRequest
from authflowguard.scan_manager import (
    GuidanceObservationError,
    GuidanceObservationRequest,
    GuidanceSubmission,
    ScanExecutionInput,
    ScanManager,
    ScanManagerError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
DEFAULT_DATA_ROOT = PROJECT_ROOT / ".authflowguard-data"


def create_app(
    frontend_dist: Path | None = None,
    data_root: Path | None = None,
    action_client_factory: Callable[[], ActionSelectionClient] | None = None,
    worker_backend: Literal["process", "thread", "inline"] = "process",
) -> FastAPI:
    if action_client_factory is not None and worker_backend == "process":
        worker_backend = "thread"
    scan_manager = ScanManager(
        data_root or DEFAULT_DATA_ROOT,
        action_client_factory=action_client_factory,
        worker_backend=worker_backend,
    )

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            scan_manager.shutdown()

    application = FastAPI(
        title="AuthFlowGuard AI",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.scan_manager = scan_manager

    @application.exception_handler(RequestValidationError)
    async def safe_validation_error(
        _request: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        """Describe invalid fields without echoing submitted credential values."""

        detail = [
            {
                "type": str(item.get("type", "validation_error")),
                # Deeper locations can contain user-controlled mapping keys.
                "loc": [str(next(iter(item.get("loc", ())), "request"))],
                "msg": "Request validation failed",
            }
            for item in error.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={"code": "invalid_request", "detail": detail},
        )

    @application.exception_handler(ScanManagerError)
    async def scan_manager_error(
        _request: Request,
        error: ScanManagerError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={"code": error.code, "detail": error.detail},
        )

    @application.get("/api/health", tags=["system"])
    async def read_health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/api/capabilities", tags=["system"])
    async def read_capabilities() -> dict[str, object]:
        return get_capabilities()

    @application.post("/api/scans", status_code=201)
    async def create_scan(request: ScanRequest) -> dict[str, object]:
        record = scan_manager.create_scan(request)
        return scan_manager.snapshot(record)

    @application.get("/api/scans")
    async def list_scans() -> list[dict[str, object]]:
        return [scan_manager.snapshot(record) for record in scan_manager.list_scans()]

    @application.post("/api/scans/{scan_id}/start")
    async def start_scan(
        scan_id: UUID,
        execution: ScanExecutionInput,
    ) -> dict[str, object]:
        record = scan_manager.start_scan(scan_id, execution)
        return scan_manager.snapshot(record)

    @application.get("/api/scans/{scan_id}")
    async def read_scan(scan_id: UUID) -> dict[str, object]:
        record = scan_manager.get_scan(scan_id)
        return scan_manager.snapshot(record)

    @application.get("/api/scans/{scan_id}/events")
    async def read_scan_events(scan_id: UUID) -> list[dict[str, object]]:
        record = scan_manager.get_scan(scan_id)
        return [event.model_dump(mode="json") for event in record.events]

    @application.post("/api/scans/{scan_id}/guidance/observe")
    async def observe_guidance(
        scan_id: UUID,
        request: GuidanceObservationRequest | None = None,
    ) -> dict[str, object]:
        try:
            return await scan_manager.observe_guidance(
                scan_id,
                request.url if request else None,
            )
        except ScanManagerError:
            raise
        except (ValueError, RuntimeError):
            raise GuidanceObservationError(
                "The target page could not be observed safely"
            ) from None

    @application.post("/api/scans/{scan_id}/guidance")
    async def submit_guidance(
        scan_id: UUID,
        guidance: GuidanceSubmission,
    ) -> dict[str, object]:
        record = scan_manager.submit_guidance(scan_id, guidance)
        return scan_manager.snapshot(record)

    @application.post("/api/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: UUID) -> dict[str, object]:
        record = scan_manager.cancel_scan(scan_id)
        return scan_manager.snapshot(record)

    @application.post("/api/scans/{scan_id}/reanalyse")
    async def reanalyse_scan(scan_id: UUID) -> dict[str, object]:
        results = scan_manager.reanalyse(scan_id)
        return {
            "scan_id": str(scan_id),
            "results": [result.model_dump(mode="json") for result in results],
        }

    @application.get("/api/scans/{scan_id}/report/{extension}")
    async def download_report(scan_id: UUID, extension: str) -> FileResponse:
        path = scan_manager.report_path(scan_id, extension)
        media_type = "application/json" if extension == "json" else "text/html"
        return FileResponse(path, media_type=media_type)

    static_directory = frontend_dist or DEFAULT_FRONTEND_DIST
    if static_directory.is_dir():
        application.mount(
            "/",
            StaticFiles(directory=static_directory, html=True),
            name="frontend",
        )

    return application


app = create_app()
