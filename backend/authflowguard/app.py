"""FastAPI entry point for the local AuthFlowGuard backend."""

from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from authflowguard.models import ScanRequest
from authflowguard.scan_manager import (
    GuidanceObservationRequest,
    GuidanceSubmission,
    ScanExecutionInput,
    ScanManager,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
DEFAULT_DATA_ROOT = PROJECT_ROOT / ".authflowguard-data"


def create_app(
    frontend_dist: Path | None = None,
    data_root: Path | None = None,
) -> FastAPI:
    application = FastAPI(
        title="AuthFlowGuard AI",
        version="0.1.0",
    )
    scan_manager = ScanManager(data_root or DEFAULT_DATA_ROOT)
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
        return JSONResponse(status_code=422, content={"detail": detail})

    @application.get("/api/health", tags=["system"])
    async def read_health() -> dict[str, str]:
        return {"status": "ok"}

    @application.post("/api/scans", status_code=201)
    async def create_scan(request: ScanRequest) -> dict[str, str]:
        record = scan_manager.create_scan(request)
        return {
            "scan_id": str(record.scan_id),
            "state": record.state.value,
        }

    @application.get("/api/scans")
    async def list_scans() -> list[dict[str, object]]:
        return [scan_manager.snapshot(record) for record in scan_manager.list_scans()]

    @application.post("/api/scans/{scan_id}/start")
    async def start_scan(
        scan_id: UUID,
        execution: ScanExecutionInput,
    ) -> dict[str, object]:
        try:
            record = scan_manager.start_scan(scan_id, execution)
        except (KeyError, ValueError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return scan_manager.snapshot(record)

    @application.get("/api/scans/{scan_id}")
    async def read_scan(scan_id: UUID) -> dict[str, object]:
        try:
            record = scan_manager.get_scan(scan_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return scan_manager.snapshot(record)

    @application.get("/api/scans/{scan_id}/events")
    async def read_scan_events(scan_id: UUID) -> list[dict[str, object]]:
        try:
            record = scan_manager.get_scan(scan_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
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
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except (ValueError, RuntimeError) as error:
            detail = str(error) or f"{type(error).__name__}: browser observation failed"
            raise HTTPException(status_code=409, detail=detail) from error

    @application.post("/api/scans/{scan_id}/guidance")
    async def submit_guidance(
        scan_id: UUID,
        guidance: GuidanceSubmission,
    ) -> dict[str, object]:
        try:
            record = scan_manager.submit_guidance(scan_id, guidance)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return scan_manager.snapshot(record)

    @application.post("/api/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: UUID) -> dict[str, object]:
        try:
            record = scan_manager.cancel_scan(scan_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return scan_manager.snapshot(record)

    @application.post("/api/scans/{scan_id}/reanalyse")
    async def reanalyse_scan(scan_id: UUID) -> dict[str, object]:
        try:
            results = scan_manager.reanalyse(scan_id)
        except (KeyError, ValueError, FileNotFoundError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return {
            "scan_id": str(scan_id),
            "results": [result.model_dump(mode="json") for result in results],
        }

    @application.get("/api/scans/{scan_id}/report/{extension}")
    async def download_report(scan_id: UUID, extension: str) -> FileResponse:
        try:
            path = scan_manager.report_path(scan_id, extension)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except (ValueError, FileNotFoundError) as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
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
