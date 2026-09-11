"""FastAPI entry point for the local AuthFlowGuard backend."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"


def create_app(frontend_dist: Path | None = None) -> FastAPI:
    application = FastAPI(
        title="AuthFlowGuard AI",
        version="0.1.0",
    )

    @application.get("/api/health", tags=["system"])
    async def read_health() -> dict[str, str]:
        return {"status": "ok"}

    static_directory = frontend_dist or DEFAULT_FRONTEND_DIST
    if static_directory.is_dir():
        application.mount(
            "/",
            StaticFiles(directory=static_directory, html=True),
            name="frontend",
        )

    return application


app = create_app()
