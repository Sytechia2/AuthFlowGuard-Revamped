"""FastAPI entry point for the local AuthFlowGuard backend."""

from fastapi import FastAPI


def create_app() -> FastAPI:
    application = FastAPI(
        title="AuthFlowGuard AI",
        version="0.1.0",
    )

    @application.get("/api/health", tags=["system"])
    async def read_health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
