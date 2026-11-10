"""FastAPI application factory."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.router import api_router
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.core.logging import configure_logging, get_logger
from app.events.bus import bus

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    bus.bind_loop(asyncio.get_running_loop())
    log.info("contextos.started", extra={"env": get_settings().env})
    yield


def _frontend_dist() -> Path | None:
    settings = get_settings()
    candidate = Path(settings.frontend_dist) if settings.frontend_dist else Path(__file__).resolve().parents[2] / "frontend" / "dist"
    return candidate if (candidate / "index.html").exists() else None


def create_app() -> FastAPI:
    settings = get_settings()
    settings.validate_for_production()
    configure_logging(settings.log_level, settings.log_json)

    app = FastAPI(
        title="ContextOS",
        version="0.1.0",
        description="Security, trust, provenance and observability layer for autonomous AI agents.",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > settings.max_event_bytes * 4:
            return JSONResponse(status_code=413, content={"error": {"code": "payload_too_large", "message": "Request body too large", "details": None}})
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    register_error_handlers(app)
    app.include_router(api_router)

    dist = _frontend_dist() if settings.serve_frontend else None
    if dist is not None:
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> FileResponse:
            if path.startswith("api/"):
                return JSONResponse(status_code=404, content={"error": {"code": "not_found", "message": "Not found", "details": None}})  # type: ignore[return-value]
            target = (dist / path).resolve()
            if path and target.is_file() and dist.resolve() in target.parents:
                return FileResponse(target)
            return FileResponse(dist / "index.html")

    return app


app = create_app()
