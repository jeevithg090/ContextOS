"""FastAPI application factory.

Startup refuses to serve an un-migrated database: the lifespan checks that the schema is at the latest
Alembic revision (``app.database.migrations.ensure_schema_ready``) and fails with an error naming
``contextos-server init-db`` otherwise. Outside production a complete schema created by ``create_all``
(test fixtures) is accepted.
"""

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
from app.database.migrations import SchemaNotReadyError, ensure_schema_ready
from app.database.session import get_engine
from app.events.bus import bus

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    try:
        status = ensure_schema_ready(get_engine(), allow_unversioned=settings.env != "production")
    except SchemaNotReadyError as exc:
        log.error("contextos.schema_not_ready", extra={"state": exc.status.state if exc.status else None,
                                                       "reason": str(exc)})
        raise
    bus.bind_loop(asyncio.get_running_loop())
    log.info("contextos.started", extra={"env": settings.env, "schema": status.state,
                                         "revision": ",".join(status.current) or None})
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
