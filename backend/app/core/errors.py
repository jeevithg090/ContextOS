"""Application error types and the uniform JSON error envelope.

Every error response has the shape ``{"error": {"code": str, "message": str, "details": any}}``.
Raise these from services/routes; never return ad-hoc error dicts.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger

log = get_logger(__name__)


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, details: Any = None, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details
        if code:
            self.code = code


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class AuthenticationError(AppError):
    status_code = 401
    code = "unauthenticated"


class PermissionDeniedError(AppError):
    status_code = 403
    code = "forbidden"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class ValidationFailedError(AppError):
    status_code = 422
    code = "validation_failed"


class PayloadTooLargeError(AppError):
    status_code = 413
    code = "payload_too_large"


_HTTP_CODES = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
    415: "unsupported_media_type",
    429: "rate_limited",
}
_ECHO_LIMIT = 200


def _echo(value: Any) -> Any:
    """A client-derived string that is about to be echoed in an error: redacted and length-capped."""
    if not isinstance(value, str):
        return value
    from app.engines.redaction import redact_text  # local: keeps app.core free of an engines import cycle

    text = redact_text(value).text
    return text if len(text) <= _ECHO_LIMIT else text[: _ECHO_LIMIT - 1] + "…"


def _envelope(code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code, content=_envelope(exc.code, exc.message, exc.details)
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Locations can carry client-chosen keys (an unexpected field name) and messages can quote
        # input: both are redacted before they are echoed. The input value itself is never echoed.
        details = [
            {
                "loc": [_echo(part) for part in err.get("loc", [])],
                "msg": _echo(err.get("msg")),
                "type": err.get("type"),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=422, content=_envelope("validation_failed", "Request validation failed", details)
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Framework errors (unknown route, wrong method, unparsable body) in the same envelope."""
        code = _HTTP_CODES.get(exc.status_code, "http_error")
        message = (
            exc.detail if isinstance(exc.detail, str) and exc.detail else code.replace("_", " ").capitalize()
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(code, message),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled_error", extra={"path": request.url.path})
        return JSONResponse(status_code=500, content=_envelope("internal_error", "Internal server error"))
