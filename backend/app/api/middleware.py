"""HTTP hardening applied to every request: body limits, JSON nesting limit and security headers.

``RequestLimitsMiddleware`` (pure ASGI) reads the request body BEFORE the application sees it:

- more than ``max_body_bytes`` → 413, whether or not the client sent ``Content-Length`` (a chunked
  body is counted as it arrives and never buffered beyond the limit). This runs before
  authentication, so an anonymous client cannot make the server hold an unbounded body.
- a JSON body nested deeper than ``MAX_JSON_DEPTH`` levels → 422. Deeply nested JSON otherwise fails
  late (serialisation depth limits, recursion) as a 500, which an integration would treat as "server
  failing" and a batch sender would retry forever.

The per-event limit (``max_event_bytes``) is enforced separately by the ingestion pipeline.
``security_headers`` sets the response headers; the SPA gets a Content-Security-Policy that allows
only same-origin scripts, API responses a ``default-src 'none'`` policy and ``Cache-Control: no-store``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from app.core.config import Settings

MAX_JSON_DEPTH = 64

# Strings are removed before brackets are counted (escaped quotes handled; linear-time pattern).
_JSON_STRING = re.compile(rb'"[^"\\]*(?:\\.[^"\\]*)*"', re.S)
_BRACKETS = re.compile(rb"[\[\]{}]")

SPA_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
    "font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; "
    "frame-ancestors 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'"
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"


def json_depth_exceeds(body: bytes, limit: int = MAX_JSON_DEPTH) -> bool:
    """True when the JSON text ``body`` nests arrays/objects deeper than ``limit`` (strings ignored)."""
    depth = 0
    for match in _BRACKETS.finditer(_JSON_STRING.sub(b'""', body)):
        if match.group() in (b"[", b"{"):
            depth += 1
            if depth > limit:
                return True
        else:
            depth -= 1
    return False


def _error_body(code: str, message: str, details: Any = None) -> bytes:
    return json.dumps({"error": {"code": code, "message": message, "details": details}}).encode()


async def _respond(
    send: Callable[..., Any], status: int, code: str, message: str, details: Any = None
) -> None:
    body = _error_body(code, message, details)
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class RequestLimitsMiddleware:
    def __init__(
        self, app: Any, *, max_body_bytes: Callable[[], int], max_json_depth: int = MAX_JSON_DEPTH
    ) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.max_json_depth = max_json_depth

    async def __call__(
        self, scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.max_body_bytes()
        too_large = f"Request body too large (limit {limit} bytes)"
        length = dict(scope.get("headers") or []).get(b"content-length", b"")
        if length.isdigit() and int(length) > limit:
            await _respond(send, 413, "payload_too_large", too_large)
            return

        chunks: list[bytes] = []
        size = 0
        first: dict[str, Any] | None = None
        while True:
            message = await receive()
            if message["type"] != "http.request":  # the client went away: hand that to the app
                first = message
                break
            body = message.get("body", b"")
            size += len(body)
            if size > limit:
                await _respond(send, 413, "payload_too_large", too_large)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break
        data = b"".join(chunks)
        if data and data.lstrip()[:1] in (b"{", b"[") and json_depth_exceeds(data, self.max_json_depth):
            await _respond(
                send,
                422,
                "validation_failed",
                f"Request body is nested more than {self.max_json_depth} levels deep",
                {"max_depth": self.max_json_depth},
            )
            return

        replayed = False

        async def replay() -> dict[str, Any]:
            nonlocal replayed
            if not replayed:
                replayed = True
                return first or {"type": "http.request", "body": data, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def apply_security_headers(headers: Any, path: str, settings: Settings) -> None:
    """Set the security headers on a response (``headers``: a mutable Starlette ``MutableHeaders``)."""
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("Referrer-Policy", "no-referrer")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
    headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if settings.cookie_secure:  # served over HTTPS: browsers must not downgrade later visits
        headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if path.startswith("/api/"):
        headers.setdefault("Cache-Control", "no-store")
        if not path.startswith("/api/docs"):  # Swagger UI loads its own scripts; it has no data of ours
            headers.setdefault("Content-Security-Policy", API_CSP)
    else:
        headers.setdefault("Content-Security-Policy", SPA_CSP)
