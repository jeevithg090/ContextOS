"""In-process fake ContextOS server for SDK tests (httpx.MockTransport; no network)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from contextos.client import ContextOSClient
from contextos.models import AgentRef
from contextos.spool import Spool

API_KEY = "ctxk_test_0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
BASE_URL = "http://contextos.test"

Responder = Callable[[httpx.Request], httpx.Response]


def decision_body(decision: str = "ALLOW", **extra: Any) -> dict[str, Any]:
    body = {
        "decision": decision,
        "enforcement": "enforced",
        "reason": extra.pop("reason", f"Policy decided {decision}"),
        "policy_decision_id": "pd_1",
        "tool_invocation_id": "ti_1",
    }
    body.update(extra)
    return body


class FakeServer:
    """Routes ``(method, path)`` to JSON responses or callables and records every request."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.refused: list[httpx.Request] = []  # attempted while ``down``
        self.routes: dict[tuple[str, str], Responder] = {}
        self.down = False  # True → every request fails with a connection error
        self.route("GET", "/api/v1/health", {"status": "ok"})
        self.route("POST", "/api/v1/events", handler=self._accept_events)

    def route(
        self, method: str, path: str, body: Any = None, *, status: int = 200, handler: Responder | None = None
    ) -> None:
        if handler is None:

            def handler(_: httpx.Request, body: Any = body, status: int = status) -> httpx.Response:
                return httpx.Response(status, json=body)

        self.routes[(method, path)] = handler

    def sequence(self, method: str, path: str, responses: list[tuple[int, Any]]) -> None:
        """Answer successive calls with successive responses (the last one repeats)."""
        queue = list(responses)

        def handler(_: httpx.Request) -> httpx.Response:
            status, body = queue.pop(0) if len(queue) > 1 else queue[0]
            if isinstance(body, Exception):
                raise body
            return httpx.Response(status, json=body)

        self.routes[(method, path)] = handler

    @staticmethod
    def _accept_events(request: httpx.Request) -> httpx.Response:
        events = json.loads(request.content)["events"]
        results = [
            {"event_id": e["event_id"], "status": "accepted", "ingested_event_id": f"ie_{i}"}
            for i, e in enumerate(events)
        ]
        return httpx.Response(200, json={"results": results})

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            self.refused.append(request)
            raise httpx.ConnectError("connection refused", request=request)
        self.requests.append(request)
        responder = self.routes.get((request.method, request.url.path))
        if responder is None:
            return httpx.Response(
                404, json={"error": {"code": "not_found", "message": "Not found", "details": None}}
            )
        return responder(request)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def client(self, tmp_path: Path, **overrides: Any) -> ContextOSClient:
        overrides.setdefault("agent", AgentRef(name="test-agent", framework="python_sdk"))
        overrides.setdefault("spool", Spool(tmp_path / "spool" / "test-agent.jsonl"))
        overrides.setdefault("sleep", lambda _s: None)
        return ContextOSClient(BASE_URL, API_KEY, transport=self.transport(), **overrides)

    # -- inspection -----------------------------------------------------------------------------

    def calls(self, method: str, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and r.url.path == path]

    def bodies(self, method: str, path: str) -> list[Any]:
        return [json.loads(r.content) for r in self.calls(method, path)]

    def events(self) -> list[dict[str, Any]]:
        """Every event POSTed to /events, flattened across batches."""
        return [e for body in self.bodies("POST", "/api/v1/events") for e in body["events"]]

    def events_of(self, event_type: str) -> list[dict[str, Any]]:
        return [e for e in self.events() if e["event_type"] == event_type]
