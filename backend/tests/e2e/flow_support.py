"""HTTP helpers for the in-process end-to-end tests: ``Flow`` speaks as the integration (API key)
and as the signed-in owner (session) through the public API only."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi.testclient import TestClient

from tests.conftest import OrgCtx

API = "/api/v1"
AGENT = "payments-agent"


def ok(response, status: int = 200) -> Any:
    assert response.status_code == status, (
        f"{response.request.method} {response.request.url}: {response.text}"
    )
    return response.json()


def event(event_type: str, session: str, **fields: Any) -> dict[str, Any]:
    return {
        "event_id": f"evt-{uuid.uuid4().hex}",
        "event_type": event_type,
        "timestamp": "2026-11-11T10:00:00+00:00",
        "agent": {"name": AGENT, "framework": "claude_code"},
        "session_id": session,
        "integration": "claude_code",
        **fields,
    }


def tool(session: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return event(
        "tool.requested",
        session,
        tool={"name": name, "provider": "claude_code"},
        arguments=arguments,
        correlation_id=f"tu-{uuid.uuid4().hex[:12]}",
    )


class Flow:
    """Thin HTTP helpers: ``key`` = the integration's API key, ``user`` = the signed-in owner."""

    def __init__(self, client: TestClient, org: OrgCtx) -> None:
        self.c, self.key, self.user = client, org.api_headers, org.user_headers

    def events(self, *events: dict[str, Any]) -> list[dict[str, Any]]:
        results = ok(self.c.post(f"{API}/events", json={"events": list(events)}, headers=self.key))["results"]
        assert [r["status"] for r in results] == ["accepted"] * len(events), results
        return results

    def decide(self, envelope: dict[str, Any]) -> dict[str, Any]:
        return ok(self.c.post(f"{API}/decide", json=envelope, headers=self.key))

    def get(self, path: str, *, as_key: bool = False, **params: Any) -> Any:
        return ok(self.c.get(f"{API}{path}", params=params, headers=self.key if as_key else self.user))

    def post(self, path: str, body: dict[str, Any], status: int = 200) -> Any:
        return ok(self.c.post(f"{API}{path}", json=body, headers=self.user), status)

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        return ok(self.c.patch(f"{API}{path}", json=body, headers=self.user))
