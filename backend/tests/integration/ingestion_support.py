"""Builders and HTTP helpers shared by the ingestion / decision / event-log tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

# A syntactically valid GitHub token used as "the secret" in exfiltration scenarios. It must never
# appear in any database column after ingestion.
GITHUB_TOKEN = "ghp_" + "Zq8RtY2uV4wX6yA1bC3dE5fG7hJ9kL0mN2pQ"


def event(
    event_type: str,
    *,
    agent: str = "coder",
    session: str = "sess-1",
    integration: str = "claude_code",
    **fields: Any,
) -> dict[str, Any]:
    return {
        "event_id": f"evt-{uuid.uuid4().hex}",
        "event_type": event_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "agent": {"name": agent, "framework": "claude_code", "version": "1.0"},
        "session_id": session,
        "integration": integration,
        **fields,
    }


def tool_requested(name: str, arguments: dict[str, Any], *, correlation_id: str | None = None, **kw: Any) -> dict[str, Any]:
    return event("tool.requested", tool={"name": name, "provider": "claude_code"}, arguments=arguments,
                 correlation_id=correlation_id or f"tu-{uuid.uuid4().hex[:12]}", **kw)


def tool_completed(name: str, arguments: dict[str, Any], result: Any, *, correlation_id: str, **kw: Any) -> dict[str, Any]:
    return event("tool.completed", tool={"name": name, "provider": "claude_code"}, arguments=arguments,
                 result=result, correlation_id=correlation_id, **kw)


def post_events(client: TestClient, headers: dict[str, str], *events: dict[str, Any]) -> list[dict[str, Any]]:
    response = client.post("/api/v1/events", json={"events": list(events)}, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["results"]


def decide(client: TestClient, headers: dict[str, str], envelope: dict[str, Any], *, expect: int = 200) -> dict[str, Any]:
    response = client.post("/api/v1/decide", json=envelope, headers=headers)
    assert response.status_code == expect, response.text
    return response.json()


def run_tool(client: TestClient, headers: dict[str, str], name: str, arguments: dict[str, Any], result: Any,
             **kw: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """PreToolUse decision + PostToolUse result, as the Claude Code hooks send them."""
    request = tool_requested(name, arguments, **kw)
    decision = decide(client, headers, request)
    done = post_events(client, headers, tool_completed(name, arguments, result,
                                                       correlation_id=request["correlation_id"], **kw))
    return decision, done
