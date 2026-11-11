"""Credentials pasted into names and identifiers never reach the database, and matching still works.

Content, arguments and results are covered by ``test_ingestion_redaction.py``. This file covers the
identifiers an event carries (agent, tool, session, event and correlation ids, integration name) and
the names people type (organisation, member, API key, registered agent and its declared tools).
Canaries are built at runtime from obviously fake parts.
"""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.base import Base
from app.events.envelope import EventEnvelope
from app.models import AgentSession, ToolInvocation
from app.services.ingestion_identity import sanitize_identifiers
from tests.integration.ingestion_support import event, post_events

API = "/api/v1"


def _canary(tag: str) -> str:
    return "ghp_" + "Zq8RtY2uV4wX6yA1bC3dE5fG7hJ9k" + tag[:7].ljust(7, "Q")


def _leaks(engine, canaries: dict[str, str]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    with engine.connect() as conn:
        for table in Base.metadata.sorted_tables:
            for row in conn.execute(table.select()):
                blob = json.dumps([str(value) for value in row])
                for tag, value in canaries.items():
                    if value in blob:
                        found.setdefault(tag, set()).add(table.name)
    return found


def test_event_identifiers_are_redacted_and_still_match(client, seeded_org, db: Session, engine):
    c = {t: _canary(t) for t in ("agent", "framewk", "version", "tool", "session", "eventid", "corr", "integr",
                                 "child", "childs", "fromag")}
    base = {"agent": {"name": c["agent"], "framework": c["framewk"], "version": c["version"]},
            "session_id": c["session"], "integration": c["integr"]}
    request = {**event("tool.requested", tool={"name": c["tool"], "provider": "custom"}, arguments={"q": 1},
                       correlation_id=c["corr"]), **base, "event_id": c["eventid"]}
    events = [
        {**event("session.started"), **base},
        request,
        {**event("tool.completed", tool={"name": c["tool"], "provider": "custom"}, arguments={"q": 1},
                 result="done", correlation_id=c["corr"]), **base},
        {**event("agent.delegated", delegation={"child_agent": {"name": c["child"]}, "child_session_id": c["childs"]}),
         **base},
        {**event("agent.message", message={"from_agent": c["fromag"], "content": "hi"}), **base},
    ]
    results = post_events(client, seeded_org.api_headers, *events)
    assert [r["status"] for r in results] == ["accepted"] * 5, results
    # Idempotency still works on the redacted event id.
    assert post_events(client, seeded_org.api_headers, request)[0]["status"] == "duplicate"

    db.rollback()
    assert _leaks(engine, c) == {}
    sessions = list(db.scalars(select(AgentSession).where(AgentSession.organization_id == seeded_org.org_id)))
    assert len(sessions) == 2  # every event of the parent landed in ONE session (plus the delegated child)
    parent = next(s for s in sessions if s.parent_session_id is None)
    assert parent.external_session_id.startswith("[REDACTED:github_token:")
    calls = list(db.scalars(select(ToolInvocation).where(ToolInvocation.organization_id == seeded_org.org_id)))
    assert len(calls) == 1 and calls[0].status == "completed"  # the result paired with its request


def test_identifier_sanitising_is_deterministic_and_leaves_clean_ids_alone():
    clean = EventEnvelope.model_validate(event("session.started", session="0b6c2f4e-9a1d-4c3e-8f7a-2d5b6c7e8f90"))
    assert sanitize_identifiers(clean) is clean
    dirty = EventEnvelope.model_validate({**event("session.started"), "session_id": _canary("same")})
    first, second = sanitize_identifiers(dirty), sanitize_identifiers(dirty)
    assert first.session_id == second.session_id != dirty.session_id
    assert _canary("same") not in first.model_dump_json()


def test_typed_names_are_redacted(client, org, db: Session, engine):
    c = {t: _canary(t) for t in ("orgname", "member", "keyname", "agent", "tool", "perm")}
    h = org.user_headers
    assert client.patch(f"{API}/org/settings", headers=h, json={"name": f"Acme {c['orgname']}"}).status_code == 200
    assert client.post(f"{API}/org/members", headers=h, json={
        "email": "member@example.test", "name": c["member"], "role": "viewer",
        "password": "a-long-enough-password"}).status_code == 201
    assert client.post(f"{API}/org/api-keys", headers=h, json={"name": c["keyname"], "scopes": ["read"]}).status_code == 201
    registered = client.post(f"{API}/agents", headers=h, json={
        "name": c["agent"], "declared_capabilities": {"tools": [{"name": c["tool"]}], "permissions": [c["perm"]]}})
    assert registered.status_code == 201, registered.text
    assert c["agent"] not in registered.text

    db.rollback()
    assert _leaks(engine, c) == {}
    # A registered (redacted) name still matches the name an integration reports.
    post_events(client, org.api_headers, event("session.started", agent=c["agent"]))
    agents = client.get(f"{API}/agents", headers=h).json()
    assert agents["total"] == 1 and agents["items"][0]["session_count"] == 1
