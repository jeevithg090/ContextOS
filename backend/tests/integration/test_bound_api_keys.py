"""API keys bound to one agent see only that agent.

Routes filtered per agent (agents, sessions, simulation runs, events, context, approvals) answer 404 for
another agent's record; routes whose answers span every agent (findings, incidents, provenance, trust,
audit, workspace, the live stream, recorded policy decisions, suites, the agent graph) refuse bound
keys with 403. A bound key that re-uses another agent's event id gets neither that event's
references nor its decision.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.core.security import generate_api_key
from app.models import Agent, AgentSession, ApiKey, AuditEvent, SimulationRun
from tests.integration.ingestion_support import event, post_events, tool_requested

API = "/api/v1"

ORG_WIDE_GETS = [
    "/findings",
    "/incidents",
    "/audit",
    "/audit/verify",
    "/trust/summary",
    "/trust/sources",
    "/trust/destinations",
    "/trust/rules",
    "/provenance/graph",
    "/agents/graph",
    "/policies/recent-decisions",
    "/simulations/suites",
    "/workspace/tasks",
    "/workspace/boards",
    "/integrations",
    "/overview",
    "/stream",
]


def _bound(db: Session, org_id: str, agent_id: str, scopes: list[str] | None = None) -> dict[str, str]:
    raw, prefix, key_hash = generate_api_key()
    db.add(
        ApiKey(
            id=new_id("api_key"),
            organization_id=org_id,
            name="bound",
            prefix=prefix,
            key_hash=key_hash,
            scopes=scopes or ["ingest", "decide", "read"],
            agent_id=agent_id,
        )
    )
    db.commit()
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture()
def two_agents(client, seeded_org, db):
    """Agents ``alpha`` and ``beta`` with one session each, and a key bound to ``alpha``."""
    h = seeded_org.api_headers
    post_events(
        client,
        h,
        event("session.started", agent="alpha", session="s-alpha"),
        event("session.started", agent="beta", session="s-beta"),
    )
    db.rollback()
    agents = {a.name: a for a in db.scalars(select(Agent).where(Agent.organization_id == seeded_org.org_id))}
    sessions = {
        s.agent_id: s
        for s in db.scalars(select(AgentSession).where(AgentSession.organization_id == seeded_org.org_id))
    }
    return {
        "alpha": agents["alpha"].id,
        "beta": agents["beta"].id,
        "alpha_session": sessions[agents["alpha"].id].id,
        "beta_session": sessions[agents["beta"].id].id,
        "headers": _bound(db, seeded_org.org_id, agents["alpha"].id),
    }


@pytest.mark.parametrize("path", ORG_WIDE_GETS)
def test_org_wide_reads_refuse_bound_keys(client, seeded_org, two_agents, path):
    response = client.get(API + path, headers=two_agents["headers"])
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "forbidden"
    # The same organisation's unbound key still reads them (403 is about the binding, not the scope).
    if path != "/stream":  # an endless response; its own tests drive it
        assert client.get(API + path, headers=seeded_org.api_headers).status_code == 200, path


def test_bound_key_sees_only_its_agent(client, two_agents):
    h = two_agents["headers"]
    listed = client.get(f"{API}/agents", headers=h).json()
    assert [a["id"] for a in listed["items"]] == [two_agents["alpha"]] and listed["total"] == 1
    assert client.get(f"{API}/agents/{two_agents['alpha']}", headers=h).status_code == 200
    for suffix in ("", "/sessions", "/tools", "/posture"):
        response = client.get(f"{API}/agents/{two_agents['beta']}{suffix}", headers=h)
        assert response.status_code == 404, suffix
        assert response.json()["error"]["code"] == "not_found"


def test_bound_key_sees_only_its_agents_sessions(client, two_agents):
    h = two_agents["headers"]
    listed = client.get(f"{API}/sessions", headers=h).json()
    assert [s["id"] for s in listed["items"]] == [two_agents["alpha_session"]]
    assert (
        client.get(f"{API}/sessions", headers=h, params={"agent_id": two_agents["beta"]}).json()["total"] == 0
    )
    assert client.get(f"{API}/sessions/{two_agents['alpha_session']}", headers=h).status_code == 200
    assert client.get(f"{API}/sessions/{two_agents['alpha_session']}/timeline", headers=h).status_code == 200
    for suffix in ("", "/timeline"):
        assert (
            client.get(f"{API}/sessions/{two_agents['beta_session']}{suffix}", headers=h).status_code == 404
        )


def test_bound_key_sees_only_its_agents_simulation_runs(client, seeded_org, two_agents, db):
    h = two_agents["headers"]
    mine = client.post(
        f"{API}/simulations/runs",
        headers=h,
        json={"scenario_id": "benign-baseline", "agent_id": two_agents["alpha"]},
    )
    assert mine.status_code == 201, mine.text
    theirs = client.post(
        f"{API}/simulations/runs",
        headers=seeded_org.user_headers,
        json={"scenario_id": "benign-baseline", "agent_id": two_agents["beta"]},
    ).json()
    listed = client.get(f"{API}/simulations/runs", headers=h).json()
    assert [r["id"] for r in listed["items"]] == [mine.json()["id"]]
    assert client.get(f"{API}/simulations/runs/{mine.json()['id']}", headers=h).status_code == 200
    assert client.get(f"{API}/simulations/runs/{theirs['id']}", headers=h).status_code == 404
    db.rollback()
    assert db.get(SimulationRun, theirs["id"]) is not None  # it exists: the 404 is the binding


def test_reusing_another_agents_event_id_reveals_nothing(client, seeded_org, two_agents, db):
    beta_call = tool_requested("Bash", {"command": "ls"}, agent="beta", session="s-beta")
    beta_decision = client.post(f"{API}/decide", json=beta_call, headers=seeded_org.api_headers).json()

    as_alpha = {**beta_call, "agent": {"name": "alpha"}, "session_id": "s-alpha"}
    result = client.post(f"{API}/events", json={"events": [as_alpha]}, headers=two_agents["headers"]).json()
    assert result["results"][0]["status"] == "rejected"
    assert result["results"][0]["refs"] == {} and result["results"][0]["ingested_event_id"] is None
    response = client.post(f"{API}/decide", json=as_alpha, headers=two_agents["headers"])
    assert response.status_code == 403 and response.json()["error"]["code"] == "attribution_rejected"
    assert beta_decision["policy_decision_id"] not in response.text
    db.rollback()
    reasons = [
        a.details.get("reason")
        for a in db.scalars(
            select(AuditEvent).where(
                AuditEvent.organization_id == seeded_org.org_id,
                AuditEvent.action == "ingest.attribution_rejected",
            )
        )
    ]
    assert reasons.count("event_id_of_another_agent") == 2

    # The bound key's own retries are still idempotent.
    mine = event("prompt.submitted", agent="alpha", session="s-alpha", content="hello")
    first = post_events(client, two_agents["headers"], mine)[0]
    again = post_events(client, two_agents["headers"], mine)[0]
    assert (first["status"], again["status"]) == ("accepted", "duplicate")
    assert again["refs"] == first["refs"]
