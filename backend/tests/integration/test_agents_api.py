"""Agents API: inventory, registration, edits and quarantine, tools, posture, graph, isolation."""

from __future__ import annotations

from sqlalchemy import select

from app.models import Agent, AuditEvent
from tests.integration.agents_support import by_name, delegation, exfil_session, simulated_agent
from tests.integration.ingestion_support import GITHUB_TOKEN, decide, tool_requested

API = "/api/v1/agents"
DECLARED = {
    "tools": [
        {"name": "Read"},
        {"name": "WebFetch"},
        {"name": "Bash"},
        {"name": "summarise_notes", "category": "http"},
    ]
}


def _register(client, org, **body):
    payload = {"name": "coder", "framework": "claude_code", "declared_capabilities": DECLARED, **body}
    response = client.post(API, json=payload, headers=org.user_headers)
    assert response.status_code == 201, response.text
    return response.json()


def _actions(db, org_id: str) -> list[str]:
    db.rollback()
    return list(
        db.scalars(
            select(AuditEvent.action).where(AuditEvent.organization_id == org_id).order_by(AuditEvent.seq)
        )
    )


def test_register_classifies_tools_server_side_and_integration_attaches(client, seeded_org, db):
    agent = _register(
        client, seeded_org, owner="platform-team", environment="production", labels=["Payments"]
    )
    tools = {t["name"]: t for t in agent["declared_capabilities"]["tools"]}
    assert tools["Bash"]["category"] == "shell" and tools["Bash"]["risk_level"] == "high"
    assert tools["WebFetch"]["category"] == "http"
    assert (
        tools["summarise_notes"]["category_hint"] == "http"
    )  # hint recorded next to the server's classification
    assert agent["labels"] == ["payments"] and agent["environment"] == "production"
    assert agent["quarantine"]["active"] is False and agent["quarantine"]["enforced"] is False
    assert "agent.registered" in _actions(db, seeded_org.org_id)

    exfil_session(client, seeded_org.api_headers)
    listing = client.get(API, headers=seeded_org.user_headers).json()
    assert listing["total"] == 1  # the integration's events attached to the registered agent (same name)
    row = listing["items"][0]
    assert row["id"] == agent["id"] and row["environment"] == "production"  # integrations cannot move it
    assert row["session_count"] == 1 and row["observed_tool_count"] == 2 and row["declared_tool_count"] == 4
    assert row["open_findings"] > 0 and row["max_open_severity"] == "critical"
    assert row["risk_score"] > 0 and row["risk_level"] in ("high", "critical")
    assert row["integration_kind"] == "claude_code"
    assert listing["facets"]["environments"] == [{"value": "production", "count": 1}]


def test_register_rejects_duplicates_reserved_labels_and_client_risk(client, seeded_org):
    _register(client, seeded_org)
    duplicate = client.post(API, json={"name": "coder"}, headers=seeded_org.user_headers)
    assert duplicate.status_code == 409
    for body in (
        {"name": "a", "risk_score": 0},
        {"name": "b", "labels": ["Quarantined"]},
        {"name": "c", "status": "active"},
        {"name": "d", "framework": "Bad Framework!"},
        {"name": "e", "declared_capabilities": {"tools": [{"name": "x", "risk_level": "low"}]}},
    ):
        response = client.post(API, json=body, headers=seeded_org.user_headers)
        assert response.status_code == 422, body


def test_register_redacts_secrets_in_free_text(client, seeded_org, db):
    agent = _register(client, seeded_org, description=f"Deploy bot. Token {GITHUB_TOKEN}")
    assert GITHUB_TOKEN not in agent["description"]
    db.rollback()
    stored = db.get(Agent, agent["id"])
    assert GITHUB_TOKEN not in (stored.description or "")


def test_quarantine_is_enforced_only_through_a_matching_policy(client, seeded_org, db):
    agent = _register(client, seeded_org)
    patched = client.patch(
        f"{API}/{agent['id']}", json={"status": "quarantined"}, headers=seeded_org.user_headers
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["status"] == "quarantined" and "quarantined" in body["labels"]
    assert body["quarantine"]["active"] is True and body["quarantine"]["enforced"] is False
    assert "still decided by your other policies" in body["quarantine"]["explanation"]
    assert "agent.quarantined" in _actions(db, seeded_org.org_id)

    created = client.post(
        "/api/v1/policies", json=body["quarantine"]["suggested_policy"], headers=seeded_org.user_headers
    )
    assert created.status_code == 201, created.text
    state = client.get(f"{API}/{agent['id']}", headers=seeded_org.user_headers).json()["quarantine"]
    assert state["enforced"] is True and state["policies"][0]["scope"] == "all_calls"

    denied = decide(
        client,
        seeded_org.api_headers,
        tool_requested("Read", {"file_path": "/work/app/main.py"}, agent="coder", session="q-1"),
    )
    assert denied["decision"] == "DENY" and denied["enforcement"] == "enforced"
    assert denied["matched_policies"][0]["name"] == "Deny tool calls from quarantined agents"

    released = client.patch(
        f"{API}/{agent['id']}", json={"status": "active"}, headers=seeded_org.user_headers
    ).json()
    assert released["status"] == "active" and "quarantined" not in released["labels"]
    allowed = decide(
        client,
        seeded_org.api_headers,
        tool_requested("Read", {"file_path": "/work/app/main.py"}, agent="coder", session="q-1"),
    )
    assert allowed["decision"] != "DENY"
    assert "agent.quarantine_released" in _actions(db, seeded_org.org_id)


def test_policy_relevant_fields_need_policy_manage(client, seeded_org, make_org, db):
    agent = _register(client, seeded_org)
    dev = make_org("Dev Org", role="developer")
    dev_agent = _register(client, dev)
    url = f"{API}/{dev_agent['id']}"
    ok = client.patch(
        url,
        json={
            "owner": "team-a",
            "description": "Builds things",
            "declared_capabilities": {"tools": [{"name": "Read"}]},
        },
        headers=dev.user_headers,
    )
    assert ok.status_code == 200 and ok.json()["owner"] == "team-a" and ok.json()["declared_tool_count"] == 1
    for change in ({"environment": "production"}, {"labels": ["pci"]}, {"status": "quarantined"}):
        assert client.patch(url, json=change, headers=dev.user_headers).status_code == 403, change
    # A no-op value for a guarded field is not a change and needs no extra permission.
    assert client.patch(url, json={"environment": "development"}, headers=dev.user_headers).status_code == 200

    owner = client.patch(
        f"{API}/{agent['id']}",
        json={"environment": "staging", "labels": ["pci"]},
        headers=seeded_org.user_headers,
    )
    assert owner.status_code == 200 and owner.json()["environment"] == "staging"
    db.rollback()
    entry = db.scalars(
        select(AuditEvent).where(
            AuditEvent.organization_id == seeded_org.org_id, AuditEvent.action == "agent.updated"
        )
    ).all()[-1]
    assert entry.details["changes"]["environment"] == {"from": "development", "to": "staging"}


def test_viewer_and_api_key_permissions(client, seeded_org, make_org):
    viewer = make_org("Viewer Org", role="viewer")
    assert client.get(API, headers=viewer.user_headers).status_code == 200
    assert client.post(API, json={"name": "x"}, headers=viewer.user_headers).status_code == 403
    agent = _register(client, seeded_org)
    assert client.get(f"{API}/{agent['id']}", headers=seeded_org.api_headers).status_code == 200  # read scope
    ingest_only = make_org("Ingest Org", scopes=["ingest"])
    assert client.get(API, headers=ingest_only.api_headers).status_code == 403
    assert (
        client.post(API, json={"name": "y"}, headers=seeded_org.api_headers).status_code == 403
    )  # no write scope


def test_tools_breakdown_and_declared_but_unused(client, seeded_org):
    agent = _register(client, seeded_org)
    exfil_session(client, seeded_org.api_headers)
    page = client.get(f"{API}/{agent['id']}/tools", headers=seeded_org.user_headers).json()
    tools = {t["name"]: t for t in page["items"]}
    assert tools["Read"]["invocation_count"] == 2 and tools["Read"]["declared"] is True
    assert tools["Read"]["decisions"] == {"AUDIT": 1, "ALLOW": 1}
    assert tools["WebFetch"]["decisions"] == {"DENY": 1} and tools["WebFetch"]["statuses"] == {"denied": 1}
    assert tools["WebFetch"]["credential_calls"] == 1 and tools["WebFetch"]["enforcement"] == {"enforced": 1}
    assert tools["Bash"]["observed"] is False and tools["Bash"]["category"] == "shell"
    assert tools["Bash"]["invocation_count"] == 0 and tools["Bash"]["tool_id"] is None


def test_posture_is_assembled_from_persisted_state(client, seeded_org):
    agent = _register(client, seeded_org)
    exfil_session(client, seeded_org.api_headers)
    posture = client.get(f"{API}/{agent['id']}/posture", headers=seeded_org.user_headers).json()
    assert 0 <= posture["score"] <= 100 and posture["grade"] in "ABCDF"
    dims = {d["key"]: d for d in posture["dimensions"]}
    assert len(dims) == 9 and sum(d["max_score"] for d in dims.values()) == 100
    assert dims["unresolved_findings"]["score"] < 10 and dims["unresolved_findings"]["evidence"]
    assert dims["trifecta_exposure"]["score"] <= 7  # one session with all three conditions caps it
    assert dims["enforcement_coverage"]["score"] == 10  # claude_code decisions were enforced
    basis = posture["basis"]
    assert basis["total_sessions"] == 1 and basis["sessions_with_trifecta"] == 1
    assert basis["supports_enforcement"] is True and basis["decisions_by_enforcement"] == {"enforced": 3}
    assert basis["untrusted_source_count"] >= 1 and basis["enabled_policy_count"] > 0
    assert basis["integration_health"] == "connected"


def test_posture_counts_a_stale_integration_as_unhealthy(client, seeded_org, db):
    from datetime import timedelta

    from app.core.timeutil import utcnow
    from app.models import Integration

    agent = _register(client, seeded_org)
    exfil_session(client, seeded_org.api_headers)
    db.rollback()
    row = db.scalar(
        select(Integration).where(
            Integration.organization_id == seeded_org.org_id, Integration.kind == "claude_code"
        )
    )
    assert row.status == "connected"  # the stored status alone would still read as healthy
    row.last_event_at = utcnow() - timedelta(hours=25)
    db.commit()
    posture = client.get(f"{API}/{agent['id']}/posture", headers=seeded_org.user_headers).json()
    coverage = {d["key"]: d for d in posture["dimensions"]}["enforcement_coverage"]
    assert posture["basis"]["integration_health"] == "stale"
    assert coverage["score"] == 5 and "'stale'" in coverage["explanation"] and coverage["recommendation"]


def test_posture_builder_passes_policies_in_the_engine_shape():
    from app.engines.policy import PolicySpec
    from app.services.agents_posture import posture_policies

    spec = PolicySpec(
        id="pol_1",
        name="Deny secrets out",
        outcome="DENY",
        mode="enforce",
        conditions={"field": "secrets_in_arguments", "op": "not_empty"},
        version=1,
        enabled=True,
        priority=100,
        severity="high",
        restrictions={},
        description=None,
    )
    assert posture_policies([spec]) == [
        {
            "id": "pol_1",
            "name": "Deny secrets out",
            "outcome": "DENY",
            "mode": "enforce",
            "conditions": spec.conditions,
            "enabled": True,
        }
    ]


def test_agent_detail_relationships_and_graph(client, seeded_org):
    delegation(client, seeded_org.api_headers)
    graph = client.get(f"{API}/graph", headers=seeded_org.user_headers).json()
    nodes = {n["name"]: n for n in graph["nodes"]}
    assert set(nodes) == {"orchestrator", "researcher"}
    edge = graph["edges"][0]
    assert edge["source"] == nodes["orchestrator"]["id"] and edge["target"] == nodes["researcher"]["id"]
    assert edge["relationship_type"] == "delegates_to" and edge["event_count"] >= 1
    assert isinstance(edge["crosses_trust_boundary"], bool) and "not that one agent caused" in graph["note"]

    detail = client.get(f"{API}/{nodes['researcher']['id']}", headers=seeded_org.user_headers).json()
    rel = detail["relationships"][0]
    assert rel["direction"] == "incoming" and rel["other_agent"]["name"] == "orchestrator"
    assert detail["recent_findings"] and detail["findings_by_severity"]
    sessions = client.get(
        f"{API}/{nodes['researcher']['id']}/sessions", headers=seeded_org.user_headers
    ).json()
    assert sessions["total"] == 1 and sessions["items"][0]["parent_session_id"]


def test_simulated_agents_are_hidden_by_default(client, seeded_org, db):
    _register(client, seeded_org)
    simulated_agent(db, seeded_org.org_id)
    default = client.get(API, headers=seeded_org.user_headers).json()
    assert [a["name"] for a in default["items"]] == ["coder"] and default["facets"]["simulated"] == 1
    everything = client.get(API, params={"include_simulated": True}, headers=seeded_org.user_headers).json()
    assert by_name(everything["items"], "sim-agent")["is_simulation"] is True
    graph = client.get(f"{API}/graph", headers=seeded_org.user_headers).json()
    assert {n["name"] for n in graph["nodes"]} == {"coder"}


def test_list_filters_search_and_sort(client, seeded_org):
    _register(client, seeded_org, name="billing-bot", owner="payments", environment="production")
    _register(client, seeded_org, name="docs-bot", owner="docs")
    h = seeded_org.user_headers
    assert [
        a["name"] for a in client.get(API, params={"environment": "production"}, headers=h).json()["items"]
    ] == ["billing-bot"]
    assert [a["name"] for a in client.get(API, params={"q": "docs"}, headers=h).json()["items"]] == [
        "docs-bot"
    ]
    assert [a["name"] for a in client.get(API, params={"sort": "name"}, headers=h).json()["items"]] == [
        "billing-bot",
        "docs-bot",
    ]
    assert client.get(API, params={"q": "%"}, headers=h).json()["total"] == 0  # LIKE wildcards are escaped
    assert client.get(API, params={"status": "deleted"}, headers=h).status_code == 422


def test_cross_org_isolation(client, seeded_org, other_org):
    agent = _register(client, seeded_org)
    exfil_session(client, seeded_org.api_headers)
    h = other_org.user_headers
    for suffix in ("", "/tools", "/posture", "/sessions"):
        assert client.get(f"{API}/{agent['id']}{suffix}", headers=h).status_code == 404, suffix
    assert client.patch(f"{API}/{agent['id']}", json={"owner": "x"}, headers=h).status_code == 404
    assert client.get(API, headers=h).json()["total"] == 0
    assert client.get(f"{API}/graph", headers=h).json()["nodes"] == []
    # Same agent name in another organisation is a different agent.
    assert client.post(API, json={"name": "coder"}, headers=h).status_code == 201
