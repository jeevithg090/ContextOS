"""Sessions API: filtered lists, risk detail with trifecta evidence, timelines, isolation."""

from __future__ import annotations

import json

from app.models import ContextItem
from tests.integration.agents_support import benign_session, delegation, exfil_session, simulated_agent
from tests.integration.ingestion_support import GITHUB_TOKEN, event, post_events, tool_requested

API = "/api/v1/sessions"
DECLARED = {"tools": [{"name": "Read"}, {"name": "WebFetch"}]}


def _setup(client, org) -> dict[str, str]:
    """Registered agent (declares WebFetch, an outbound channel) + one risky and one benign session."""
    assert client.post("/api/v1/agents", json={"name": "coder", "declared_capabilities": DECLARED},
                       headers=org.user_headers).status_code == 201
    exfil_session(client, org.api_headers)
    benign_session(client, org.api_headers)
    items = client.get(API, headers=org.user_headers).json()["items"]
    return {s["external_session_id"]: s["id"] for s in items}


def test_list_filters_by_trifecta_risk_status_and_agent(client, seeded_org):
    ids = _setup(client, seeded_org)
    h = seeded_org.user_headers
    risky = client.get(API, params={"trifecta": True}, headers=h).json()
    assert [s["id"] for s in risky["items"]] == [ids["sess-exfil"]]
    row = risky["items"][0]
    assert row["trifecta"] and row["sensitive_access"] and row["untrusted_exposure"] and row["outbound_channel"]
    assert row["risk_level"] == "critical" and row["open_findings"] > 0 and row["agent"]["name"] == "coder"
    assert [s["id"] for s in client.get(API, params={"trifecta": False}, headers=h).json()["items"]] == [ids["sess-benign"]]
    assert client.get(API, params={"min_risk": 90}, headers=h).json()["total"] == 1
    assert [s["status"] for s in client.get(API, params={"status": "ended"}, headers=h).json()["items"]] == ["ended"]
    by_risk = client.get(API, params={"sort": "risk"}, headers=h).json()["items"]
    assert by_risk[0]["id"] == ids["sess-exfil"]
    agent_id = row["agent"]["id"]
    assert client.get(API, params={"agent_id": agent_id}, headers=h).json()["total"] == 2
    assert client.get(API, params={"q": "benign"}, headers=h).json()["total"] == 1
    assert client.get(API, params={"min_risk": 101}, headers=h).status_code == 422


def test_detail_reports_trifecta_conditions_with_resolvable_evidence(client, seeded_org, db):
    ids = _setup(client, seeded_org)
    detail = client.get(f"{API}/{ids['sess-exfil']}", headers=seeded_org.user_headers).json()
    risk = detail["risk"]
    assert risk["trifecta"] is True and "not proof" in risk["note"] and "not proof" in risk["summary"]
    conditions = {c["key"]: c for c in risk["conditions"]}
    assert set(conditions) == {"sensitive_access", "untrusted_exposure", "outbound_channel"}
    assert all(c["active"] and c["evidence"] for c in conditions.values())
    sensitive = conditions["sensitive_access"]["evidence"]
    item = next(e for e in sensitive if e["type"] == "context_item")
    assert item["label"].endswith(".env") and item["session_id"] == ids["sess-exfil"]
    db.rollback()
    stored = db.get(ContextItem, item["id"])
    assert stored is not None and stored.organization_id == seeded_org.org_id and stored.contains_secrets
    untrusted = conditions["untrusted_exposure"]["evidence"]
    assert any(e["trust_level"] == "SUSPICIOUS" and e["label"].endswith("README.md") for e in untrusted)
    assert any(e["type"] == "tool" and e["id"] == "WebFetch" for e in conditions["outbound_channel"]["evidence"])
    assert risk["factors"] and all(f["explanation"] for f in risk["factors"])

    counts = detail["counts"]
    assert counts["decisions"] == {"AUDIT": 1, "ALLOW": 1, "DENY": 1} and counts["enforcement"] == {"enforced": 3}
    assert counts["context_items"] == 2 and counts["untrusted_context_items"] == 2 and counts["tool_invocations"] == 3
    assert counts["timeline_entries"] == 6 and counts["findings_open"] == len(detail["findings"]) > 0
    assert detail["metadata"] == {"cwd": "/work/app", "model": "claude"}
    assert detail["findings"][0]["severity"] == "critical"
    assert GITHUB_TOKEN not in json.dumps(detail)


def test_timeline_titles_decisions_and_links(client, seeded_org):
    ids = _setup(client, seeded_org)
    page = client.get(f"{API}/{ids['sess-exfil']}/timeline", headers=seeded_org.user_headers).json()
    entries = page["items"]
    assert page["total"] == 6 and [e["sequence"] for e in entries] == sorted(e["sequence"] for e in entries)
    titles = [e["title"] for e in entries]
    assert titles[0] == "Session started" and entries[0]["summary"] == "model: claude · cwd: /work/app"
    assert "Allowed Read .env (audited)" in titles and "Read file .env" in titles
    assert "Read file README.md" in titles
    denied = entries[-1]
    assert denied["title"].startswith("Denied WebFetch to webhook.site")
    assert denied["decision"] == "DENY" and denied["enforcement"] == "enforced" and denied["severity"] == "critical"
    assert denied["refs"]["tool_invocation_id"] and denied["refs"]["policy_decision_id"] and denied["refs"]["finding_ids"]
    assert denied["tool"] == {"name": "WebFetch", "category": "http", "status": "denied"}
    readme = next(e for e in entries if e["title"] == "Read file README.md")
    assert readme["trust_level"] == "SUSPICIOUS" and readme["refs"]["context_item_id"] and readme["severity"]
    assert GITHUB_TOKEN not in json.dumps(page)


def test_timeline_focuses_the_page_containing_an_invocation(client, seeded_org):
    ids = _setup(client, seeded_org)
    h = seeded_org.user_headers
    full = client.get(f"{API}/{ids['sess-exfil']}/timeline", headers=h).json()["items"]
    invocation = full[-1]["refs"]["tool_invocation_id"]
    page = client.get(f"{API}/{ids['sess-exfil']}/timeline", params={"invocation_id": invocation, "limit": 2},
                      headers=h).json()
    assert page["offset"] == 4 and page["focus_event_ids"] == [full[-1]["id"]]
    assert full[-1]["id"] in [e["id"] for e in page["items"]]
    other = client.get(f"{API}/{ids['sess-benign']}/timeline", params={"invocation_id": invocation}, headers=h).json()
    assert other["focus_event_ids"] == [] and other["offset"] == 0  # not part of that session


def test_observed_decisions_are_not_described_as_blocks(client, seeded_org):
    h = seeded_org.api_headers
    post_events(client, h, tool_requested("WebFetch", {"url": "https://webhook.site/x", "method": "POST",
                                                       "body": "hello"}, session="obs-1"))
    session_id = client.get(API, headers=seeded_org.user_headers).json()["items"][0]["id"]
    entry = client.get(f"{API}/{session_id}/timeline", headers=seeded_org.user_headers).json()["items"][0]
    assert entry["enforcement"] == "observed"
    assert entry["title"].startswith("Observed request: WebFetch") and "nothing could be prevented" in entry["summary"]
    assert not entry["title"].startswith(("Denied", "Allowed", "Held"))


def test_delegation_parent_child_and_inherited_task(client, seeded_org):
    delegation(client, seeded_org.api_headers)
    h = seeded_org.user_headers
    items = {s["external_session_id"]: s for s in client.get(API, headers=h).json()["items"]}
    parent, child = items["orch-1"], items["res-1"]
    assert parent["child_count"] == 1 and child["parent_session_id"] == parent["id"]
    parent_detail = client.get(f"{API}/{parent['id']}", headers=h).json()
    assert [c["id"] for c in parent_detail["children"]] == [child["id"]]
    assert parent_detail["children"][0]["agent"]["name"] == "researcher"
    child_detail = client.get(f"{API}/{child['id']}", headers=h).json()
    assert child_detail["parent"]["id"] == parent["id"] and child_detail["parent"]["agent"]["name"] == "orchestrator"

    parent_tl = client.get(f"{API}/{parent['id']}/timeline", headers=h).json()["items"]
    assert parent_tl[0]["title"] == "Delegated to researcher" and parent_tl[0]["refs"]["child_session_id"] == child["id"]
    child_tl = client.get(f"{API}/{child['id']}/timeline", headers=h).json()["items"]
    task = child_tl[0]
    assert task["title"] == "Task received from orchestrator" and task["from_other_session"] is True
    assert task["summary"] == "Find the vendor's pricing." and task["refs"]["context_item_id"]
    assert task["refs"]["child_session_id"] is None
    assert any(e["title"] == "Fetched pricing.example-vendor.net/plans" for e in child_tl)


def test_simulated_sessions_hidden_unless_requested(client, seeded_org, db):
    benign_session(client, seeded_org.api_headers)
    simulated_agent(db, seeded_org.org_id)
    h = seeded_org.user_headers
    assert client.get(API, headers=h).json()["total"] == 1
    everything = client.get(API, params={"include_simulated": True}, headers=h).json()
    assert everything["total"] == 2 and any(s["is_simulation"] for s in everything["items"])


def test_processing_errors_are_visible_in_the_timeline(client, seeded_org, monkeypatch):
    from app.services import ingestion

    post_events(client, seeded_org.api_headers, event("session.started", session="err-1"))

    def boom(st):
        raise RuntimeError("detector crashed")

    monkeypatch.setitem(ingestion._HANDLERS, "prompt.submitted", boom)
    post_events(client, seeded_org.api_headers, event("prompt.submitted", content="hello", session="err-1"))
    session_id = client.get(API, headers=seeded_org.user_headers).json()["items"][0]["id"]
    entries = client.get(f"{API}/{session_id}/timeline", headers=seeded_org.user_headers).json()["items"]
    failed = [e for e in entries if e["processing_status"] == "error"]
    assert failed and failed[0]["title"] == "Could not process prompt.submitted event"
    assert "detector crashed" in failed[0]["summary"] and failed[0]["from_other_session"] is False
    detail = client.get(f"{API}/{session_id}", headers=seeded_org.user_headers).json()
    assert detail["counts"]["processing_errors"] == 1 and detail["counts"]["timeline_entries"] == 2


def test_cross_org_isolation_and_permissions(client, seeded_org, other_org, make_org):
    ids = _setup(client, seeded_org)
    session_id = ids["sess-exfil"]
    h = other_org.user_headers
    assert client.get(f"{API}/{session_id}", headers=h).status_code == 404
    assert client.get(f"{API}/{session_id}/timeline", headers=h).status_code == 404
    assert client.get(API, headers=h).json()["total"] == 0
    assert client.get(API, params={"agent_id": client.get(f"{API}/{session_id}", headers=seeded_org.user_headers)
                                   .json()["agent"]["id"]}, headers=h).json()["total"] == 0
    ingest_only = make_org("Ingest Only", scopes=["ingest"])
    assert client.get(API, headers=ingest_only.api_headers).status_code == 403
    assert client.get(f"{API}/{session_id}", headers=seeded_org.api_headers).status_code == 200  # read scope
    assert client.get(API).status_code == 401


def test_timeline_entries_carry_the_decision_explanation_and_stay_shared(client, seeded_org, db):
    from sqlalchemy import select

    from app.models import AgentSession, IngestedEvent
    from app.services import sessions_service, sessions_timeline

    ids = _setup(client, seeded_org)
    entries = client.get(f"{API}/{ids['sess-exfil']}/timeline", headers=seeded_org.user_headers).json()["items"]
    denied = next(e for e in entries if e["decision"] == "DENY")
    assert denied["enforcement"] == "enforced" and denied["explanation"].startswith("DENY by policy")
    assert all(e["explanation"] is None for e in entries if e["decision"] is None)
    assert GITHUB_TOKEN not in json.dumps(entries)

    # The public name and the former private one are the same function (replay imports it).
    assert sessions_service.timeline_entries is sessions_timeline.timeline_entries is sessions_service._entries
    db.rollback()
    session = db.scalar(select(AgentSession).where(AgentSession.id == ids["sess-exfil"]))
    rows = list(db.scalars(sessions_service.timeline_query(seeded_org.org_id, session, "coder")
                           .order_by(IngestedEvent.sequence)))
    direct = sessions_service.timeline_entries(db, seeded_org.org_id, session, rows)
    assert [e["id"] for e in direct] == [e["id"] for e in entries]
    assert [e["title"] for e in direct] == [e["title"] for e in entries]
