"""Replay Lab API: recorded steps with recomputed risk, and counterfactual policy replay.

Data comes from the real ingestion pipeline (POST /events, POST /decide) on an org seeded with the
built-in policy pack. Counterfactuals must evaluate recorded input snapshots only, label themselves
as simulations and never persist anything.
"""

from __future__ import annotations

import json

from sqlalchemy import func, select

from app.models import PolicyDecision, SecurityPolicy
from tests.integration.agents_support import MALICIOUS_README, exfil_session, simulated_agent
from tests.integration.ingestion_support import (
    GITHUB_TOKEN,
    decide,
    event,
    post_events,
    run_tool,
    tool_completed,
    tool_requested,
)

API = "/api/v1/replay"
DECLARED = {"tools": [{"name": "Read"}, {"name": "WebFetch"}]}
DENY_READS = {"name": "Deny all reads", "outcome": "DENY", "conditions": {"field": "tool.name", "op": "eq", "value": "Read"}}


def _exfil(client, org) -> str:
    """Agent declaring WebFetch + the exfiltration session (AUDIT .env read, ALLOW README read, DENY WebFetch)."""
    assert client.post("/api/v1/agents", json={"name": "coder", "declared_capabilities": DECLARED},
                       headers=org.user_headers).status_code == 201
    exfil_session(client, org.api_headers)
    return client.get("/api/v1/sessions", headers=org.user_headers).json()["items"][0]["id"]


def _policy_id(client, org, name: str) -> str:
    items = client.get("/api/v1/policies", params={"limit": 500}, headers=org.user_headers).json()["items"]
    return next(p["id"] for p in items if p["name"] == name)


def _cf(client, org, session_id: str, *, expect: int = 200, **policy_set):
    body = {"session_id": session_id, "policy_set": policy_set}
    response = client.post(f"{API}/counterfactual", json=body, headers=org.user_headers)
    assert response.status_code == expect, response.text
    return response.json()


# ----------------------------------------------------------------------------- session replay


def test_replay_returns_recorded_steps_with_outcomes_findings_and_recomputed_risk(client, seeded_org):
    sid = _exfil(client, seeded_org)
    response = client.get(f"{API}/sessions/{sid}", headers=seeded_org.user_headers)
    assert response.status_code == 200, response.text
    data = response.json()
    steps = data["steps"]

    assert data["total_steps"] == 6 and data["decision_steps"] == 3 and not data["truncated"]
    assert [s["index"] for s in steps] == list(range(6))
    assert [s["sequence"] for s in steps] == sorted(s["sequence"] for s in steps)
    assert [s["event_type"] for s in steps] == ["session.started", "tool.requested", "tool.completed",
                                                "tool.requested", "tool.completed", "tool.requested"]
    assert steps[1]["title"] == "Allowed Read .env (audited)" and steps[2]["title"] == "Read file .env"
    assert data["risk_basis"] == "recomputed from recorded events" and "redacted" in data["basis"]
    assert "not applied" in data["risk_note"]

    outcomes = [(s["outcome"]["decision"], s["outcome"]["enforcement"]) for s in steps if s["outcome"]]
    assert outcomes == [("AUDIT", "enforced"), ("ALLOW", "enforced"), ("DENY", "enforced")]
    exfil = steps[5]
    assert "Block credential exfiltration" in exfil["outcome"]["matched_policies"]
    assert exfil["outcome"]["approval_status"] is None and exfil["refs"]["policy_decision_id"]
    assert exfil["recorded_risk"]["trifecta"] is True and steps[0]["recorded_risk"] is None
    assert any(f["severity"] == "critical" for f in exfil["findings"])
    assert all(f["title"] and f["status"] == "open" for s in steps for f in s["findings"])
    assert steps[4]["refs"]["context_item_id"] and steps[4]["trust_level"]

    risks = [s["risk_after"] for s in steps]
    assert all(r["basis"] == "recomputed from recorded events" for r in risks)
    assert risks[0]["score"] < risks[-1]["score"] and risks[0]["trifecta"] is False
    deltas = [risks[0]["score"]] + [b["score"] - a["score"] for a, b in zip(risks, risks[1:], strict=False)]
    assert [r["delta"] for r in risks] == deltas
    # Without later triage or reclassification the recomputation ends where the live pipeline did.
    assert risks[-1]["score"] == data["session"]["risk_score"] and risks[-1]["trifecta"] is True
    assert {f["key"] for f in risks[-1]["factors"]} >= {"sensitive_access", "untrusted_exposure", "trifecta"}
    assert GITHUB_TOKEN not in json.dumps(data)


def test_replay_windows_and_decision_focus_keep_prefix_risk(client, seeded_org):
    sid = _exfil(client, seeded_org)
    h = seeded_org.user_headers
    full = client.get(f"{API}/sessions/{sid}", headers=h).json()["steps"]
    window = client.get(f"{API}/sessions/{sid}", params={"limit": 2, "offset": 2}, headers=h).json()
    assert [s["index"] for s in window["steps"]] == [2, 3] and window["truncated"] is True
    assert [s["risk_after"] for s in window["steps"]] == [s["risk_after"] for s in full[2:4]]

    deny_id = full[5]["refs"]["policy_decision_id"]
    focused = client.get(f"{API}/sessions/{sid}", params={"limit": 2, "decision_id": deny_id}, headers=h).json()
    assert focused["focus_index"] == 5 and focused["offset"] == 4 and [s["index"] for s in focused["steps"]] == [4, 5]
    unknown = client.get(f"{API}/sessions/{sid}", params={"decision_id": "pdc_unknown"}, headers=h).json()
    assert unknown["focus_index"] is None and unknown["offset"] == 0
    assert client.get(f"{API}/sessions/asn_missing", headers=h).status_code == 404
    assert client.get(f"{API}/sessions/{sid}", params={"limit": 0}, headers=h).status_code == 422


def test_replay_tracks_approval_outcome_and_status_over_time(client, seeded_org):
    h, api = seeded_org.user_headers, seeded_org.api_headers
    assert client.post("/api/v1/agents", json={"name": "coder", "declared_capabilities": DECLARED},
                       headers=h).status_code == 201
    kw = {"session": "sess-approval"}
    run_tool(client, api, "Read", {"file_path": "/work/app/.env"}, f"GITHUB_TOKEN={GITHUB_TOKEN}\n", **kw)
    run_tool(client, api, "Read", {"file_path": "/work/app/README.md"}, MALICIOUS_README, **kw)
    request = tool_requested("WebFetch", {"url": "https://status.partner-api.net/health"}, **kw)
    held = decide(client, api, request)
    assert held["decision"] == "REQUIRE_APPROVAL" and held["approval_id"]
    assert client.post(f"/api/v1/approvals/{held['approval_id']}/decide", json={"approve": True},
                       headers=h).status_code == 200
    post_events(client, api, tool_completed("WebFetch", {"url": "https://status.partner-api.net/health"}, "ok",
                                            correlation_id=request["correlation_id"], **kw))
    sid = next(s["id"] for s in client.get("/api/v1/sessions", headers=h).json()["items"]
               if s["external_session_id"] == "sess-approval")

    steps = client.get(f"{API}/sessions/{sid}", headers=h).json()["steps"]
    paused, ran = steps[-2], steps[-1]
    assert paused["outcome"]["decision"] == "REQUIRE_APPROVAL" and paused["outcome"]["approval_status"] == "approved"
    assert paused["outcome"]["approval_id"] == held["approval_id"]
    # While paused the call had not run, so "outbound channel used" is not yet a factor; once it ran it is.
    assert "outbound_channel" not in {f["key"] for f in paused["risk_after"]["factors"]}
    assert "outbound_channel" in {f["key"] for f in ran["risk_after"]["factors"]}


def test_simulated_session_replays_and_has_nothing_to_evaluate(client, org, db):
    simulated_agent(db, org.org_id)
    sid = client.get("/api/v1/sessions", params={"include_simulated": True}, headers=org.user_headers).json()["items"][0]["id"]
    data = client.get(f"{API}/sessions/{sid}", headers=org.user_headers).json()
    assert data["session"]["is_simulation"] is True and data["total_steps"] == 1 and data["decision_steps"] == 0
    cf = _cf(client, org, sid)
    assert cf["simulation"] is True and cf["steps"] == [] and cf["summary"]["evaluated"] == 0


# ----------------------------------------------------------------------------- counterfactual


def test_counterfactual_with_current_policies_reproduces_recorded_decisions(client, seeded_org, db):
    sid = _exfil(client, seeded_org)
    decisions_before = db.scalar(select(func.count()).select_from(PolicyDecision))
    cf = _cf(client, seeded_org, sid)
    assert cf["simulation"] is True and cf["label"].startswith("SIMULATION")
    assert cf["basis"] == "recorded PolicyDecision.input_snapshot" and len(cf["caveats"]) == 2
    assert cf["summary"] == {"evaluated": 3, "changed": 0, "would_deny": 1, "would_pause": 0, "would_allow": 2,
                             "would_restrict": 0, "drifted": 0, "transitions": {}}
    assert cf["not_evaluable_count"] == 0
    assert [s["step_index"] for s in cf["steps"]] == [1, 3, 5]
    exfil = cf["steps"][2]
    assert exfil["tool"] == {"name": "WebFetch", "category": "http"} and exfil["original_enforcement"] == "enforced"
    assert exfil["current_decision"] == "DENY" and not exfil["drifted"] and exfil["policy_changes"] == []
    fields = {e["field"]: e for e in exfil["evidence"]}
    assert fields["destination.identifier"]["value"] == "webhook.site"
    assert fields["secrets_in_arguments"]["present"] and "Block credential exfiltration" in fields["secrets_in_arguments"]["policies"]
    assert GITHUB_TOKEN not in json.dumps(cf)
    db.rollback()
    assert db.scalar(select(func.count()).select_from(PolicyDecision)) == decisions_before  # nothing persisted


def test_disabling_a_policy_changes_only_the_decisions_it_decided(client, seeded_org):
    sid = _exfil(client, seeded_org)
    block = _policy_id(client, seeded_org, "Block credential exfiltration")
    # The session read an injected README, so a second layer also denies credentials in the arguments.
    layered = _policy_id(client, seeded_org, "Deny credentials in tool arguments after prompt injection")
    only_block = _cf(client, seeded_org, sid, disable_policy_ids=[block])
    assert only_block["summary"]["changed"] == 0 and only_block["steps"][2]["hypothetical_decision"] == "DENY"
    cf = _cf(client, seeded_org, sid, disable_policy_ids=[block, layered])
    assert cf["summary"]["changed"] == 1 and cf["summary"]["transitions"] == {"DENY→REQUIRE_APPROVAL": 1}
    reads, exfil = cf["steps"][:2], cf["steps"][2]
    assert not any(s["changed"] for s in reads)
    assert exfil["hypothetical_decision"] == "REQUIRE_APPROVAL" and exfil["changed"]
    assert exfil["current_decision"] == "DENY" and not exfil["drifted"]
    assert {"policy_id": block, "name": "Block credential exfiltration", "change": "disabled",
            "detail": "Disabled in this simulation"} in exfil["policy_changes"]
    assert exfil["explanation"].startswith("Hypothetically REQUIRE_APPROVAL instead of the recorded DENY")
    listed = next(p for p in cf["policy_set"]["policies"] if p["id"] == block)
    assert listed["enabled"] is False and listed["changes"] == ["disabled"] and listed["source"] == "saved"


def test_outcome_and_mode_overrides(client, seeded_org):
    sid = _exfil(client, seeded_org)
    block = _policy_id(client, seeded_org, "Block credential exfiltration")
    audit = _policy_id(client, seeded_org, "Audit sensitive file reads")
    layered = _policy_id(client, seeded_org, "Deny credentials in tool arguments after prompt injection")
    cf = _cf(client, seeded_org, sid, overrides={block: {"outcome": "AUDIT"}, audit: {"mode": "monitor"}},
             disable_policy_ids=[layered])
    read_env, _, exfil = cf["steps"]
    assert read_env["hypothetical_decision"] == "ALLOW" and read_env["changed"]
    assert [c["change"] for c in read_env["policy_changes"]] == ["monitor"]
    assert [m["name"] for m in read_env["hypothetical_monitor_matches"]] == ["Audit sensitive file reads"]
    assert exfil["hypothetical_decision"] == "REQUIRE_APPROVAL"
    change = next(c for c in exfil["policy_changes"] if c["policy_id"] == block)
    assert change["change"] == "outcome_changed" and "AUDIT" in change["detail"]


def test_draft_policies_on_an_empty_base_and_downstream_caveat(client, seeded_org):
    sid = _exfil(client, seeded_org)
    cf = _cf(client, seeded_org, sid, base="none", add_policies=[DENY_READS])
    assert [s["hypothetical_decision"] for s in cf["steps"]] == ["DENY", "DENY", "ALLOW"]
    assert cf["summary"]["transitions"] == {"AUDIT→DENY": 1, "ALLOW→DENY": 1, "DENY→ALLOW": 1}
    assert [s["after_hypothetical_block"] for s in cf["steps"]] == [False, True, True]
    first = cf["steps"][0]
    assert first["hypothetical_matches"][0]["draft"] is True and first["hypothetical_matches"][0]["policy_id"] == "draft-1"
    assert first["evidence"] == [{"field": "tool.name", "present": True, "value": "Read", "policies": ["Deny all reads"]}]
    assert {c["change"] for c in first["policy_changes"]} == {"removed", "newly_matches"}
    assert cf["policy_set"]["policies"] == [{"id": "draft-1", "name": "Deny all reads", "version": 1, "outcome": "DENY",
                                             "mode": "enforce", "enabled": True, "priority": 100, "source": "draft",
                                             "changes": ["added"]}]
    assert cf["policy_set"]["base"] == "none" and cf["policy_set"]["default_decision"] == "ALLOW"

    deny_by_default = client.post(f"{API}/counterfactual", headers=seeded_org.user_headers, json={
        "session_id": sid, "policy_set": {"base": "none"}, "default_decision": "DENY"}).json()
    assert {s["hypothetical_decision"] for s in deny_by_default["steps"]} == {"DENY"}
    assert any("No enabled policy" in w for w in deny_by_default["policy_set"]["warnings"])


def test_observed_decisions_explain_that_nothing_could_have_been_prevented(client, seeded_org):
    # POST /events (not /decide): the request is recorded as observed, so a DENY is hypothetical only.
    post_events(client, seeded_org.api_headers, tool_requested("Read", {"file_path": "/work/app/main.py"}, session="obs"))
    sid = client.get("/api/v1/sessions", headers=seeded_org.user_headers).json()["items"][0]["id"]
    step = _cf(client, seeded_org, sid, add_policies=[DENY_READS])["steps"][0]
    assert step["original_enforcement"] == "observed" and step["hypothetical_decision"] == "DENY"
    assert "could not have prevented it" in step["explanation"]


def test_decisions_without_a_recorded_snapshot_are_not_evaluated(client, seeded_org, db):
    sid = _exfil(client, seeded_org)
    row = db.scalars(select(PolicyDecision).where(PolicyDecision.session_id == sid)
                     .order_by(PolicyDecision.evaluated_at)).first()
    row.input_snapshot = {}  # e.g. a decision recorded before snapshots existed
    db.commit()
    cf = _cf(client, seeded_org, sid, base="none", add_policies=[DENY_READS])
    assert cf["summary"]["evaluated"] == 2 and cf["not_evaluable_count"] == 1
    missing = cf["not_evaluable"][0]
    assert missing["policy_decision_id"] == row.id and "no input snapshot" in missing["reason"]
    assert row.id not in {s["decision_id"] for s in cf["steps"]}


def test_invalid_policy_sets_are_rejected_with_reasons(client, seeded_org):
    sid = _exfil(client, seeded_org)
    block = _policy_id(client, seeded_org, "Block credential exfiltration")
    bad_field = _cf(client, seeded_org, sid, expect=422, add_policies=[
        {"name": "Typo", "outcome": "DENY", "conditions": {"field": "tool.categry", "op": "eq", "value": "http"}}])
    assert any(e.startswith("add_policies[0]") and "tool.category" in e for e in bad_field["error"]["details"]["errors"])
    secret = _cf(client, seeded_org, sid, expect=422, add_policies=[
        {"name": "Leaky", "outcome": "DENY", "conditions": {"field": "arguments.*", "op": "contains", "value": GITHUB_TOKEN}}])
    assert any("looks like a credential" in e for e in secret["error"]["details"]["errors"])
    assert GITHUB_TOKEN not in json.dumps(secret)
    _cf(client, seeded_org, sid, expect=422, base="none", disable_policy_ids=[block])
    _cf(client, seeded_org, sid, expect=422, disable_policy_ids=[block], overrides={block: {"mode": "monitor"}})
    restrict = _cf(client, seeded_org, sid, expect=422, overrides={block: {"outcome": "RESTRICT"}})
    assert "defines no restrictions" in restrict["error"]["details"]["errors"][0]
    _cf(client, seeded_org, sid, expect=422, overrides={block: {"outcome": "MAYBE"}})
    _cf(client, seeded_org, sid, expect=404, disable_policy_ids=["pol_does_not_exist"])
    smuggled = client.post(f"{API}/counterfactual", headers=seeded_org.user_headers,
                           json={"session_id": sid, "decision": "ALLOW"})
    assert smuggled.status_code == 422


# ----------------------------------------------------------------------------- isolation and permissions


def test_other_organisations_cannot_replay_or_reference_policies(client, seeded_org, other_org, db):
    sid = _exfil(client, seeded_org)
    assert client.get(f"{API}/sessions/{sid}", headers=other_org.user_headers).status_code == 404
    assert client.post(f"{API}/counterfactual", json={"session_id": sid},
                       headers=other_org.user_headers).status_code == 404

    from app.services.seed import seed_security_defaults

    seed_security_defaults(db, other_org.org_id)
    db.commit()
    foreign = db.scalar(select(SecurityPolicy.id).where(SecurityPolicy.organization_id == other_org.org_id))
    _cf(client, seeded_org, sid, expect=404, disable_policy_ids=[foreign])
    _cf(client, seeded_org, sid, expect=404, overrides={foreign: {"enabled": False}})
    _cf(client, seeded_org, sid, expect=404, add_policies=[{**DENY_READS, "id": foreign}])
    # A decision id from another organisation never focuses anything.
    exfil_session(client, other_org.api_headers)
    other_sid = client.get("/api/v1/sessions", headers=other_org.user_headers).json()["items"][0]["id"]
    other_dec = client.get(f"{API}/sessions/{other_sid}", headers=other_org.user_headers).json()["steps"][1]["refs"]["policy_decision_id"]
    assert client.get(f"{API}/sessions/{sid}", params={"decision_id": other_dec},
                      headers=seeded_org.user_headers).json()["focus_index"] is None


def test_permissions_read_scope_required_and_viewers_allowed(client, make_org):
    ingest_only = make_org("Initech", scopes=["ingest"])
    assert client.get(f"{API}/sessions/asn_x", headers=ingest_only.api_headers).status_code == 403
    assert client.post(f"{API}/counterfactual", json={"session_id": "asn_x"},
                       headers=ingest_only.api_headers).status_code == 403
    assert client.get(f"{API}/sessions/asn_x").status_code == 401

    viewer = make_org("Viewer Co", role="viewer")
    post_events(client, viewer.api_headers, event("session.started", session="v-1"))
    sid = client.get("/api/v1/sessions", headers=viewer.user_headers).json()["items"][0]["id"]
    assert client.get(f"{API}/sessions/{sid}", headers=viewer.user_headers).status_code == 200
    assert client.post(f"{API}/counterfactual", json={"session_id": sid}, headers=viewer.user_headers).status_code == 200
    assert client.get(f"{API}/sessions/{sid}", headers=viewer.api_headers).status_code == 200  # read-scoped key
