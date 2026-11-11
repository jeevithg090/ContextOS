"""Overview (security command centre): posture, series, lists, nav counts, onboarding, simulated
rows, honest enforcement wording, isolation and permissions.

Data comes from the real ingestion pipeline (POST /events, POST /decide, and ``ingest_event`` with
``is_simulation=True`` for Simulation Lab traffic). Timestamps of pipeline rows are moved only to
test time bucketing.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.core.security import generate_api_key
from app.core.timeutil import utcnow
from app.domain.enums import Role
from app.events.envelope import EventEnvelope
from app.models import (
    Agent,
    ApiKey,
    Approval,
    IngestedEvent,
    Integration,
    PolicyDecision,
    SecurityFinding,
    SimulationRun,
)
from app.services.audit import append_audit
from app.services.ingestion import IngestContext, ingest_event
from app.services.overview_service_series import window_for
from tests.integration.agents_support import MALICIOUS_README, benign_session, exfil_session
from tests.integration.ingestion_support import GITHUB_TOKEN, decide, event, post_events, tool_requested

BASE = "/api/v1/overview"
WEBHOOK = {"url": "https://hooks.webhook.site/9f1c", "method": "POST", "body": "build=green"}
DECLARED = {"tools": [{"name": "Read"}, {"name": "WebFetch"}]}  # WebFetch: a declared outbound channel


def _overview(client: TestClient, headers: dict, expect: int = 200, **params) -> dict:
    response = client.get(BASE, headers=headers, params=params)
    assert response.status_code == expect, response.text
    return response.json()


def _nav(client: TestClient, headers: dict, expect: int = 200) -> dict:
    response = client.get(f"{BASE}/nav-counts", headers=headers)
    assert response.status_code == expect, response.text
    return response.json()


def _register_coder(client: TestClient, org) -> None:
    response = client.post("/api/v1/agents", json={"name": "coder", "declared_capabilities": DECLARED},
                           headers=org.user_headers)
    assert response.status_code == 201, response.text


def _simulated(db: Session, org_id: str) -> None:
    ctx = IngestContext(org_id=org_id, actor_type="system", is_simulation=True)
    for env in (
        event("session.started", agent="sim-agent", session="sim-1"),
        event("context.ingested", agent="sim-agent", session="sim-1",
              source={"type": "web", "identifier": "https://sim.example.net/page"}, content=MALICIOUS_README),
    ):
        ingest_event(db, ctx, EventEnvelope.model_validate(env))
    db.commit()


# ----------------------------------------------------------------------------- empty / onboarding


def test_empty_org_returns_zeros_and_onboarding(client, org):
    data = _overview(client, org.user_headers)
    assert data["window"] == "24h" and data["bucket"] == "hour" and data["include_simulated"] is False
    posture = data["posture"]
    assert posture["agents_total"] == 0 and posture["sessions_active"] == 0 and posture["trifecta_sessions"] == 0
    assert posture["decisions_total"] == 0 and posture["blocked_actions"] == 0
    assert posture["enforcement_coverage"] == {"total": 0, "enforced": 0, "advisory": 0, "observed": 0, "share": None}
    assert set(posture["sources_by_trust"]) == {"TRUSTED", "APPROVED", "EXTERNAL", "UNKNOWN", "SUSPICIOUS", "BLOCKED"}
    assert set(posture["open_findings_by_severity"]) == {"critical", "high", "medium", "low", "info"}
    assert len(data["series"]["events"]) == 24 and all(p["live"] == 0 for p in data["series"]["events"])
    assert data["top_risky_agents"] == [] and data["recent_blocked_or_paused"] == [] and data["integrations"] == []
    # The fixture creates an API key; nothing has reported yet.
    assert data["onboarding"] == {"has_agents": False, "has_api_key": True, "has_events": False, "has_simulations": False}
    assert _nav(client, org.user_headers) == {"pending_approvals": 0, "open_incidents": 0, "open_findings": 0}


def test_window_sizes_and_validation(client, org):
    assert len(_overview(client, org.user_headers, window="7d")["series"]["findings_by_severity"]) == 7
    month = _overview(client, org.user_headers, window="30d")
    assert month["bucket"] == "day" and len(month["series"]["decisions_by_outcome"]) == 30
    _overview(client, org.user_headers, expect=422, window="90d")


def test_onboarding_ignores_revoked_keys_and_tracks_simulations(client, org, db):
    key = db.get(ApiKey, org.api_key_id)
    key.revoked_at = utcnow()
    db.add(SimulationRun(id=new_id("simulation_run"), organization_id=org.org_id, scenario_id="injection-readme",
                         scenario_name="Injected README", status="completed"))
    db.commit()
    onboarding = _overview(client, org.user_headers)["onboarding"]
    assert onboarding["has_api_key"] is False and onboarding["has_simulations"] is True


# ----------------------------------------------------------------------------- posture from the pipeline


def test_posture_reflects_pipeline_activity(client, seeded_org, db):
    h = seeded_org.api_headers
    _register_coder(client, seeded_org)
    exfil = exfil_session(client, h)
    benign_session(client, h, session="sess-benign")
    approval = decide(client, h, tool_requested("WebFetch", WEBHOOK, session="sess-approval"))
    assert exfil["exfil"]["decision"] == "DENY" and approval["decision"] == "REQUIRE_APPROVAL"

    response = client.get(BASE, headers=seeded_org.user_headers)
    assert response.status_code == 200
    assert GITHUB_TOKEN not in response.text  # nothing raw leaves the API
    data = response.json()
    posture = data["posture"]
    db.rollback()

    assert posture["agents_total"] == 1 and posture["agents_active"] == 1
    assert posture["sessions_active"] == 2  # the benign session ended
    assert posture["trifecta_sessions"] == 1
    assert posture["pending_approvals"] == 1
    decisions = db.scalar(select(func.count(PolicyDecision.id)).where(PolicyDecision.organization_id == seeded_org.org_id))
    assert posture["decisions_total"] == decisions == sum(posture["decisions_by_outcome"].values())
    assert posture["decisions_by_outcome"]["DENY"] >= 1 and posture["decisions_by_outcome"]["REQUIRE_APPROVAL"] == 1
    assert posture["enforcement_coverage"]["enforced"] == decisions and posture["enforcement_coverage"]["share"] == 1.0
    assert posture["blocked_actions"] == posture["decisions_by_outcome"]["DENY"]

    open_rows = dict(db.execute(select(SecurityFinding.severity, func.count(SecurityFinding.id)).where(
        SecurityFinding.organization_id == seeded_org.org_id, SecurityFinding.status.in_(["open", "acknowledged"]))
        .group_by(SecurityFinding.severity)).tuples().all())
    assert {k: v for k, v in posture["open_findings_by_severity"].items() if v} == open_rows
    assert posture["open_findings_total"] == sum(open_rows.values())
    assert posture["open_incidents"] >= 1  # the credential flow is critical and opens an incident
    assert sum(posture["sources_by_trust"].values()) >= 1

    events = db.scalar(select(func.count(IngestedEvent.id)).where(IngestedEvent.organization_id == seeded_org.org_id))
    assert sum(p["live"] for p in data["series"]["events"]) == events
    assert sum(p["DENY"] for p in data["series"]["decisions_by_outcome"]) == posture["decisions_by_outcome"]["DENY"]
    findings_total = db.scalar(select(func.count(SecurityFinding.id)).where(
        SecurityFinding.organization_id == seeded_org.org_id, SecurityFinding.status != "false_positive"))
    assert sum(sum(v for k, v in p.items() if k != "t") for p in data["series"]["findings_by_severity"]) == findings_total


def test_lists_explain_risk_attention_and_blocked_calls(client, seeded_org):
    h = seeded_org.api_headers
    _register_coder(client, seeded_org)
    exfil = exfil_session(client, h)
    approval = decide(client, h, tool_requested("WebFetch", WEBHOOK, session="sess-approval"))
    data = _overview(client, seeded_org.user_headers)

    agent = data["top_risky_agents"][0]
    assert agent["name"] == "coder" and agent["risk_score"] > 0 and agent["trifecta"] is True
    assert agent["reason"] and agent["reason_detail"] and agent["session_id"]
    assert agent["risk_level"] in {"low", "medium", "high", "critical"} and agent["open_findings"] >= 1

    attention = data["attention"]
    assert [a["id"] for a in attention["pending_approvals"]] == [approval["approval_id"]]
    assert attention["pending_approvals"][0]["tool_name"] == "WebFetch"
    assert attention["pending_approvals"][0]["seconds_remaining"] > 0
    severities = [f["severity"] for f in attention["critical_findings"]]
    assert severities and severities[0] == "critical" and set(severities) <= {"critical", "high"}
    assert attention["open_incidents"] and attention["open_incidents"][0]["number"] >= 1
    assert data["recent_findings"] and all(not f["is_simulation"] for f in data["recent_findings"])

    blocked = {b["invocation_id"]: b for b in data["recent_blocked_or_paused"]}
    denied = blocked[exfil["exfil"]["tool_invocation_id"]]
    assert (denied["decision"], denied["enforcement"], denied["outcome"]) == ("DENY", "enforced", "Blocked before it ran")
    assert denied["agent"]["name"] == "coder" and denied["tool"]["name"] == "WebFetch" and denied["action"]
    assert GITHUB_TOKEN not in str(denied)
    paused = blocked[approval["tool_invocation_id"]]
    assert paused["decision"] == "REQUIRE_APPROVAL" and paused["outcome"] == "Paused, waiting for a human"
    assert paused["approval_id"] == approval["approval_id"]

    (integration,) = data["integrations"]
    assert (integration["kind"], integration["status"], integration["enforcement_capable"]) == ("claude_code", "connected", True)
    assert integration["decision_count"] >= 3 and integration["event_count"] >= integration["decision_count"]
    assert data["recent_activity"] and data["recent_activity"][0]["seq"] > data["recent_activity"][-1]["seq"]
    assert data["onboarding"]["has_agents"] is True and data["onboarding"]["has_events"] is True


def test_observed_denials_are_not_claimed_as_blocked(client, seeded_org):
    """A tool request reported through POST /events (after the fact) is evaluated but nothing could
    be prevented: it must not count as a blocked action and must say so."""
    results = post_events(client, seeded_org.api_headers, tool_requested("Bash", {"command": "rm -rf ~/"}, session="obs"))
    invocation_id = results[0]["refs"]["tool_invocation_id"]
    data = _overview(client, seeded_org.user_headers)
    posture = data["posture"]
    assert posture["decisions_by_outcome"]["DENY"] == 1 and posture["blocked_actions"] == 0
    assert posture["enforcement_coverage"]["observed"] == 1 and posture["enforcement_coverage"]["share"] == 0.0
    (row,) = [b for b in data["recent_blocked_or_paused"] if b["invocation_id"] == invocation_id]
    assert row["enforcement"] == "observed" and "nothing was prevented" in row["outcome"]
    assert "Blocked" not in row["outcome"]


def test_advisory_denials_are_worded_as_advisory(client, seeded_org):
    response = decide(client, seeded_org.api_headers,
                      tool_requested("Bash", {"command": "rm -rf ~/"}, integration="langgraph", session="adv"))
    assert (response["decision"], response["enforcement"]) == ("DENY", "advisory")
    data = _overview(client, seeded_org.user_headers)
    assert data["posture"]["blocked_actions"] == 0 and data["posture"]["enforcement_coverage"]["advisory"] == 1
    (row,) = data["recent_blocked_or_paused"]
    assert row["outcome"] == "Denied; this integration may not have honoured the decision"
    (integration,) = data["integrations"]
    assert integration["kind"] == "langgraph" and integration["enforcement_capable"] is False


def test_stale_integration_and_overdue_approvals(client, seeded_org, db):
    approval = decide(client, seeded_org.api_headers, tool_requested("WebFetch", WEBHOOK))
    db.rollback()
    db.get(Approval, approval["approval_id"]).expires_at = utcnow() - timedelta(seconds=5)
    integration = db.scalar(select(Integration).where(Integration.organization_id == seeded_org.org_id))
    integration.last_event_at = utcnow() - timedelta(days=2)
    db.commit()
    data = _overview(client, seeded_org.user_headers)
    assert data["posture"]["pending_approvals"] == 0 and data["attention"]["pending_approvals"] == []
    assert _nav(client, seeded_org.user_headers)["pending_approvals"] == 0
    assert data["integrations"][0]["status"] == "stale"


# ----------------------------------------------------------------------------- series bucketing


def test_events_are_bucketed_by_server_receive_time(client, seeded_org, db):
    benign_session(client, seeded_org.api_headers)
    db.rollback()
    rows = list(db.scalars(select(IngestedEvent).where(IngestedEvent.organization_id == seeded_org.org_id)
                           .order_by(IngestedEvent.sequence)))
    assert len(rows) >= 4
    window = window_for("7d", utcnow())
    rows[0].received_at = window.edges[0] + timedelta(hours=3)  # first day
    rows[1].received_at = window.edges[2] + timedelta(minutes=1)  # third day
    rows[2].received_at = window.edges[0] - timedelta(seconds=1)  # just before the window
    db.commit()
    events = _overview(client, seeded_org.user_headers, window="7d")["series"]["events"]
    counts = [p["live"] for p in events]
    assert counts[0] == 1 and counts[2] == 1
    assert sum(counts) == len(rows) - 1  # the out-of-window event is not counted
    assert events[0]["t"].startswith(window.edges[0].date().isoformat())


# ----------------------------------------------------------------------------- simulated rows


def test_simulated_rows_are_excluded_by_default_and_labelled_when_included(client, org, db):
    _simulated(db, org.org_id)
    default = _overview(client, org.user_headers)
    assert default["posture"]["agents_total"] == 0 and default["posture"]["open_findings_total"] == 0
    assert sum(default["posture"]["sources_by_trust"].values()) == 0
    assert default["simulated"]["events"] == 2 and default["simulated"]["findings"] >= 1
    assert default["onboarding"]["has_agents"] is False and default["onboarding"]["has_events"] is False

    included = _overview(client, org.user_headers, include_simulated="true")
    assert included["include_simulated"] is True and included["posture"]["agents_total"] == 1
    assert sum(p["simulated"] for p in included["series"]["events"]) == 2
    assert all(p["live"] == 0 for p in included["series"]["events"])
    assert included["recent_findings"] and all(f["is_simulation"] for f in included["recent_findings"])
    assert sum(included["posture"]["sources_by_trust"].values()) == 1
    # Sidebar badges count only real work, and simulations never mark an integration connected.
    assert _nav(client, org.user_headers)["open_findings"] == 0
    assert included["integrations"] == []


# ----------------------------------------------------------------------------- redaction


def test_recent_activity_details_are_redacted(client, org, db):
    append_audit(db, org.org_id, action="settings.updated", actor_type="user", actor_id=org.user_id,
                 target_type="organization", target_id=org.org_id,
                 details={"note": f"rotated token {GITHUB_TOKEN}", "nested": {"api_key": "plain-value-123"}})
    db.commit()
    response = client.get(BASE, headers=org.user_headers)
    assert GITHUB_TOKEN not in response.text and "plain-value-123" not in response.text
    entry = response.json()["recent_activity"][0]
    assert entry["action"] == "settings.updated" and entry["actor_label"] == "Acme Owner"


# ----------------------------------------------------------------------------- isolation / permissions


def test_other_org_sees_nothing(client, seeded_org, other_org):
    exfil_session(client, seeded_org.api_headers)
    decide(client, seeded_org.api_headers, tool_requested("WebFetch", WEBHOOK, session="sess-approval"))
    assert _nav(client, seeded_org.user_headers)["open_findings"] >= 1

    data = _overview(client, other_org.user_headers, include_simulated="true")
    posture = data["posture"]
    assert posture["agents_total"] == 0 and posture["decisions_total"] == 0 and posture["open_findings_total"] == 0
    assert posture["pending_approvals"] == 0 and posture["open_incidents"] == 0 and posture["trifecta_sessions"] == 0
    assert sum(posture["sources_by_trust"].values()) == 0
    assert sum(p["live"] + p["simulated"] for p in data["series"]["events"]) == 0
    for key in ("top_risky_agents", "recent_findings", "recent_blocked_or_paused", "integrations"):
        assert data[key] == [], key
    assert all(v == [] for v in data["attention"].values())
    assert all(a["action"] != "tool.denied" for a in data["recent_activity"])
    assert _nav(client, other_org.user_headers) == {"pending_approvals": 0, "open_incidents": 0, "open_findings": 0}
    # The org header cannot be used to read another organisation's overview.
    headers = {**other_org.user_headers, "X-ContextOS-Org": seeded_org.org_id}
    assert client.get(BASE, headers=headers).status_code == 403


def test_permissions(client, make_org, db):
    viewer = make_org("Viewers", role=Role.VIEWER)
    _overview(client, viewer.user_headers)
    _overview(client, viewer.api_headers)  # read-scoped key
    ingest_only = make_org("Ingesters", scopes=["ingest", "decide"])
    _overview(client, ingest_only.api_headers, expect=403)
    _nav(client, ingest_only.api_headers, expect=403)
    assert client.get(BASE).status_code == 401

    post_events(client, viewer.api_headers, event("session.started", agent="bound-agent", session="b-1"))
    db.rollback()
    agent = db.scalar(select(Agent).where(Agent.organization_id == viewer.org_id, Agent.name == "bound-agent"))
    raw, prefix, key_hash = generate_api_key()
    db.add(ApiKey(id=new_id("api_key"), organization_id=viewer.org_id, name="bound", prefix=prefix, key_hash=key_hash,
                  scopes=["read"], agent_id=agent.id))
    db.commit()
    bound = {"Authorization": f"Bearer {raw}"}
    _overview(client, bound, expect=403)
    _nav(client, bound, expect=403)
