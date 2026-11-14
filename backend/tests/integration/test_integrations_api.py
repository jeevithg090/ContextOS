"""GET /integrations and GET /integrations/{kind}/setup.

Traffic is produced by the real pipeline (POST /events, POST /decide, ``ingest_event`` for Simulation
Lab traffic) so health and counts come from persisted rows.
"""

from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import select

from app.core.timeutil import utcnow
from app.domain.enums import Role
from app.events.envelope import EventEnvelope
from app.models import Integration, Organization
from app.services.ingestion import IngestContext, ingest_event
from app.services.integrations_service import health_of, server_url_for
from tests.integration.agents_support import exfil_session
from tests.integration.ingestion_support import decide, event, post_events, tool_requested

URL = "/api/v1/integrations"
SUPPORTED = {"claude_code", "mcp_gateway", "openai_codex", "python_sdk"}
PLANNED = {"cursor", "langgraph", "crewai", "openai_agents_sdk", "anthropic_agent_sdk"}


def _get(client, headers):
    response = client.get(URL, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _connected(body, kind):
    return next(i for i in body["connected"] if i["kind"] == kind)


def _catalog(body, kind):
    return next(c for c in body["catalog"] if c["kind"] == kind)


# ----------------------------------------------------------------------------- catalog honesty


def test_empty_org_lists_catalog_and_nothing_connected(client, org):
    body = _get(client, org.user_headers)
    assert body["connected"] == []
    assert body["stale_after_minutes"] == 24 * 60 and body["stale_after_hours"] == 24
    kinds = {c["kind"] for c in body["catalog"]}
    assert kinds == SUPPORTED | PLANNED
    for entry in body["catalog"]:
        assert entry["health"] == "never_seen"
        assert entry["last_event_at"] is None


def test_capability_matrix_is_honest(client, org):
    body = _get(client, org.user_headers)
    for kind in SUPPORTED:
        entry = _catalog(body, kind)
        assert entry["status"] == "supported"
        assert entry["best_enforcement"] == "enforced"
        assert entry["limitations"], kind
        assert entry["docs_path"]
        # Monitoring never claims to block anything.
        assert {m["mode"] for m in entry["monitoring"]} == {"observed"}
        assert any(e["mode"] == "enforced" for e in entry["enforcement"])
        assert set(entry["api_key_scopes"]) == {"ingest", "decide"}

    claude = _catalog(body, "claude_code")
    monitored = " ".join(m["name"] for m in claude["monitoring"])
    for hook in ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "SessionEnd", "SubagentStop"):
        assert hook in monitored
    assert {e["name"] for e in claude["enforcement"]} == {"PreToolUse deny", "PreToolUse ask"}
    limits = " ".join(claude["limitations"])
    assert "reasoning" in limits and "never answers \"allow\"" in limits and "PreToolUse hook" in limits

    codex = _catalog(body, "openai_codex")
    monitored = " ".join(m["name"] for m in codex["monitoring"])
    for hook in ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "SessionEnd", "SubagentStop"):
        assert hook in monitored
    assert {e["name"] for e in codex["enforcement"]} == {"PreToolUse block", "Approvals and restrictions"}
    limits = " ".join(codex["limitations"])
    for gap in ("web search", "write_stdin", "untrusted", "failed calls", "never grants approval", "fail mode"):
        assert gap in limits, gap
    assert codex["docs_path"] == "docs/integrations/codex.md"

    gateway = _catalog(body, "mcp_gateway")
    assert any(e["name"] == "tools/call deny" for e in gateway["enforcement"])
    assert any("started through the gateway" in lim for lim in gateway["limitations"])

    sdk = _catalog(body, "python_sdk")
    modes = {e["name"]: e["mode"] for e in sdk["enforcement"]}
    assert modes["guard()-wrapped tools"] == "enforced"
    assert modes["client.decide() without guard()"] == "advisory"

    for kind in PLANNED:
        entry = _catalog(body, kind)
        assert entry["status"] == "planned"
        assert entry["best_enforcement"] is None
        assert entry["monitoring"] == [] and entry["enforcement"] == []  # nothing is claimed
        assert entry["integration_surface"] and entry["available_today"]
        assert entry["interim_kind"] in SUPPORTED


# ----------------------------------------------------------------------------- health and evidence


def test_claude_code_traffic_marks_integration_connected_with_counts(client, seeded_org):
    exfil_session(client, seeded_org.api_headers)
    body = _get(client, seeded_org.user_headers)
    row = _connected(body, "claude_code")
    assert row["health"] == "connected"
    assert row["supported"] is True and row["best_enforcement"] == "enforced"
    assert row["display_name"] == "Claude Code"
    assert row["event_count"] == 6 and row["decision_count"] == 3  # 1 start, 3 decisions, 2 results
    assert row["events_24h"] == row["event_count"]
    assert row["decisions"]["enforced"] == 3 and row["decisions"]["advisory"] == 0
    assert row["agent_count"] == 1
    assert row["last_event_at"] is not None
    catalog = _catalog(body, "claude_code")
    assert catalog["health"] == "connected" and catalog["last_event_at"] == row["last_event_at"]
    assert _catalog(body, "mcp_gateway")["health"] == "never_seen"


def test_observed_tool_requests_count_as_observed_decisions(client, seeded_org):
    post_events(client, seeded_org.api_headers,
                tool_requested("Read", {"file_path": "/work/app/src/a.py"}, integration="mcp_gateway"))
    row = _connected(_get(client, seeded_org.user_headers), "mcp_gateway")
    assert row["decisions"] == {"enforced": 0, "advisory": 0, "observed": 1}
    assert row["decision_count"] == 0  # only /decide requests count as decisions asked before the tool ran


def test_uncatalogued_integration_is_listed_as_advisory(client, seeded_org):
    decide(client, seeded_org.api_headers, tool_requested("Read", {"file_path": "/tmp/x"}, integration="homegrown"))
    decide(client, seeded_org.api_headers, tool_requested("Read", {"file_path": "/tmp/y"}, integration=""))
    body = _get(client, seeded_org.user_headers)
    home = _connected(body, "homegrown")
    assert home["supported"] is False and home["best_enforcement"] == "advisory"
    assert home["decisions"]["advisory"] == 1 and home["decisions"]["enforced"] == 0
    custom = _connected(body, "custom")
    assert custom["display_name"] == "Custom (no integration name)"
    assert custom["decisions"]["advisory"] == 1


def test_stale_and_never_seen_health(client, org, db):
    post_events(client, org.api_headers, event("session.started", integration="python_sdk"))
    row = db.scalar(select(Integration).where(Integration.organization_id == org.org_id,
                                              Integration.kind == "python_sdk"))
    row.last_event_at = utcnow() - timedelta(hours=25)
    db.commit()
    entry = _connected(_get(client, org.user_headers), "python_sdk")
    assert entry["health"] == "stale" and "contextos doctor" in entry["health_detail"]
    assert "24 hours" in entry["health_detail"]

    now = utcnow()
    assert health_of(None, now)[0] == "never_seen"
    assert health_of(now - timedelta(minutes=16), now)[0] == "connected"  # idle for minutes is not stale
    assert health_of(now - timedelta(hours=23, minutes=59), now)[0] == "connected"
    assert health_of(now - timedelta(hours=24, seconds=1), now)[0] == "stale"


def test_integrations_page_and_overview_share_one_staleness_rule(client, org, db):
    post_events(client, org.api_headers, event("session.started", integration="python_sdk"))
    row = db.scalar(select(Integration).where(Integration.organization_id == org.org_id,
                                              Integration.kind == "python_sdk"))
    for age, expected in ((timedelta(hours=2), "connected"), (timedelta(hours=30), "stale")):
        row.last_event_at = utcnow() - age
        db.commit()
        page = _connected(_get(client, org.user_headers), "python_sdk")["health"]
        overview = client.get("/api/v1/overview", headers=org.user_headers).json()["integrations"]
        assert page == expected
        assert next(i for i in overview if i["kind"] == "python_sdk")["status"] == expected


def test_connected_sorted_by_health_then_recency(client, org, db):
    post_events(client, org.api_headers, event("session.started", integration="python_sdk", session="a"))
    post_events(client, org.api_headers, event("session.started", integration="mcp_gateway", session="b"))
    row = db.scalar(select(Integration).where(Integration.organization_id == org.org_id,
                                              Integration.kind == "mcp_gateway"))
    row.last_event_at = utcnow() - timedelta(hours=2)
    db.commit()
    kinds = [i["kind"] for i in _get(client, org.user_headers)["connected"]]
    assert kinds == ["python_sdk", "mcp_gateway"]


def test_simulation_traffic_never_marks_an_integration_connected(client, org, db):
    ctx = IngestContext(org_id=org.org_id, actor_type="system", is_simulation=True)
    ingest_event(db, ctx, EventEnvelope.model_validate(event("session.started", integration="claude_code")))
    db.commit()
    assert _get(client, org.user_headers)["connected"] == []


# ----------------------------------------------------------------------------- isolation and permissions


def test_other_org_sees_none_of_this_orgs_integrations(client, seeded_org, other_org):
    exfil_session(client, seeded_org.api_headers)
    body = _get(client, other_org.user_headers)
    assert body["connected"] == []
    assert all(c["health"] == "never_seen" for c in body["catalog"])
    # The other org's own traffic is counted only for itself.
    post_events(client, other_org.api_headers, event("session.started", integration="claude_code"))
    mine = _connected(_get(client, other_org.user_headers), "claude_code")
    assert mine["event_count"] == 1 and mine["decisions"]["enforced"] == 0


def test_permissions(client, make_org):
    viewer = make_org("Viewers", role=Role.VIEWER)
    assert client.get(URL, headers=viewer.user_headers).status_code == 200
    assert client.get(URL, headers=viewer.api_headers).status_code == 200  # key has the read scope
    assert client.get(URL).status_code == 401
    ingest_only = make_org("Ingest only", scopes=["ingest", "decide"])
    denied = client.get(URL, headers=ingest_only.api_headers)
    assert denied.status_code == 403 and denied.json()["error"]["code"] == "forbidden"
    assert client.get(f"{URL}/claude_code/setup", headers=ingest_only.api_headers).status_code == 403


# ----------------------------------------------------------------------------- setup guides


def _setup(client, org, kind, headers=None):
    response = client.get(f"{URL}/{kind}/setup", headers=headers or org.user_headers)
    assert response.status_code == 200, response.text
    return response.json()


def _commands(guide):
    return [c for step in guide["steps"] for c in step["commands"]]


def test_claude_code_setup_uses_request_url_and_never_a_real_key(client, org):
    guide = _setup(client, org, "claude_code")
    assert guide["status"] == "supported" and guide["server_url"] == "http://testserver"
    codes = "\n".join(c["code"] for c in _commands(guide))
    assert "pip install -e sdk" in codes
    assert "contextos init --url http://testserver --api-key ctxk_your_key --claude-code" in codes
    assert "contextos doctor" in codes
    assert org.api_key not in json.dumps(guide)
    hooks = json.loads(next(c["code"] for c in _commands(guide) if c["language"] == "json"))["hooks"]
    assert hooks["PreToolUse"][0]["hooks"][0]["timeout"] == 60
    assert set(hooks) >= {"PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd"}
    assert guide["steps"][0]["link"]["href"] == "/settings?tab=api-keys"
    scopes = {s["scope"]: s["required"] for s in guide["api_key_scopes"]}
    assert scopes == {"ingest": True, "decide": True, "read": False}
    assert guide["notes"] and guide["verification"]


def test_mcp_gateway_setup_has_valid_mcp_json_snippet(client, org):
    guide = _setup(client, org, "mcp_gateway")
    codes = _commands(guide)
    assert any("pip install -e 'sdk[mcp]'" in c["code"] for c in codes)
    snippet = next(c for c in codes if c["title"] == ".mcp.json")
    server = json.loads(snippet["code"])["mcpServers"]["toolbox"]
    assert server["command"] == "contextos" and server["args"][:3] == ["mcp-gateway", "--name", "toolbox"]
    assert server["env"] == {"CONTEXTOS_URL": "http://testserver"}  # the key stays in ~/.contextos


def test_python_sdk_setup_shows_guard_example(client, org):
    guide = _setup(client, org, "python_sdk")
    python = next(c for c in _commands(guide) if c["language"] == "python")
    assert "@guard(" in python["code"] and "ToolDenied" in python["code"]
    compile(python["code"], "agent.py", "exec")  # the example is valid Python


def test_codex_setup_installs_hooks_and_asks_for_trust_in_codex(client, org):
    guide = _setup(client, org, "openai_codex")
    assert guide["status"] == "supported" and guide["interim_kind"] is None
    codes = "\n".join(c["code"] for c in _commands(guide))
    assert "contextos init --url http://testserver --api-key ctxk_your_key --codex" in codes
    assert org.api_key not in json.dumps(guide)
    trust = next(s for s in guide["steps"] if s["title"] == "Trust the hooks in Codex")
    assert "/hooks" in trust["description"] and any(c["code"] == "/hooks" for c in trust["commands"])
    hooks = json.loads(next(c["code"] for c in _commands(guide) if c["language"] == "json"))["hooks"]
    assert hooks["PreToolUse"][0]["matcher"] == "*"
    assert hooks["PreToolUse"][0]["hooks"][0] == {"type": "command", "command": "contextos codex-hook PreToolUse",
                                                   "timeout": 60}
    assert hooks["SessionEnd"][0]["hooks"][0]["timeout"] == 3  # Codex clamps SessionEnd hooks to 3 s
    assert set(hooks) == {"PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SubagentStop",
                          "SessionEnd"}
    gateway = next(c for c in _commands(guide) if c["language"] == "toml")
    assert "[mcp_servers.toolbox]" in gateway["code"] and "mcp-gateway" in gateway["code"]
    assert guide["docs_path"] == "docs/integrations/codex.md"
    assert "Enforced" in guide["verification"]
    assert {s["scope"]: s["required"] for s in guide["api_key_scopes"]} == {"ingest": True, "decide": True,
                                                                             "read": False}


def test_codex_setup_explains_that_ask_blocks(client, org, db):
    org_row = db.get(Organization, org.org_id)
    org_row.settings = {**(org_row.settings or {}), "fail_mode": "ask"}
    db.commit()
    guide = _setup(client, org, "openai_codex")
    step = next(s for s in guide["steps"] if s["title"].startswith("Apply your organisation's fail mode"))
    assert "cannot ask" in step["description"] and "'closed'" in step["description"]
    assert any(c["code"] == "export CONTEXTOS_CODEX_FAIL_MODE=ask" for c in step["commands"])


def test_planned_setup_returns_labelled_interim_path(client, org):
    cursor = _setup(client, org, "cursor")
    assert cursor["status"] == "planned" and cursor["interim_kind"] == "mcp_gateway"
    assert "no native ContextOS integration yet" in cursor["notes"][0]
    assert any(c["title"] == ".cursor/mcp.json" for c in _commands(cursor))
    langgraph = _setup(client, org, "langgraph")
    assert langgraph["interim_kind"] == "python_sdk"
    assert any(c["language"] == "python" for c in _commands(langgraph))


def test_unknown_kind_is_404(client, org):
    response = client.get(f"{URL}/not_a_framework/setup", headers=org.user_headers)
    assert response.status_code == 404 and response.json()["error"]["code"] == "not_found"


def test_unsafe_host_header_falls_back_to_placeholder_url(client, org):
    guide = _setup(client, org, "claude_code", headers={**org.user_headers, "Host": "evil.example;rm"})
    assert guide["server_url"] == "http://localhost:8000"
    assert "could not be used safely" in guide["server_url_note"]
    assert server_url_for("https://contextos.internal:8443/")[0] == "https://contextos.internal:8443"
    assert server_url_for("http://[::1]:8000/")[0] == "http://[::1]:8000"
    assert server_url_for("javascript:alert(1)")[0] == "http://localhost:8000"


def test_setup_guides_use_the_organisations_fail_mode(client, org, db):
    org_row = db.get(Organization, org.org_id)
    org_row.settings = {**(org_row.settings or {}), "fail_mode": "closed"}
    db.commit()
    sdk = _setup(client, org, "python_sdk")
    assert sdk["fail_mode"] == "closed"
    assert any("contextos init --url http://testserver --api-key ctxk_your_key --fail-mode closed" in c["code"]
               for c in _commands(sdk))
    hook = _setup(client, org, "claude_code")
    codes = [c["code"] for c in _commands(hook)]
    assert "export CONTEXTOS_HOOK_FAIL_MODE=closed" in codes
    assert json.loads(next(c["code"] for c in _commands(hook) if c["language"] == "json"))["hooks"]  # hooks first

    org_row.settings = {**org_row.settings, "fail_mode": "ask"}
    db.commit()
    gateway = _setup(client, org, "mcp_gateway")
    init = next(s for s in gateway["steps"] if s["title"].startswith("Connect the project"))
    assert "--fail-mode ask" in init["commands"][0]["code"] and "treats 'ask' as 'closed'" in init["description"]


def test_setup_guide_defaults_to_the_server_default_fail_mode(client, org):
    guide = _setup(client, org, "python_sdk")
    assert guide["fail_mode"] == "ask"  # default_org_settings()
