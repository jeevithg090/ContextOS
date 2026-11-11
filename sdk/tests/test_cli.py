"""CLI commands via typer's CliRunner against a mocked ContextOS server (no network)."""

from __future__ import annotations

import json
import stat
import sys
import types
from pathlib import Path

import pytest
from typer.testing import CliRunner

from contextos._cli import common, delegates
from contextos.cli import app
from contextos.client import ContextOSClient
from contextos.spool import Spool

from .sdk_fakes import API_KEY, BASE_URL, FakeServer

runner = CliRunner(env={"COLUMNS": "220"})


@pytest.fixture()
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    fake = FakeServer()
    home = tmp_path / "home"
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.setenv("CONTEXTOS_HOME", str(home))
    for var in ("CONTEXTOS_URL", "CONTEXTOS_API_KEY", "CONTEXTOS_AGENT_NAME", "CONTEXTOS_FAIL_MODE"):
        monkeypatch.delenv(var, raising=False)

    def factory(cfg):
        return ContextOSClient(cfg.url, cfg.api_key, transport=fake.transport(), sleep=lambda _s: None,
                               spool=Spool(home / "spool" / "cli.jsonl"))

    monkeypatch.setattr(common, "client_factory", factory)
    return fake


def _configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_URL", BASE_URL)
    monkeypatch.setenv("CONTEXTOS_API_KEY", API_KEY)


def _grant_all_scopes(server: FakeServer) -> None:
    server.route("GET", "/api/v1/agents", {"items": [], "total": 0, "limit": 1, "offset": 0})
    server.route("POST", "/api/v1/events", {"error": {"code": "validation_failed", "message": "empty"}}, status=422)
    server.route("POST", "/api/v1/decide", {"error": {"code": "validation_failed", "message": "empty"}}, status=422)


# -- init -------------------------------------------------------------------------------------

def test_init_verifies_then_writes_project_and_user_config(server: FakeServer, tmp_path: Path) -> None:
    _grant_all_scopes(server)
    result = runner.invoke(app, ["init", "--url", BASE_URL, "--api-key", API_KEY, "--agent-name", "billing-bot"])
    assert result.exit_code == 0, result.output
    assert API_KEY not in result.output and "ctxk_tes…" in result.output
    project_cfg = json.loads((tmp_path / "project" / ".contextos" / "config.json").read_text())
    assert project_cfg == {"url": BASE_URL, "agent_name": "billing-bot", "fail_mode": "closed"}
    user_file = tmp_path / "home" / "config.json"
    assert json.loads(user_file.read_text()) == {"api_key": API_KEY}
    assert stat.S_IMODE(user_file.stat().st_mode) == 0o600
    assert {r.url.path for r in server.requests} >= {"/api/v1/health", "/api/v1/agents", "/api/v1/events", "/api/v1/decide"}


def test_init_with_rejected_key_writes_nothing(server: FakeServer, tmp_path: Path) -> None:
    server.route("GET", "/api/v1/agents", {"error": {"code": "unauthenticated", "message": "Invalid or revoked API key"}}, status=401)
    result = runner.invoke(app, ["init", "--url", BASE_URL, "--api-key", API_KEY])
    assert result.exit_code == 1
    assert "rejected" in result.output
    assert not (tmp_path / "project" / ".contextos").exists()
    assert not (tmp_path / "home" / "config.json").exists()


def test_init_unreachable_server_fails_with_a_hint(server: FakeServer) -> None:
    server.down = True
    result = runner.invoke(app, ["init", "--url", BASE_URL, "--api-key", API_KEY])
    assert result.exit_code == 1 and "Cannot reach ContextOS" in result.output


def test_init_project_key_location_is_private_and_git_ignored(server: FakeServer, tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", "--url", BASE_URL, "--api-key", API_KEY, "--key-location", "project", "--skip-verify"])
    assert result.exit_code == 0, result.output
    cfg_file = tmp_path / "project" / ".contextos" / "config.json"
    assert json.loads(cfg_file.read_text())["api_key"] == API_KEY
    assert stat.S_IMODE(cfg_file.stat().st_mode) == 0o600
    assert "config.json" in (cfg_file.parent / ".gitignore").read_text()
    assert server.requests == []


def test_init_claude_code_delegates_to_the_installer(server: FakeServer, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _grant_all_scopes(server)
    calls = []
    fake = types.ModuleType("contextos.integrations.claude_code.install")
    fake.install_hooks = lambda project_dir, scope: calls.append((project_dir, scope)) or str(project_dir / ".claude" / "settings.json")
    monkeypatch.setitem(sys.modules, "contextos.integrations.claude_code.install", fake)
    result = runner.invoke(app, ["init", "--url", BASE_URL, "--api-key", API_KEY, "--claude-code", "--scope", "local"])
    assert result.exit_code == 0, result.output
    assert calls == [((tmp_path / "project").resolve(), "local")]
    assert "Claude Code hooks installed" in result.output


def test_init_rejects_bad_fail_mode(server: FakeServer) -> None:
    result = runner.invoke(app, ["init", "--api-key", API_KEY, "--fail-mode", "sometimes", "--skip-verify"])
    assert result.exit_code == 1 and "--fail-mode" in result.output


# -- status / doctor / flush -------------------------------------------------------------------

def test_status_masks_the_key_and_reports_reachability(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    assert API_KEY not in result.output and "ctxk_tes…" in result.output and "(from env)" in result.output
    assert "Reachable   yes" in result.output
    server.down = True
    assert runner.invoke(app, ["status"]).exit_code == 1


def test_doctor_healthy(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    _grant_all_scopes(server)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    for text in ("Server reachable", "accepted", "Scope 'decide'", "granted", "Offline spool", "Claude Code hooks"):
        assert text in result.output
    assert API_KEY not in result.output


def test_doctor_warns_when_the_api_key_travels_unencrypted(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)  # the fake server's URL is plain HTTP to a non-local host
    _grant_all_scopes(server)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output  # a warning, not a failure
    assert "Transport" in result.output and "unencrypted" in result.output


def test_doctor_fails_on_rejected_key_and_reports_missing_scopes(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    server.route("GET", "/api/v1/agents", {"error": {"code": "unauthenticated", "message": "Invalid or revoked API key"}}, status=401)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1 and "rejected" in result.output
    _grant_all_scopes(server)
    server.route("POST", "/api/v1/decide", {"error": {"code": "forbidden", "message": "no"}}, status=403)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0 and "missing" in result.output


def test_doctor_reports_installed_hooks(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    _grant_all_scopes(server)
    fake = types.ModuleType("contextos.integrations.claude_code.install")
    fake.hooks_status = lambda project_dir: {"installed": True, "detail": "PreToolUse, PostToolUse in .claude/settings.json"}
    monkeypatch.setitem(sys.modules, "contextos.integrations.claude_code.install", fake)
    result = runner.invoke(app, ["doctor"])
    assert "PreToolUse, PostToolUse in .claude/settings.json" in result.output


def test_flush_sends_spooled_events(server: FakeServer, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _configured(monkeypatch)
    Spool(tmp_path / "home" / "spool" / "cli.jsonl").append(
        [{"event_id": f"evt_{i}", "event_type": "session.started", "agent": {"name": "a"}, "session_id": "s",
          "timestamp": "2026-11-10T10:00:00Z"} for i in range(3)])
    result = runner.invoke(app, ["flush"])
    assert result.exit_code == 0, result.output
    assert "Delivered 3 of 3" in result.output and len(server.events()) == 3


# -- read commands -----------------------------------------------------------------------------

def test_agents_table_and_json(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    page = {"items": [{"id": "agt_1", "name": "billing-bot", "framework": "python_sdk", "environment": "production",
                       "status": "active", "risk_score": 42, "last_seen_at": "2026-11-10T10:00:00Z"}],
            "total": 1, "limit": 50, "offset": 0}
    server.route("GET", "/api/v1/agents", page)
    result = runner.invoke(app, ["agents"])
    assert result.exit_code == 0 and "billing-bot" in result.output and "2026-11-10 10:00:00" in result.output
    assert json.loads(runner.invoke(app, ["agents", "--json"]).output) == page


def test_agents_empty_state(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    server.route("GET", "/api/v1/agents", {"items": [], "total": 0, "limit": 50, "offset": 0})
    assert "No agents yet" in runner.invoke(app, ["agents"]).output


def test_events_filters_by_session(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    server.route("GET", "/api/v1/events", {"items": [{"id": "ie_1", "event_type": "tool.requested", "session_id": "ses_9",
                                                      "integration": "python_sdk", "received_at": "2026-11-10T10:00:00Z"}],
                                           "total": 120, "limit": 50, "offset": 0})
    result = runner.invoke(app, ["events", "--session", "ses_9"])
    assert result.exit_code == 0 and "tool.requested" in result.output and "Showing 1 of 120" in result.output
    assert server.calls("GET", "/api/v1/events")[0].url.params["session_id"] == "ses_9"


def test_policies_and_incidents(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    server.route("GET", "/api/v1/policies", {"items": [{"id": "pol_1", "name": "Block secrets to web", "outcome": "DENY",
                                                        "mode": "monitor", "enabled": True, "priority": 900, "severity": "high"}],
                                             "total": 1, "limit": 200, "offset": 0})
    server.route("GET", "/api/v1/incidents", {"items": [{"id": "inc_1", "number": 7, "title": "Credential exfiltration attempt",
                                                         "severity": "critical", "status": "open"}], "total": 1, "limit": 50, "offset": 0})
    policies = runner.invoke(app, ["policies"])
    assert policies.exit_code == 0 and "Block secrets to web" in policies.output and "monitor (recorded only)" in policies.output
    incidents = runner.invoke(app, ["incidents", "--status", "open"])
    assert incidents.exit_code == 0 and "Credential exfiltration attempt" in incidents.output
    assert server.calls("GET", "/api/v1/incidents")[0].url.params["status"] == "open"


def test_read_command_without_read_scope_explains_itself(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    server.route("GET", "/api/v1/policies", {"error": {"code": "forbidden", "message": "Missing permission 'read'"}}, status=403)
    result = runner.invoke(app, ["policies"])
    assert result.exit_code == 1 and "lacks the scope" in result.output


# Shapes captured from a live server (GET /sessions/{id}, GET /sessions/{id}/timeline).
SESSION = {"id": "asn_1", "external_session_id": "ses_ext_1", "agent": {"id": "agt_1", "name": "support-bot"},
           "is_simulation": False}
TIMELINE = {"items": [
    {"id": "evt_1", "sequence": 1, "occurred_at": "2026-11-10T10:00:00Z", "received_at": "2026-11-10T10:00:00Z",
     "event_type": "context.ingested", "title": "Read web https://evil.test/page", "summary": None,
     "trust_level": "SUSPICIOUS", "decision": None, "enforcement": None, "severity": "high",
     "explanation": "Hidden instructions found in an HTML comment"},
    {"id": "evt_2", "sequence": 2, "occurred_at": "2026-11-10T10:00:05Z", "received_at": "2026-11-10T10:00:05Z",
     "event_type": "tool.requested", "title": "Denied send_email to attacker@evil.test", "summary": None,
     "trust_level": None, "decision": "DENY", "enforcement": "enforced", "severity": None, "explanation": None},
], "total": 2, "limit": 200, "offset": 0, "focus_event_ids": []}


def test_replay_prints_the_timeline(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    server.route("GET", "/api/v1/sessions/asn_1", SESSION)
    server.route("GET", "/api/v1/sessions/asn_1/timeline", TIMELINE)
    result = runner.invoke(app, ["replay", "asn_1"])
    assert result.exit_code == 0, result.output
    assert "Session asn_1 of agent support-bot — 2 recorded step(s)" in result.output
    assert "2026-11-10 10:00:00  context.ingested  Read web https://evil.test/page" in result.output
    assert "Hidden instructions found" in result.output and "DENY" in result.output and "enforced" in result.output
    assert "not proof" in result.output and "simulated" not in result.output


def test_replay_accepts_the_integration_session_id(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    """The SDK and hooks print their own session id (ses_…); the API's id routes take asn_… ids."""
    _configured(monkeypatch)
    server.route("GET", "/api/v1/sessions", {"items": [{**SESSION, "id": "asn_other", "external_session_id": "ses_ext_10"},
                                                       {**SESSION, "is_simulation": True}],
                                             "total": 2, "limit": 50, "offset": 0})
    server.route("GET", "/api/v1/sessions/asn_1", {**SESSION, "is_simulation": True})
    server.route("GET", "/api/v1/sessions/asn_1/timeline", TIMELINE)
    result = runner.invoke(app, ["replay", "ses_ext_1"])
    assert result.exit_code == 0, result.output
    assert "Session asn_1 of agent support-bot simulated (Simulation Lab)" in result.output
    lookup = server.calls("GET", "/api/v1/sessions")[0].url.params
    assert lookup["q"] == "ses_ext_1" and lookup["include_simulated"] == "true"


def test_replay_unknown_session(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    server.route("GET", "/api/v1/sessions", {"items": [], "total": 0, "limit": 50, "offset": 0})
    result = runner.invoke(app, ["replay", "ses_missing"])
    assert result.exit_code == 1 and "Not found" in result.output and "ses_missing" in result.output


def test_simulated_rows_are_labelled_and_hidden_unless_requested(server: FakeServer,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    real = {"id": "agt_1", "name": "billing-bot", "framework": "python_sdk", "environment": "production",
            "status": "active", "risk_score": 0, "last_seen_at": "2026-11-10T10:00:00Z", "is_simulation": False}
    server.route("GET", "/api/v1/agents", {"items": [real], "total": 1, "limit": 50, "offset": 0,
                                           "facets": {"simulated": 2}})
    hidden = runner.invoke(app, ["agents"])
    assert hidden.exit_code == 0 and "2 simulated agent(s) hidden" in hidden.output
    assert "include_simulated" not in server.calls("GET", "/api/v1/agents")[0].url.params
    server.route("GET", "/api/v1/agents", {"items": [real, {**real, "id": "agt_2", "name": "sim-readme",
                                                            "is_simulation": True}],
                                           "total": 2, "limit": 50, "offset": 0, "facets": {"simulated": 2}})
    shown = runner.invoke(app, ["agents", "--include-simulated"])
    assert shown.exit_code == 0 and "sim-readme" in shown.output and "simulated" in shown.output
    assert "hidden" not in shown.output
    assert server.calls("GET", "/api/v1/agents")[-1].url.params["include_simulated"] == "true"

    server.route("GET", "/api/v1/incidents", {"items": [{"id": "inc_1", "key": "INC-1", "title": "Sim incident",
                                                         "severity": "critical", "status": "open",
                                                         "opened_at": "2026-11-10T10:00:00Z", "is_simulation": True}],
                                              "total": 1, "limit": 50, "offset": 0})
    incidents = runner.invoke(app, ["incidents", "--include-simulated"])
    assert "INC-1" in incidents.output and "simulated" in incidents.output
    assert server.calls("GET", "/api/v1/incidents")[0].url.params["include_simulated"] == "true"

    server.route("GET", "/api/v1/events", {"items": [{"id": "evt_1", "event_type": "session.started", "agent_name": "sim-readme",
                                                      "session_id": "asn_9", "integration": "claude_code",
                                                      "received_at": "2026-11-10T10:00:00Z", "is_simulation": True}],
                                           "total": 1, "limit": 50, "offset": 0})
    events = runner.invoke(app, ["events"])
    assert "sim-readme" in events.output and "simulated" in events.output


def test_simulate_list_and_run(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    monkeypatch.setattr("contextos._cli.data.time.sleep", lambda _s: None)
    server.route("GET", "/api/v1/simulations/scenarios", [{"id": "pi-web", "name": "Web prompt injection",
                                                           "category": "prompt_injection", "description": "Hidden instruction in a page"}])
    listed = runner.invoke(app, ["simulate", "--list"])
    assert listed.exit_code == 0 and "pi-web" in listed.output and "Web prompt injection" in listed.output

    server.route("POST", "/api/v1/simulations/runs", {"id": "sim_1", "scenario_id": "pi-web", "status": "running"})
    server.sequence("GET", "/api/v1/simulations/runs/sim_1", [
        (200, {"id": "sim_1", "status": "running"}),
        (200, {"id": "sim_1", "scenario_name": "Web prompt injection", "status": "completed", "passed": True,
               "summary": "Exfiltration was denied", "session_id": "ses_sim",
               "results": [{"name": "send_email denied", "expected": "DENY", "actual": "DENY", "passed": True}]}),
    ])
    ran = runner.invoke(app, ["simulate", "pi-web"])
    assert ran.exit_code == 0, ran.output
    assert "PASSED" in ran.output and "send_email denied" in ran.output and "contextos replay ses_sim" in ran.output
    assert server.bodies("POST", "/api/v1/simulations/runs") == [{"scenario_id": "pi-web"}]


def test_simulate_without_the_ingest_scope_says_which_scope(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    server.route("POST", "/api/v1/simulations/runs", {"error": {"code": "permission_denied",
                                                                "message": "Missing permission 'ingest'"}}, status=403)
    result = runner.invoke(app, ["simulate", "pi-web"])
    assert result.exit_code == 1 and "needs the 'ingest' scope" in result.output


def test_simulate_failed_verdict_exits_non_zero(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    _configured(monkeypatch)
    server.route("POST", "/api/v1/simulations/runs", {"id": "sim_2", "status": "completed", "passed": False,
                                                      "summary": "The e-mail was sent"})
    result = runner.invoke(app, ["simulate", "pi-web"])
    assert result.exit_code == 1 and "FAILED" in result.output


# -- delegated subcommands ---------------------------------------------------------------------

def test_hook_delegates_and_propagates_the_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = []
    fake = types.ModuleType("contextos.integrations.claude_code.hook")
    fake.main = lambda event_name: seen.append(event_name) or 2
    monkeypatch.setitem(sys.modules, "contextos.integrations.claude_code.hook", fake)
    result = runner.invoke(app, ["hook", "PreToolUse"])
    assert seen == ["PreToolUse"] and result.exit_code == 2


def test_missing_hook_module_fails_closed_for_pre_tool_use(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str):
        raise ModuleNotFoundError(f"No module named {name!r}", name="contextos.integrations.claude_code")

    monkeypatch.setattr(delegates.importlib, "import_module", missing)
    pre = runner.invoke(app, ["hook", "PreToolUse"])
    assert pre.exit_code == delegates.CLAUDE_BLOCK_EXIT and "unavailable" in pre.output
    assert runner.invoke(app, ["hook", "PostToolUse"]).exit_code == 1


def test_mcp_gateway_passes_arguments_through(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = []
    fake = types.ModuleType("contextos.integrations.mcp_gateway.cli")
    fake.main = lambda args: seen.append(args) or 0
    monkeypatch.setitem(sys.modules, "contextos.integrations.mcp_gateway.cli", fake)
    result = runner.invoke(app, ["mcp-gateway", "--config", "gateway.json", "--help"])
    assert result.exit_code == 0 and seen == [["--config", "gateway.json", "--help"]]


def test_mcp_gateway_missing_optional_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str):
        raise ModuleNotFoundError("No module named 'mcp'", name="mcp")

    monkeypatch.setattr(delegates.importlib, "import_module", missing)
    result = runner.invoke(app, ["mcp-gateway"])
    assert result.exit_code == 1 and "contextos[mcp]" in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and result.output.startswith("contextos ")
