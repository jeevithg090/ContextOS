"""Live: every ``contextos`` CLI command against a real ``contextos-server``.

Each command runs as a subprocess in a scratch project with an isolated ``CONTEXTOS_HOME``; the
outputs are checked against what the server's API returns for the same records.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from app.simulations.payloads import MALICIOUS_README
from tests.e2e.live_support import LiveServer, client_env, run, tool_path

pytestmark = pytest.mark.live


class Cli:
    def __init__(self, live: LiveServer, tmp_path: Path) -> None:
        self.project = tmp_path / "project"
        self.project.mkdir()
        self.env = client_env(live, tmp_path / "home", COLUMNS="250")
        self.env.pop("CONTEXTOS_API_KEY")  # `init` stores it; later commands read the config files
        self.key = live.api_key
        self.exe = str(tool_path("contextos"))

    def __call__(self, *args: str, expect: int = 0, stdin: bytes = b"") -> str:
        done = run([self.exe, *args], self.env, stdin=stdin, cwd=self.project, timeout=300)
        out = done.stdout.decode() + done.stderr.decode()
        assert done.returncode == expect, f"contextos {' '.join(args)} exited {done.returncode}:\n{out}"
        assert self.key not in out, "the CLI printed the API key"
        return out

    def json(self, *args: str) -> Any:
        done = run([self.exe, *args, "--json"], self.env, cwd=self.project, timeout=300)
        assert done.returncode == 0, done.stderr.decode()
        return json.loads(done.stdout)


def test_every_cli_command_against_the_live_server(live: LiveServer, tmp_path: Path) -> None:
    cli = Cli(live, tmp_path)
    agent = f"cli-live-{uuid.uuid4().hex[:6]}"

    # Setup: init verifies the server and the key's scopes, then status / doctor read the config back.
    out = cli("init", "--url", live.url, "--api-key", live.api_key, "--agent-name", agent)
    assert "Connected to" in out and out.count("✓") >= 5
    assert agent in cli("status") and "Reachable   yes" in cli("status")
    doctor = cli("doctor")
    assert "Scope 'ingest'" in doctor and "granted" in doctor and "contextos simulate" in doctor
    assert "The spool is empty." in cli("flush")

    # Simulation Lab: list, run (through the real pipeline), replay the simulated session.
    scenarios = cli.json("simulate", "--list")
    assert "benign-baseline" in [s["id"] for s in scenarios["items"]]
    assert "benign-baseline" in cli("simulate", "--list")
    run_out = cli.json("simulate", "malicious-readme")
    assert run_out["status"] == "completed" and run_out["passed"] is True and run_out["is_simulation"] is True
    text_run = cli("simulate", "benign-baseline")
    assert "PASSED" in text_run and "simulated" in text_run
    replay = cli("replay", run_out["session_id"])
    assert "simulated (Simulation Lab)" in replay and "DENY" in replay and "not proof" in replay

    # Real traffic from this project's agent, then the data commands.
    session = f"ses_cli_{uuid.uuid4().hex[:10]}"
    with live.key() as key:
        events = [{"event_id": f"evt-{uuid.uuid4().hex}", "event_type": t, "timestamp": "2026-11-11T10:00:00+00:00",
                   "agent": {"name": agent, "framework": "python_sdk"}, "session_id": session,
                   "integration": "python_sdk", **extra}
                  for t, extra in (("session.started", {}),
                                   ("context.ingested", {"source": {"type": "file", "identifier": "/w/README.md"},
                                                         "content": MALICIOUS_README}))]
        assert key.post("/events", json={"events": events}).status_code == 200
    agents = cli.json("agents")
    assert agent in [a["name"] for a in agents["items"]]
    assert all(not a["is_simulation"] for a in agents["items"])
    assert agents["facets"]["simulated"] >= 1 and "simulated agent(s) hidden" in cli("agents")
    assert "sim-malicious-readme" in cli("agents", "--include-simulated")
    listed = cli.json("events", "--session", session)
    assert [e["event_type"] for e in listed["items"]] == ["context.ingested", "session.started"]
    assert agent in cli("events", "--session", session)
    by_external = cli("replay", session)  # the integration's own session id works too
    assert f"of agent {agent}" in by_external and "2 recorded step(s)" in by_external
    assert "Block credential exfiltration" in cli("policies")
    incidents = cli.json("incidents", "--include-simulated")
    assert incidents["total"] >= 1 and any(i["is_simulation"] for i in incidents["items"])
    assert all(not i["is_simulation"] for i in cli.json("incidents")["items"])

    # Detection: a malicious README is flagged (exit 3), a .env is not uploaded without --force.
    (cli.project / "README.md").write_text(MALICIOUS_README, encoding="utf-8")
    (cli.project / ".env").write_text("X=1\n", encoding="utf-8")
    scan = cli("scan", str(cli.project / "README.md"), str(cli.project / ".env"), expect=3)
    assert "PI-OVERRIDE-001" in scan and "sensitive path, not uploaded" in scan
    assert "<stdin> — nothing detected" in cli("scan", "-", stdin=b"Run make test before opening a pull request.")

    # Integrations entry points are wired (their behaviour is covered by the other live tests).
    assert "PreToolUse" in cli("hook", "--help")
    assert "--name NAME" in cli("mcp-gateway", "--help")
