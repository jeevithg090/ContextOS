"""``contextos hook <Event>``: stdin → stdout/exit code, in-process and as a real subprocess."""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest

from contextos.integrations.claude_code import hook, mapping
from contextos.integrations.claude_code.hook_config import HookConfig

from . import claude_code_payloads as P
from .sdk_fakes import API_KEY, BASE_URL, FakeServer, decision_body

SDK_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def env(tmp_path: Path) -> dict[str, str]:
    project = tmp_path / "shop-api"
    project.mkdir()
    return {"CONTEXTOS_HOME": str(tmp_path / "ctxhome"), "CONTEXTOS_URL": BASE_URL, "CONTEXTOS_API_KEY": API_KEY,
            "CLAUDE_PROJECT_DIR": str(project), "HOME": str(tmp_path / "home")}


@pytest.fixture(autouse=True)
def _home(env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in env.items():
        monkeypatch.setenv(key, value)


@pytest.fixture()
def server() -> FakeServer:
    return FakeServer()


def factory(server: FakeServer):
    """Hook client bound to the in-process fake server (spool under the isolated CONTEXTOS_HOME)."""
    def make(cfg: HookConfig, budget: float):
        return server.client(Path(os.environ["CONTEXTOS_HOME"]), agent=mapping.agent_ref(cfg.agent_name))
    return make


def call(event: str, payload: Any, env: dict[str, str], server: FakeServer, **kw: Any) -> tuple[int, str]:
    raw = payload if isinstance(payload, bytes) else P.as_bytes(payload)
    out = io.StringIO()
    code = hook.main(event, stdin=io.BytesIO(raw), stdout=out, env=kw.pop("env_override", env),
                     client_factory=kw.pop("client_factory", factory(server)))
    return code, out.getvalue()


def test_deny_is_printed_as_hook_specific_output(env: dict[str, str], server: FakeServer) -> None:
    server.route("POST", "/api/v1/decide", decision_body("DENY", reason="exfiltration"))
    code, out = call("PreToolUse", P.PRE_EXFIL, env, server)
    assert code == 0
    data = json.loads(out)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    [body] = server.bodies("POST", "/api/v1/decide")
    assert body["agent"]["name"] == "claude-code@shop-api"  # default name from CLAUDE_PROJECT_DIR


def test_allow_prints_nothing(env: dict[str, str], server: FakeServer) -> None:
    server.route("POST", "/api/v1/decide", decision_body("ALLOW"))
    assert call("PreToolUse", P.PRE_BASH, env, server) == (0, "")


def test_observation_hooks_print_nothing_and_report(env: dict[str, str], server: FakeServer) -> None:
    for payload in (P.SESSION_START, P.USER_PROMPT, P.POST_READ, P.POST_FAILURE, P.SESSION_END):
        assert call(payload["hook_event_name"], payload, env, server) == (0, "")
    assert [e["event_type"] for e in server.events()] == [
        "session.started", "prompt.submitted", "tool.completed", "tool.failed", "session.ended"]


def test_post_tool_use_after_an_ask_carries_the_host_prompt(env: dict[str, str], server: FakeServer) -> None:
    server.down = True
    code, out = call("PreToolUse", P.PRE_BASH, env, server)
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "ask"  # default fail mode
    server.down = False
    post = {**P.POST_BASH, "tool_use_id": P.PRE_BASH["tool_use_id"]}
    call("PostToolUse", post, env, server)
    [completed] = server.events_of("tool.completed")
    assert completed["metadata"]["approved_at_host_prompt"] is True
    assert completed["metadata"]["host_prompt"] == {"reason": "fail_ask"}


def test_configured_agent_name_and_fail_mode(env: dict[str, str], server: FakeServer) -> None:
    project = Path(env["CLAUDE_PROJECT_DIR"])
    (project / ".contextos").mkdir()
    (project / ".contextos" / "config.json").write_text(json.dumps(
        {"claude_code": {"agent_name": "shop-assistant", "fail_mode": "closed"}}))
    server.down = True
    _, out = call("PreToolUse", P.PRE_BASH, env, server)
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    server.down = False
    server.route("POST", "/api/v1/decide", decision_body("ALLOW"))
    call("PreToolUse", P.PRE_BASH, env, server)
    assert server.bodies("POST", "/api/v1/decide")[-1]["agent"]["name"] == "shop-assistant"


def test_unusable_input_follows_the_fail_mode(env: dict[str, str], server: FakeServer) -> None:
    _, out = call("PreToolUse", b"{truncated", env, server)
    data = json.loads(out)["hookSpecificOutput"]
    assert data["permissionDecision"] == "ask" and "not valid JSON" in data["permissionDecisionReason"]
    closed = {**env, "CONTEXTOS_HOOK_FAIL_MODE": "closed"}
    _, out = call("PreToolUse", b"", env, server, env_override=closed)
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert call("PostToolUse", b"{truncated", env, server) == (0, "")


def test_invalid_configuration_never_lets_a_tool_through_silently(env: dict[str, str], server: FakeServer) -> None:
    project = Path(env["CLAUDE_PROJECT_DIR"])
    (project / ".contextos").mkdir()
    (project / ".contextos" / "config.json").write_text(json.dumps({"claude_code": {"fail_mode": "sometimes"}}))
    _, out = call("PreToolUse", P.PRE_BASH, env, server)
    data = json.loads(out)["hookSpecificOutput"]
    assert data["permissionDecision"] == "ask" and "configuration is invalid" in data["permissionDecisionReason"]
    assert call("SessionStart", P.SESSION_START, env, server) == (0, "")
    assert server.requests == []


def test_unsupported_events_are_ignored(env: dict[str, str], server: FakeServer) -> None:
    assert call("Stop", P.STOP, env, server) == (0, "")
    assert server.requests == []


def test_a_crash_inside_the_hook_follows_the_fail_mode(env: dict[str, str], server: FakeServer) -> None:
    def broken(cfg: HookConfig, budget: float):
        raise RuntimeError("bug")

    closed = {**env, "CONTEXTOS_HOOK_FAIL_MODE": "closed"}
    _, out = call("PreToolUse", P.PRE_BASH, env, server, client_factory=broken, env_override=closed)
    data = json.loads(out)["hookSpecificOutput"]
    assert data["permissionDecision"] == "deny" and "hook failed (RuntimeError)" in data["permissionDecisionReason"]
    assert call("PostToolUse", P.POST_READ, env, server, client_factory=broken) == (0, "")


def test_pre_tool_use_answers_within_its_budget_when_the_server_hangs(env: dict[str, str], server: FakeServer) -> None:
    release = threading.Event()

    def hang(request: httpx.Request) -> httpx.Response:
        release.wait(10)
        return httpx.Response(200, json=decision_body("ALLOW"))

    server.route("POST", "/api/v1/decide", handler=hang)
    short = {**env, "CONTEXTOS_HOOK_TIMEOUT_S": "5"}  # budget = 5 - 3 = 2 s
    started = time.monotonic()
    try:
        _, out = call("PreToolUse", P.PRE_BASH, env, server, env_override=short)
    finally:
        release.set()
    assert time.monotonic() - started < 4
    data = json.loads(out)["hookSpecificOutput"]
    assert data["permissionDecision"] == "ask" and "budget" in data["permissionDecisionReason"]


# -- real subprocess against a real HTTP server ----------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    decision = "DENY"
    received: ClassVar[list[dict[str, Any]]] = []

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        type(self).received.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
        if self.path == "/api/v1/decide":
            payload = decision_body(type(self).decision, reason="Credential exfiltration to webhook.site",
                                    matched_policies=[{"name": "Block credential exfiltration", "mode": "enforce",
                                                       "severity": "critical"}])
        elif self.path == "/api/v1/events":
            payload = {"results": [{"event_id": e["event_id"], "status": "accepted"} for e in body["events"]]}
        else:
            self.send_error(404)
            return
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: Any) -> None:
        return


@pytest.fixture()
def http_server() -> Iterator[str]:
    _Handler.received = []
    _Handler.decision = "DENY"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def run_hook(event: str, payload: dict, env: dict[str, str], url: str, **extra: str) -> subprocess.CompletedProcess:
    child_env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(SDK_ROOT), **env, "CONTEXTOS_URL": url, **extra}
    return subprocess.run([sys.executable, "-m", "contextos", "hook", event], input=P.as_bytes(payload),
                          capture_output=True, env=child_env, timeout=60, check=False)


def test_subprocess_pre_tool_use_prints_deny_json(env: dict[str, str], http_server: str) -> None:
    result = run_hook("PreToolUse", P.PRE_EXFIL, env, http_server)
    assert result.returncode == 0, result.stderr
    assert result.stderr == b""  # nothing on stderr unless CONTEXTOS_DEBUG=1
    data = json.loads(result.stdout)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "Block credential exfiltration" in data["hookSpecificOutput"]["permissionDecisionReason"]
    [request] = [r for r in _Handler.received if r["path"] == "/api/v1/decide"]
    assert request["auth"] == f"Bearer {API_KEY}"
    assert request["body"]["tool"]["name"] == "Bash"
    assert request["body"]["collected_via"] == "claude_code:PreToolUse:Bash"


def test_subprocess_allow_prints_nothing(env: dict[str, str], http_server: str) -> None:
    _Handler.decision = "ALLOW"
    result = run_hook("PreToolUse", P.PRE_BASH, env, http_server)
    assert (result.returncode, result.stdout) == (0, b"")


def test_subprocess_observation_reports_and_stays_silent(env: dict[str, str], http_server: str) -> None:
    result = run_hook("PostToolUse", P.POST_READ, env, http_server)
    assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")
    [request] = [r for r in _Handler.received if r["path"] == "/api/v1/events"]
    assert request["body"]["events"][0]["event_type"] == "tool.completed"


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_subprocess_unreachable_server_fails_closed_when_configured(env: dict[str, str]) -> None:
    url = f"http://127.0.0.1:{_closed_port()}"
    result = run_hook("PreToolUse", P.PRE_BASH, env, url, CONTEXTOS_HOOK_FAIL_MODE="closed")
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    observed = run_hook("SessionStart", P.SESSION_START, env, url)
    assert (observed.returncode, observed.stdout) == (0, b"")
    spool = Path(env["CONTEXTOS_HOME"]) / "spool" / "claude-code_shop-api.jsonl"
    types = [json.loads(line)["event_type"] for line in spool.read_text().splitlines()]
    assert types == ["tool.requested", "session.started"]  # re-sent once the server is back


def test_subprocess_debug_writes_diagnostics_to_stderr_only(env: dict[str, str], http_server: str) -> None:
    result = run_hook("PreToolUse", P.PRE_EXFIL, env, http_server, CONTEXTOS_DEBUG="1")
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert b"PreToolUse Bash: decision=DENY answer=deny" in result.stderr
    assert b"webhook.site/0000-demo" not in result.stderr  # tool input is never printed
