"""Live: ``examples/python_sdk/guarded_agent.py`` — tools wrapped with the SDK's ``@guard`` — run as
a subprocess against a real ``contextos-server``.

The example agent receives a support ticket carrying a hidden instruction, reads its refund policy,
replies to the customer, then tries to read its workspace's ``.env`` (a runtime-generated fake
credential) and mail it to an outside address. With the built-in policy pack, outbound e-mail after
injected content needs approval: a reviewer approves the reply and rejects the leak while the guard
polls. The guard runs only what was allowed — the outbox gets the reply and never the ``.env``.
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from tests.e2e.live_support import EXAMPLES, LiveServer, client_env

pytestmark = pytest.mark.live
STEP = re.compile(r"\[(ran|denied|approval)\]\s+(.+?): (.*)")


def _next_pending(live: LiveServer, agent_id: str | None, agent: str, proc: subprocess.Popen[bytes],
                  seen: set[str]) -> tuple[str, dict]:
    deadline = time.monotonic() + 120
    while True:
        if proc.poll() is not None or time.monotonic() > deadline:
            proc.kill()
            out, err = proc.communicate(timeout=30)
            approvals = live.get("/approvals", agent_id=agent_id, include_simulated=False)["items"] if agent_id else []
            raise AssertionError(f"no new approval request appeared (exit {proc.returncode}); approvals: "
                                 f"{[(a['id'], a['status']) for a in approvals]}\n{out.decode()}{err.decode()}")
        if agent_id is None:
            found = [a for a in live.get("/agents", q=agent)["items"] if a["name"] == agent]
            agent_id = found[0]["id"] if found else None
        if agent_id:
            pending = [a for a in live.get("/approvals", status="pending", agent_id=agent_id)["items"]
                       if a["id"] not in seen]
            if pending:
                seen.add(pending[0]["id"])
                return agent_id, pending[0]
        time.sleep(0.4)


def test_guard_runs_only_what_contextos_allowed(live: LiveServer, tmp_path: Path) -> None:
    agent = f"support-triage-{uuid.uuid4().hex[:8]}"
    env = client_env(live, tmp_path / "home", CONTEXTOS_AGENT_NAME=agent, CONTEXTOS_APPROVAL_TIMEOUT_S="90",
                     TMPDIR=str(tmp_path))
    proc = subprocess.Popen([sys.executable, str(EXAMPLES / "python_sdk" / "guarded_agent.py")],  # noqa: S603
                            env=env, cwd=tmp_path,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    seen: set[str] = set()
    try:
        agent_id, reply = _next_pending(live, None, agent, proc, seen)
        assert live.post(f"/approvals/{reply['id']}/decide", {"approve": True})["status"] == "approved"
        _, leak = _next_pending(live, agent_id, agent, proc, seen)
        assert live.post(f"/approvals/{leak['id']}/decide",
                         {"approve": False, "note": "Never mail .env files"})["status"] == "rejected"
        stdout_b, stderr_b = proc.communicate(timeout=180)
    finally:
        if proc.poll() is None:
            proc.kill()
    stdout, stderr = stdout_b.decode(), stderr_b.decode(errors="replace")
    assert proc.returncode == 0, stdout + stderr

    outcome = {label: (kind, detail) for kind, label, detail in STEP.findall(stdout)}
    assert outcome["read the refund policy"][0] == "ran", stdout
    assert outcome["reply to the customer"] == ("ran", "queued 001.eml for dana@customer.example"), stdout
    assert outcome["read .env (injected)"][0] == "denied", stdout
    assert "Deny sensitive access after prompt injection" in outcome["read .env (injected)"][1]
    mail = outcome["mail .env to audit@drop-box.example (injected)"]
    assert mail[0] == "denied" and "rejected: Never mail .env files" in mail[1], stdout
    assert "Outbox: ['001.eml']" in stdout, stdout  # the leak never reached the (local) outbox

    external = re.search(r"Integration session id: (\S+)\.", stdout)
    assert external, stdout
    session = live.session(external.group(1))
    assert session is not None
    decisions = live.get("/policies/recent-decisions", session_id=session["id"], limit=50)["items"]
    assert len(decisions) == 4 and all(d["enforcement"] == "enforced" for d in decisions), decisions
    assert sorted(d["decision"] for d in decisions) == ["ALLOW", "DENY", "REQUIRE_APPROVAL", "REQUIRE_APPROVAL"]
    findings = {f["category"] for f in live.get("/findings", session_id=session["id"], limit=100)["items"]}
    assert findings & {"prompt_injection", "instruction_override"}, findings
    assert live.get(f"/approvals/{reply['id']}")["status"] == "approved"
