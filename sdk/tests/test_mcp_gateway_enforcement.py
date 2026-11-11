"""Decision handling: every ContextOS answer and failure maps to forward or block (fail closed by default)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")

import anyio  # noqa: E402

from contextos.integrations.mcp_gateway.enforcement import Enforcer, opaque_category  # noqa: E402
from contextos.integrations.mcp_gateway.mapping import tool_request_event  # noqa: E402
from contextos.models import AgentRef  # noqa: E402

from .mcp_gateway_support import FakeClock  # noqa: E402
from .sdk_fakes import FakeServer, decision_body  # noqa: E402

TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"  # synthetic GitHub-token shape
DENY_MATCH = [{"policy_id": "pol_1", "name": "Deny deleting notes", "version": 1, "outcome": "DENY", "mode": "enforce",
               "severity": "high", "explanation": "tool.name equals delete_all_notes"}]


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)


@pytest.fixture()
def server() -> FakeServer:
    return FakeServer()


@pytest.fixture()
def client(server: FakeServer, tmp_path: Path):
    return server.client(tmp_path)


def _request(tool: str = "delete_all_notes", **arguments: Any):
    return tool_request_event(agent=AgentRef(name="claude-code", framework="mcp"), session_id="ses_1",
                              server_name="notes", tool_name=tool, arguments=arguments or {"confirm": True},
                              correlation_id="cor_1")


def _authorize(enforcer: Enforcer, request=None, on_wait=None):
    return anyio.run(lambda: enforcer.authorize(request or _request(), on_wait=on_wait))


@pytest.mark.parametrize("decision", ["ALLOW", "AUDIT"])
def test_allow_and_audit_forward_unchanged_arguments(server: FakeServer, client, decision: str) -> None:
    server.route("POST", "/api/v1/decide", decision_body(decision))
    verdict = _authorize(Enforcer(client))
    assert verdict.allowed and verdict.arguments == {"confirm": True} and verdict.outcome == decision.lower()
    body = server.bodies("POST", "/api/v1/decide")[0]
    assert body["tool"] == {"name": "delete_all_notes", "provider": "mcp:notes", "server": "notes"}
    assert body["integration"] == "mcp_gateway" and body["arguments"] == {"confirm": True}


def test_deny_names_the_policy_and_its_reason(server: FakeServer, client) -> None:
    server.route("POST", "/api/v1/decide", decision_body("DENY", reason="Deleting notes is not allowed.",
                                                         matched_policies=DENY_MATCH))
    verdict = _authorize(Enforcer(client))
    assert not verdict.allowed and verdict.outcome == "denied"
    assert verdict.message == ("Blocked by ContextOS policy 'Deny deleting notes': Deleting notes is not allowed "
                               "(decision pd_1). The tool was not run.")


def test_unrecognised_decision_fails_closed(server: FakeServer, client) -> None:
    server.route("POST", "/api/v1/decide", decision_body("QUARANTINE"))
    verdict = _authorize(Enforcer(client, fail_mode="open"))
    assert not verdict.allowed and "unrecognised decision 'QUARANTINE'" in verdict.message


def test_unreachable_fails_closed_by_default_and_spools_the_attempt(server: FakeServer, client) -> None:
    server.down = True
    verdict = _authorize(Enforcer(client))
    assert not verdict.allowed and verdict.outcome == "fail_closed"
    assert "unreachable" in verdict.message and verdict.message.startswith("Blocked by the ContextOS MCP gateway")
    spooled = [json.loads(line) for line in client.spool.path.read_text().splitlines()]
    assert spooled[0]["event_type"] == "tool.requested"
    assert spooled[0]["metadata"] == {"decision_unavailable": True, "fail_mode": "closed", "local_outcome": "not_run"}


def test_fail_open_forwards_without_a_decision(server: FakeServer, client) -> None:
    server.down = True
    verdict = _authorize(Enforcer(client, fail_mode="open"))
    assert verdict.allowed and verdict.fail_open and verdict.decision is None
    spooled = json.loads(client.spool.path.read_text().splitlines()[0])
    assert spooled["metadata"]["local_outcome"] == "forwarded_without_decision"


def test_server_errors_apply_the_fail_mode(server: FakeServer, client) -> None:
    server.route("POST", "/api/v1/decide", {"error": {"code": "decision_failed", "message": "boom"}}, status=500)
    assert not _authorize(Enforcer(client)).allowed
    assert _authorize(Enforcer(client, fail_mode="open")).allowed


@pytest.mark.parametrize(("status", "outcome"), [(401, "auth_error"), (403, "auth_error"), (422, "api_error")])
def test_rejected_keys_and_invalid_requests_always_block(server: FakeServer, client, status: int, outcome: str) -> None:
    server.route("POST", "/api/v1/decide", {"error": {"code": "x", "message": "nope"}}, status=status)
    verdict = _authorize(Enforcer(client, fail_mode="open"))
    assert not verdict.allowed and verdict.outcome == outcome


def _approval(server: FakeServer, *statuses: str, note: str | None = None) -> None:
    server.route("POST", "/api/v1/decide", decision_body("REQUIRE_APPROVAL", approval_id="apr_1",
                                                         approval_status="pending", reason="Needs a human."))
    server.sequence("GET", "/api/v1/decide/approvals/apr_1",
                    [(200, {"approval_id": "apr_1", "status": s, "decision_note": note}) for s in statuses])


def test_approval_granted_while_waiting_forwards_and_reports_progress(server: FakeServer, client) -> None:
    _approval(server, "pending", "pending", "approved")
    clock, progress = FakeClock(), []

    async def on_wait(elapsed: float, total: float, message: str) -> None:
        progress.append((elapsed, total, message))

    verdict = _authorize(Enforcer(client, approval_timeout_s=60, poll_s=2, clock=clock.time, sleep=clock.sleep),
                         on_wait=on_wait)
    assert verdict.allowed and verdict.outcome == "approved"
    assert len(server.calls("GET", "/api/v1/decide/approvals/apr_1")) == 3
    assert [p[0] for p in progress] == [0, 2, 4] and progress[0][1] == 60 and "apr_1" in progress[0][2]


def test_rejected_approval_blocks_with_the_reviewer_note(server: FakeServer, client) -> None:
    _approval(server, "rejected", note="not during the freeze")
    clock = FakeClock()
    verdict = _authorize(Enforcer(client, approval_timeout_s=60, clock=clock.time, sleep=clock.sleep))
    assert not verdict.allowed and verdict.outcome == "approval_rejected"
    assert "approval apr_1 was rejected: not during the freeze" in verdict.message


def test_pending_approval_times_out_and_blocks(server: FakeServer, client) -> None:
    _approval(server, "pending")
    clock = FakeClock()
    verdict = _authorize(Enforcer(client, approval_timeout_s=10, poll_s=3, clock=clock.time, sleep=clock.sleep))
    assert not verdict.allowed and verdict.outcome == "approval_timeout"
    assert "not decided within 10s" in verdict.message and sum(clock.sleeps) == pytest.approx(10)


def test_approval_timeout_zero_blocks_without_polling(server: FakeServer, client) -> None:
    _approval(server, "approved")
    verdict = _authorize(Enforcer(client, approval_timeout_s=0))
    assert not verdict.allowed and verdict.outcome == "approval_not_awaited"
    assert server.calls("GET", "/api/v1/decide/approvals/apr_1") == []


def test_already_approved_needs_no_polling(server: FakeServer, client) -> None:
    server.route("POST", "/api/v1/decide", decision_body("REQUIRE_APPROVAL", approval_id="apr_1",
                                                         approval_status="approved"))
    assert _authorize(Enforcer(client)).allowed and server.calls("GET", "/api/v1/decide/approvals/apr_1") == []


def test_approval_poll_with_a_revoked_key_blocks(server: FakeServer, client) -> None:
    _approval(server, "pending")
    server.route("GET", "/api/v1/decide/approvals/apr_1", {"error": {"code": "x", "message": "revoked"}}, status=401)
    clock = FakeClock()
    verdict = _authorize(Enforcer(client, approval_timeout_s=60, clock=clock.time, sleep=clock.sleep))
    assert not verdict.allowed and verdict.outcome == "approval_error"


def _restrict(server: FakeServer, restrictions: dict[str, Any]) -> None:
    server.route("POST", "/api/v1/decide", decision_body("RESTRICT", restrictions=restrictions,
                                                         matched_policies=[{"name": "Mask secrets", "outcome": "RESTRICT"}]))


def test_restrict_redacts_secrets_after_a_server_recheck(server: FakeServer, client) -> None:
    _restrict(server, {"redact_secrets": True})
    server.route("POST", "/api/v1/scan", {"hits": [], "secrets": []})
    verdict = _authorize(Enforcer(client), _request("add_note", title="t", notes=f"token {TOKEN}"))
    assert verdict.allowed and verdict.outcome == "restricted"
    assert TOKEN not in json.dumps(verdict.arguments) and verdict.arguments["title"] == "t"
    assert TOKEN not in server.calls("POST", "/api/v1/scan")[0].content.decode()


def test_restrict_blocks_when_the_recheck_is_unavailable(server: FakeServer, client) -> None:
    _restrict(server, {"redact_secrets": True})
    server.route("POST", "/api/v1/scan", {"error": {"code": "forbidden", "message": "no read scope"}}, status=403)
    verdict = _authorize(Enforcer(client), _request("add_note", notes=TOKEN))
    assert not verdict.allowed and "Blocked by ContextOS policy 'Mask secrets'" in verdict.message
    assert "could not re-check" in verdict.message


@pytest.mark.parametrize(("arguments", "allowed"), [
    ({"path": "./docs/readme.md"}, True),
    ({"path": "/etc/passwd"}, False),
    ({"command": "cat ~/.ssh/id_rsa"}, False),  # opaque: files touched by a command cannot be checked
])
def test_restrict_path_globs(server: FakeServer, client, tmp_path: Path, arguments: dict, allowed: bool) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "readme.md").write_text("x")
    _restrict(server, {"allowed_path_globs": [str(tmp_path.resolve()) + "/docs/*", "docs/*"]})
    verdict = _authorize(Enforcer(client), _request("read_file", **arguments))
    assert verdict.allowed is allowed


def test_restrict_with_unknown_restrictions_fails_closed(server: FakeServer, client) -> None:
    _restrict(server, {"sandbox": "strict"})
    verdict = _authorize(Enforcer(client), _request("add_note", title="x"))
    assert not verdict.allowed and "does not understand restriction(s) sandbox" in verdict.message


def test_opaque_category_detects_program_arguments() -> None:
    assert opaque_category({"Command": "ls"}) == "shell" and opaque_category({"script": ""}) == "shell"
    assert opaque_category({"path": "/var/data"}) is None


def test_invalid_fail_mode_is_rejected(client) -> None:
    with pytest.raises(ValueError):
        Enforcer(client, fail_mode="ask")
