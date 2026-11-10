"""guard(): decisions are enforced before the wrapped function runs; results are reported after."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contextos import AgentSession, ApprovalRequired, ToolDenied, guard
from contextos.guard import ToolGuard

from .sdk_fakes import FakeServer, decision_body


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("CONTEXTOS_FAIL_MODE", raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture()
def server() -> FakeServer:
    return FakeServer()


@pytest.fixture()
def client(server: FakeServer, tmp_path: Path):
    return server.client(tmp_path)


def _decide(server: FakeServer, decision: str = "ALLOW", **extra) -> None:
    server.route("POST", "/api/v1/decide", decision_body(decision, **extra))


def test_allow_runs_the_tool_and_reports_the_result(server: FakeServer, client) -> None:
    _decide(server, "ALLOW")
    calls: list[tuple] = []

    @guard("send_email", category_hint="email", client=client, destination="to")
    def send_email(to: str, subject: str, body: str = "hi") -> str:
        calls.append((to, subject, body))
        return f"sent to {to}"

    assert send_email("ops@example.com", "Report") == "sent to ops@example.com"
    assert calls == [("ops@example.com", "Report", "hi")]

    request = server.bodies("POST", "/api/v1/decide")[0]
    assert request["event_type"] == "tool.requested"
    assert request["tool"] == {"name": "send_email", "provider": "python_sdk", "category_hint": "email"}
    assert request["arguments"] == {"to": "ops@example.com", "subject": "Report", "body": "hi"}
    assert request["destination"] == {"kind": "email", "identifier": "ops@example.com"}
    assert request["collected_via"] == "python_sdk.guard"

    completed = server.events_of("tool.completed")
    assert len(completed) == 1
    assert completed[0]["correlation_id"] == request["correlation_id"]
    assert completed[0]["result"] == "sent to ops@example.com"
    assert completed[0]["metadata"]["decision"] == "ALLOW"
    assert completed[0]["session_id"] == request["session_id"]


def test_audit_runs_the_tool(server: FakeServer, client) -> None:
    _decide(server, "AUDIT")
    assert guard("lookup", client=client)(lambda q: q.upper())("abc") == "ABC"


def test_deny_never_enters_the_function(server: FakeServer, client) -> None:
    _decide(server, "DENY", reason="Untrusted web content preceded an outbound e-mail")
    entered = []

    @guard("send_email", client=client)
    def send_email(to: str) -> None:
        entered.append(to)

    with pytest.raises(ToolDenied) as info:
        send_email("attacker@evil.test")
    assert entered == []
    assert info.value.reason == "Untrusted web content preceded an outbound e-mail"
    assert info.value.decision is not None and info.value.decision.decision == "DENY"
    assert server.events_of("tool.completed") == [] and server.events_of("tool.failed") == []


def test_unknown_decision_fails_closed(server: FakeServer, client) -> None:
    _decide(server, "MAYBE")
    with pytest.raises(ToolDenied, match="unrecognised decision"):
        guard("t", client=client)(lambda: "ran")()


def test_require_approval_waits_and_runs_when_approved(server: FakeServer, client) -> None:
    _decide(server, "REQUIRE_APPROVAL", approval_id="apr_1", approval_status="pending")
    server.sequence("GET", "/api/v1/decide/approvals/apr_1", [(200, {"status": "pending"}), (200, {"status": "approved"})])
    assert guard("deploy", client=client, approval_timeout_s=30, poll_s=0.01)(lambda env: f"deployed {env}")("prod") == "deployed prod"
    assert len(server.calls("GET", "/api/v1/decide/approvals/apr_1")) == 2


@pytest.mark.parametrize("final", ["rejected", "expired", "cancelled"])
def test_require_approval_denies_when_not_approved(server: FakeServer, client, final: str) -> None:
    _decide(server, "REQUIRE_APPROVAL", approval_id="apr_1", approval_status="pending")
    server.route("GET", "/api/v1/decide/approvals/apr_1", {"status": final, "decision_note": "not today"})
    ran = []
    with pytest.raises(ToolDenied, match=f"was {final}: not today"):
        guard("deploy", client=client, approval_timeout_s=30)(lambda: ran.append(1))()
    assert ran == []


def test_require_approval_times_out_closed(server: FakeServer, tmp_path: Path) -> None:
    _decide(server, "REQUIRE_APPROVAL", approval_id="apr_1", approval_status="pending")
    server.route("GET", "/api/v1/decide/approvals/apr_1", {"status": "pending"})
    now = [0.0]
    client = server.client(tmp_path, sleep=lambda s: now.__setitem__(0, now[0] + s), clock=lambda: now[0])
    with pytest.raises(ToolDenied, match="no approval decision within 10s"):
        guard("deploy", client=client, approval_timeout_s=10, poll_s=2)(lambda: "ran")()


def test_zero_approval_timeout_hands_the_approval_to_the_host(server: FakeServer, client) -> None:
    _decide(server, "REQUIRE_APPROVAL", approval_id="apr_9", approval_status="pending")
    with pytest.raises(ApprovalRequired) as info:
        guard("deploy", client=client, approval_timeout_s=0)(lambda: "ran")()
    assert info.value.approval_id == "apr_9"
    assert isinstance(info.value, ToolDenied)  # code that only handles denials stays safe


def test_fail_closed_when_unreachable_and_attempt_is_spooled(server: FakeServer, client) -> None:
    server.down = True
    ran = []
    with pytest.raises(ToolDenied, match="fail mode is 'closed'"):
        guard("shell", client=client, fail_mode="closed")(lambda cmd: ran.append(cmd))("ls")
    assert ran == []
    spooled = [json.loads(line) for line in client.spool.path.read_text().splitlines()]
    assert [e["event_type"] for e in spooled] == ["tool.requested"]
    assert spooled[0]["metadata"]["local_outcome"] == "not_run"


def test_fail_open_runs_with_a_warning_and_records_it(server: FakeServer, client) -> None:
    server.down = True
    with pytest.warns(RuntimeWarning, match="WITHOUT a policy decision"):
        result = guard("search", client=client, fail_mode="open")(lambda q: f"results for {q}")("x")
    assert result == "results for x"
    spooled = [json.loads(line) for line in client.spool.path.read_text().splitlines()]
    assert [e["event_type"] for e in spooled] == ["tool.requested", "tool.completed"]
    assert spooled[0]["metadata"]["local_outcome"] == "ran_unguarded"
    assert spooled[1]["metadata"]["ran_without_decision"] is True


def test_fail_ask_raises_approval_required(server: FakeServer, client) -> None:
    server.down = True
    with pytest.raises(ApprovalRequired, match="needs a human decision") as info:
        guard("shell", client=client, fail_mode="ask")(lambda: "ran")()
    assert info.value.approval_id is None


def test_server_error_uses_the_fail_mode(server: FakeServer, client) -> None:
    server.route("POST", "/api/v1/decide", {"error": {"code": "internal", "message": "boom"}}, status=500)
    with pytest.raises(ToolDenied, match="failing"):
        guard("shell", client=client, fail_mode="closed")(lambda: "ran")()


def test_rejected_key_fails_closed_even_in_open_mode(server: FakeServer, client) -> None:
    server.route("POST", "/api/v1/decide", {"error": {"code": "unauthenticated", "message": "Invalid or revoked API key"}}, status=401)
    with pytest.raises(ToolDenied, match="rejected the API key"):
        guard("shell", client=client, fail_mode="open")(lambda: "ran")()


def test_fail_mode_comes_from_config(server: FakeServer, client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_FAIL_MODE", "ask")
    server.down = True
    with pytest.raises(ApprovalRequired):
        guard("shell", client=client)(lambda: "ran")()


def test_tool_exceptions_are_reported_and_re_raised(server: FakeServer, client) -> None:
    _decide(server, "ALLOW")

    @guard("read_file", category_hint="file_read", client=client)
    def read_file(path: str) -> str:
        raise FileNotFoundError(path)

    with pytest.raises(FileNotFoundError):
        read_file("missing.txt")
    failed = server.events_of("tool.failed")
    assert len(failed) == 1 and failed[0]["is_error"] is True
    assert failed[0]["result"].startswith("FileNotFoundError")


def test_reporting_failure_never_changes_the_tool_outcome(server: FakeServer, client) -> None:
    _decide(server, "ALLOW")
    server.route("POST", "/api/v1/events", {"error": {"code": "internal", "message": "db down"}}, status=500)
    assert guard("t", client=client)(lambda: 42)() == 42


def test_large_results_are_truncated(server: FakeServer, client) -> None:
    _decide(server, "ALLOW")
    guard("dump", client=client, max_result_chars=100)(lambda: "y" * 5000)()
    result = server.events_of("tool.completed")[0]["result"]
    assert result.startswith("y" * 100) and "TRUNCATED: 4900 more characters" in result


def test_session_context_supplies_session_and_agent(server: FakeServer, client) -> None:
    _decide(server, "ALLOW")
    tool = guard("lookup", client=client)(lambda q: q)
    with AgentSession(client, metadata={"task": "triage"}) as session:
        session.prompt("summarise the inbox")
        tool("inbox")
    decide = server.bodies("POST", "/api/v1/decide")[0]
    assert decide["session_id"] == session.session_id
    types = [e["event_type"] for e in server.events()]
    assert types == ["session.started", "prompt.submitted", "tool.completed", "session.ended"]
    assert server.events_of("session.ended")[0]["metadata"] == {"outcome": "completed"}


def test_methods_do_not_report_self(server: FakeServer, client) -> None:
    _decide(server, "ALLOW")

    class Mailer:
        @guard("send", client=client)
        def send(self, to: str) -> str:
            return f"{type(self).__name__}->{to}"

    assert Mailer().send("a@b.co") == "Mailer->a@b.co"
    assert server.bodies("POST", "/api/v1/decide")[0]["arguments"] == {"to": "a@b.co"}


def test_bare_decorator_uses_the_function_name(server: FakeServer, client, monkeypatch: pytest.MonkeyPatch) -> None:
    _decide(server, "ALLOW")
    from contextos import session as session_module

    monkeypatch.setattr(session_module, "_DEFAULT_CLIENT", client)

    @guard
    def summarise(text: str) -> str:
        return text[:3]

    assert summarise("abcdef") == "abc"
    assert server.bodies("POST", "/api/v1/decide")[0]["tool"]["name"] == "summarise"
    assert isinstance(summarise.contextos_guard, ToolGuard)


def test_bad_call_signature_raises_before_any_request(server: FakeServer, client) -> None:
    tool = guard("t", client=client)(lambda a: a)
    with pytest.raises(TypeError):
        tool(1, 2)
    assert server.requests == []


def test_unbuildable_request_fails_closed_without_contacting_the_server(server: FakeServer, client) -> None:
    ran = []
    with pytest.raises(ToolDenied, match="could not be built"):
        guard("x" * 300, client=client)(lambda: ran.append(1))()
    assert ran == [] and server.requests == []
