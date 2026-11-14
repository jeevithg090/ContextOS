"""PreToolUse decision → hook answer matrix, approval polling, restrictions and fail modes."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from contextos.config import Config
from contextos.integrations.claude_code import approval, mapping, observe
from contextos.integrations.claude_code.enforce import PreToolUseEnforcer, Verdict
from contextos.integrations.claude_code.hook_config import HookConfig
from contextos.integrations.claude_code.mapping import parse_payload

from . import claude_code_payloads as P
from .sdk_fakes import API_KEY, BASE_URL, FakeServer, decision_body

POLICY = {
    "policy_id": "pol_1",
    "name": "Block credential exfiltration",
    "outcome": "DENY",
    "mode": "enforce",
    "severity": "critical",
    "explanation": "secret in arguments",
}


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))


@pytest.fixture()
def server() -> FakeServer:
    return FakeServer()


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


def cfg(tmp_path: Path, **overrides) -> HookConfig:
    values = {"fail_mode": "ask", "approval_wait_s": 45.0, "on_approval_timeout": "ask"}
    values.update(overrides)
    return HookConfig(
        base=Config(url=BASE_URL, api_key=API_KEY, timeout_s=5.0),
        project_dir=tmp_path,
        agent_name="claude-code@shop-api",
        **values,
    )


def run(server: FakeServer, tmp_path: Path, clock: FakeClock, payload: dict, **cfg_overrides) -> Verdict:
    client = server.client(
        tmp_path, agent=mapping.agent_ref("claude-code@shop-api"), clock=clock, sleep=clock.sleep
    )
    config = cfg(tmp_path, **cfg_overrides)
    enforcer = PreToolUseEnforcer(
        client, config, deadline=clock() + config.decide_budget_s, clock=clock, poll_s=1.5
    )
    return enforcer.run(parse_payload(P.as_bytes(payload), "PreToolUse"))


def decide_returns(server: FakeServer, decision: str, **extra) -> None:
    server.route("POST", "/api/v1/decide", decision_body(decision, **extra))


def specific(verdict: Verdict) -> dict:
    out = verdict.to_output()
    assert out is not None
    return out["hookSpecificOutput"]


# -- the matrix ------------------------------------------------------------------------------------


@pytest.mark.parametrize("decision", ["ALLOW", "AUDIT"])
def test_allow_and_audit_emit_no_decision_so_claude_code_permissions_still_apply(
    server: FakeServer, tmp_path: Path, clock: FakeClock, decision: str
) -> None:
    decide_returns(server, decision)
    verdict = run(server, tmp_path, clock, P.PRE_BASH)
    assert verdict.permission is None
    assert verdict.to_output() is None  # nothing on stdout: never permissionDecision "allow"
    [body] = server.bodies("POST", "/api/v1/decide")
    assert body["event_type"] == "tool.requested" and body["arguments"] == P.PRE_BASH["tool_input"]
    assert body["integration"] == "claude_code"


def test_deny_cites_the_policy_and_decision(server: FakeServer, tmp_path: Path, clock: FakeClock) -> None:
    decide_returns(
        server,
        "DENY",
        reason="The arguments contain an AWS access key and webhook.site is SUSPICIOUS.",
        matched_policies=[POLICY],
        policy_decision_id="pd_42",
    )
    verdict = run(server, tmp_path, clock, P.PRE_EXFIL)
    out = specific(verdict)
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "deny"
    assert "“Block credential exfiltration”, critical" in out["permissionDecisionReason"]
    assert "pd_42" in out["permissionDecisionReason"]
    assert "webhook.site is SUSPICIOUS" in out["permissionDecisionReason"]
    assert "Block credential exfiltration" in verdict.to_output()["systemMessage"]


def test_deny_cites_only_the_policy_that_decided_not_audit_matches(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    audit = {
        **POLICY,
        "policy_id": "pol_2",
        "name": "Audit sensitive file reads",
        "outcome": "AUDIT",
        "severity": "medium",
    }
    monitor = {**POLICY, "policy_id": "pol_3", "name": "Trial rule", "mode": "monitor"}
    decide_returns(server, "DENY", matched_policies=[audit, POLICY, monitor])
    reason = specific(run(server, tmp_path, clock, P.PRE_EXFIL))["permissionDecisionReason"]
    assert "Policy: “Block credential exfiltration”, critical." in reason
    assert "Audit sensitive file reads" not in reason and "Trial rule" not in reason


def test_deny_by_the_default_decision_does_not_credit_an_audit_policy(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    audit = {**POLICY, "name": "Audit shell commands", "outcome": "AUDIT", "severity": "low"}
    decide_returns(server, "DENY", matched_policies=[audit])
    reason = specific(run(server, tmp_path, clock, P.PRE_BASH))["permissionDecisionReason"]
    assert "Policy: organisation default decision." in reason and "Audit shell commands" not in reason


def test_reasons_are_masked_locally_even_if_the_server_echoed_a_secret(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    decide_returns(server, "DENY", reason="found AKIAIOSFODNN7EXAMPLE in the command")
    out = specific(run(server, tmp_path, clock, P.PRE_EXFIL))
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(out)


def test_unrecognised_decision_fails_closed(server: FakeServer, tmp_path: Path, clock: FakeClock) -> None:
    decide_returns(server, "MAYBE")
    assert specific(run(server, tmp_path, clock, P.PRE_BASH))["permissionDecision"] == "deny"


def test_to_output_refuses_to_emit_allow() -> None:
    with pytest.raises(ValueError, match="refusing"):
        Verdict("allow").to_output()  # type: ignore[arg-type]


# -- approvals -------------------------------------------------------------------------------------


def approval_needed(server: FakeServer, statuses: list[tuple[int, dict]], **extra) -> None:
    fields = {
        "approval_id": "apr_1",
        "approval_status": "pending",
        "reason": "Outbound call while the session holds secrets and untrusted content.",
        "matched_policies": [
            {
                **POLICY,
                "name": "Require approval under the lethal trifecta",
                "severity": "high",
                "outcome": "REQUIRE_APPROVAL",
            }
        ],
        **extra,
    }
    decide_returns(server, "REQUIRE_APPROVAL", **fields)
    server.sequence("GET", "/api/v1/decide/approvals/apr_1", statuses)


def test_approved_while_waiting_lets_the_normal_flow_continue(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    approval_needed(
        server,
        [
            (200, {"approval_id": "apr_1", "status": "pending"}),
            (200, {"approval_id": "apr_1", "status": "approved"}),
        ],
    )
    verdict = run(server, tmp_path, clock, P.PRE_WEBFETCH)
    assert verdict.permission is None and verdict.outcome == "approved"
    assert len(server.calls("GET", "/api/v1/decide/approvals/apr_1")) == 2


def test_already_approved_needs_no_poll(server: FakeServer, tmp_path: Path, clock: FakeClock) -> None:
    approval_needed(server, [(200, {"status": "approved"})], approval_status="approved")
    assert run(server, tmp_path, clock, P.PRE_WEBFETCH).permission is None
    assert server.calls("GET", "/api/v1/decide/approvals/apr_1") == []


@pytest.mark.parametrize("status", ["rejected", "expired", "cancelled"])
def test_rejected_expired_or_cancelled_approval_denies(
    server: FakeServer, tmp_path: Path, clock: FakeClock, status: str
) -> None:
    approval_needed(
        server, [(200, {"approval_id": "apr_1", "status": status, "decision_note": "not this domain"})]
    )
    out = specific(run(server, tmp_path, clock, P.PRE_WEBFETCH))
    assert out["permissionDecision"] == "deny"
    assert f"apr_1 for this WebFetch call was {status}" in out["permissionDecisionReason"]
    if status == "rejected":
        assert "not this domain" in out["permissionDecisionReason"]


CANCEL = "/api/v1/decide/approvals/apr_1/cancel"


def cancel_returns(server: FakeServer, status: int, body: dict) -> None:
    server.route("POST", CANCEL, body, status=status)


def test_pending_after_the_wait_withdraws_the_request_and_asks(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    approval_needed(server, [(200, {"approval_id": "apr_1", "status": "pending"})])
    cancel_returns(server, 200, {"approval_id": "apr_1", "status": "cancelled"})
    start = clock()
    verdict = run(server, tmp_path, clock, P.PRE_WEBFETCH)
    out = specific(verdict)
    assert out["permissionDecision"] == "ask"
    assert out["permissionDecisionReason"].startswith(
        "ContextOS approval apr_1 was not decided within 45s — decide at this prompt. The request was withdrawn "
        "from the Approval Centre"
    )
    assert 44 <= clock() - start <= 46  # waited approval_wait_s (45 s) on the fake clock
    (body,) = server.bodies("POST", CANCEL)
    assert body == {"reason": "The Claude Code hook stopped waiting after 45s and answered 'ask'."}
    assert verdict.notes["approval_withdrawn"] is True
    record = approval.take_host_prompt(P.PRE_WEBFETCH["tool_use_id"])
    assert record == {"reason": "approval_pending", "approval_id": "apr_1", "policy_decision_id": "pd_1"}


def test_pending_after_the_wait_denies_when_configured(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    approval_needed(server, [(200, {"status": "pending"})])
    cancel_returns(server, 200, {"approval_id": "apr_1", "status": "cancelled"})
    out = specific(run(server, tmp_path, clock, P.PRE_WEBFETCH, on_approval_timeout="deny"))
    assert out["permissionDecision"] == "deny" and "still pending" in out["permissionDecisionReason"]
    # An approval belongs to one call: the reason must not suggest approving the stale request helps.
    assert "can no longer be approved" in out["permissionDecisionReason"]
    assert "approve the new request" in out["permissionDecisionReason"]
    assert server.bodies("POST", CANCEL)[0]["reason"].endswith("answered 'deny'.")


def test_a_withdrawal_the_server_cannot_record_keeps_the_answer_honest(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    approval_needed(server, [(200, {"status": "pending"})])
    cancel_returns(server, 503, {"error": {"code": "unavailable", "message": "down", "details": None}})
    verdict = run(server, tmp_path, clock, P.PRE_WEBFETCH, on_approval_timeout="deny")
    out = specific(verdict)
    assert out["permissionDecision"] == "deny"
    assert "Approving that request now will not run this call" in out["permissionDecisionReason"]
    assert verdict.notes["approval_withdrawn"] is False


@pytest.mark.parametrize(
    ("status", "permission"), [("approved", None), ("rejected", "deny"), ("expired", "deny")]
)
def test_a_decision_made_just_before_the_withdrawal_wins(
    server: FakeServer, tmp_path: Path, clock: FakeClock, status: str, permission: str | None
) -> None:
    """The person decided between the last poll and the withdrawal: the server answers 409 with it."""
    approval_needed(server, [(200, {"status": "pending"})])
    cancel_returns(
        server,
        409,
        {
            "error": {
                "code": "conflict",
                "message": f"Approval already {status}",
                "details": {"status": status, "decided_at": "2026-11-11T10:00:00Z"},
            }
        },
    )
    verdict = run(server, tmp_path, clock, P.PRE_WEBFETCH)
    assert verdict.permission == permission
    assert verdict.outcome == ("approved" if status == "approved" else f"approval_{status}")


def test_approval_wait_always_fits_inside_the_hook_timeout(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    approval_needed(server, [(200, {"status": "pending"})])
    start = clock()
    run(server, tmp_path, clock, P.PRE_WEBFETCH, approval_wait_s=600, hook_timeout_s=60)
    assert clock() - start <= 60 - 3 - 5  # hook timeout minus margin minus the decide timeout


def test_approval_that_cannot_be_checked_denies(server: FakeServer, tmp_path: Path, clock: FakeClock) -> None:
    approval_needed(server, [(404, {"error": {"code": "not_found", "message": "Approval not found"}})])
    out = specific(run(server, tmp_path, clock, P.PRE_WEBFETCH))
    assert out["permissionDecision"] == "deny" and "could not be checked" in out["permissionDecisionReason"]


def test_approval_without_an_id_fails_closed(server: FakeServer, tmp_path: Path, clock: FakeClock) -> None:
    decide_returns(server, "REQUIRE_APPROVAL")
    assert specific(run(server, tmp_path, clock, P.PRE_WEBFETCH))["permissionDecision"] == "deny"


# -- restrictions ----------------------------------------------------------------------------------


def test_path_restrictions_that_pass_need_no_decision(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    project = (tmp_path / "proj").resolve()
    project.mkdir()
    (project / "README.md").write_text("# hi")
    decide_returns(server, "RESTRICT", restrictions={"allowed_path_globs": [f"{project}/*"]})
    payload = {**P.PRE_READ, "cwd": str(project), "tool_input": {"file_path": str(project / "README.md")}}
    verdict = run(server, tmp_path, clock, payload)
    assert verdict.permission is None and verdict.outcome == "restrict_satisfied"


def test_path_outside_the_allowed_globs_is_denied(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    decide_returns(server, "RESTRICT", restrictions={"allowed_path_globs": ["/srv/other/*"]})
    out = specific(run(server, tmp_path, clock, P.PRE_READ))
    assert (
        out["permissionDecision"] == "deny"
        and "outside the allowed patterns" in out["permissionDecisionReason"]
    )


def test_path_restrictions_on_a_shell_command_fail_closed(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    decide_returns(server, "RESTRICT", restrictions={"deny_path_globs": ["*.env"]})
    out = specific(run(server, tmp_path, clock, P.PRE_BASH))
    assert (
        out["permissionDecision"] == "deny"
        and "cannot be checked for Bash" in out["permissionDecisionReason"]
    )


def test_secret_redaction_asks_with_the_masked_input(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    decide_returns(server, "RESTRICT", restrictions={"redact_secrets": True})
    server.route("POST", "/api/v1/scan", {"secrets": [], "hits": []})
    payload = {
        **P.PRE_WEBFETCH,
        "tool_input": {"url": "https://api.example.com/x?key=AKIAIOSFODNN7EXAMPLE", "prompt": "summarise"},
    }
    out = specific(run(server, tmp_path, clock, payload))
    assert out["permissionDecision"] == "ask"
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(out["updatedInput"])
    assert "[REDACTED:aws_access_key]" in out["updatedInput"]["url"]
    assert out["updatedInput"]["prompt"] == "summarise"  # the whole input object is returned


def test_secret_redaction_without_a_server_recheck_fails_closed(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    decide_returns(server, "RESTRICT", restrictions={"redact_secrets": True})
    server.route(
        "POST", "/api/v1/scan", {"error": {"code": "forbidden", "message": "missing scope read"}}, status=403
    )
    payload = {**P.PRE_WEBFETCH, "tool_input": {"url": "https://x.example.com/?k=AKIAIOSFODNN7EXAMPLE"}}
    assert specific(run(server, tmp_path, clock, payload))["permissionDecision"] == "deny"


def test_unknown_restrictions_fail_closed(server: FakeServer, tmp_path: Path, clock: FakeClock) -> None:
    decide_returns(server, "RESTRICT", restrictions={"sandbox": "strict"})
    out = specific(run(server, tmp_path, clock, P.PRE_READ))
    assert out["permissionDecision"] == "deny" and "fail closed" in out["permissionDecisionReason"]


# -- fail modes ------------------------------------------------------------------------------------


@pytest.mark.parametrize(("mode", "expected"), [("closed", "deny"), ("ask", "ask"), ("open", None)])
def test_unreachable_server_follows_the_fail_mode(
    server: FakeServer, tmp_path: Path, clock: FakeClock, mode: str, expected: str | None
) -> None:
    server.down = True
    verdict = run(server, tmp_path, clock, P.PRE_BASH, fail_mode=mode)
    assert verdict.permission == expected
    out = verdict.to_output() or {}
    assert "allow" not in json.dumps(out.get("hookSpecificOutput", {}))
    if mode == "open":
        assert "WITHOUT a policy decision" in out["systemMessage"]
    spooled = [
        json.loads(line) for line in (tmp_path / "spool" / "test-agent.jsonl").read_text().splitlines()
    ]
    assert spooled[0]["event_type"] == "tool.requested"
    assert spooled[0]["metadata"]["decision_unavailable"] is True
    assert (
        spooled[0]["metadata"]["local_outcome"]
        == {"closed": "not_run", "ask": "asked_user", "open": "ran_unguarded"}[mode]
    )


@pytest.mark.parametrize("status", [500, 503])
def test_server_errors_follow_the_fail_mode(
    server: FakeServer, tmp_path: Path, clock: FakeClock, status: int
) -> None:
    server.route("POST", "/api/v1/decide", {"error": {"code": "internal", "message": "boom"}}, status=status)
    assert run(server, tmp_path, clock, P.PRE_BASH, fail_mode="closed").permission == "deny"


@pytest.mark.parametrize("status", [401, 403])
def test_rejected_api_key_always_denies_even_in_open_mode(
    server: FakeServer, tmp_path: Path, clock: FakeClock, status: int
) -> None:
    server.route(
        "POST",
        "/api/v1/decide",
        {"error": {"code": "unauthorized", "message": "Invalid API key"}},
        status=status,
    )
    out = specific(run(server, tmp_path, clock, P.PRE_BASH, fail_mode="open"))
    assert (
        out["permissionDecision"] == "deny"
        and "rejected this hook's API key" in out["permissionDecisionReason"]
    )


def test_invalid_request_follows_the_fail_mode_and_is_not_spooled(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    server.route(
        "POST",
        "/api/v1/decide",
        {"error": {"code": "validation_error", "message": "bad envelope"}},
        status=422,
    )
    verdict = run(server, tmp_path, clock, P.PRE_BASH, fail_mode="ask")
    assert verdict.permission == "ask" and "bad envelope" in (verdict.reason or "")
    assert not (tmp_path / "spool" / "test-agent.jsonl").exists()


def test_input_too_large_to_evaluate_is_never_truncated(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    payload = {**P.PRE_BASH, "tool_input": {"command": "echo " + "x" * 600_000}}
    verdict = run(server, tmp_path, clock, payload, fail_mode="closed")
    assert verdict.permission == "deny" and "above the 500,000-byte limit" in (verdict.reason or "")
    assert server.calls("POST", "/api/v1/decide") == []


def test_ask_from_fail_mode_is_recorded_for_the_post_tool_use_hook(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    server.down = True
    run(server, tmp_path, clock, P.PRE_BASH, fail_mode="ask")
    assert approval.take_host_prompt(P.PRE_BASH["tool_use_id"]) == {"reason": "fail_ask"}
    assert approval.take_host_prompt(P.PRE_BASH["tool_use_id"]) is None


# -- delegation ------------------------------------------------------------------------------------


def test_allowed_agent_call_reports_the_delegation(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    decide_returns(server, "ALLOW")
    run(server, tmp_path, clock, P.PRE_AGENT)
    [event] = server.events_of("agent.delegated")
    assert event["delegation"]["child_agent"]["name"] == "claude-code@shop-api/Explore"
    h = parse_payload(P.as_bytes(P.POST_AGENT_ASYNC), "PostToolUse")
    events = observe.observation_events(h, mapping.agent_ref("claude-code@shop-api"), max_result_chars=1000)
    assert [e.event_type for e in events] == ["tool.completed"]  # background launch: child stays open


def test_denied_agent_call_reports_no_delegation(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    decide_returns(server, "DENY")
    run(server, tmp_path, clock, P.PRE_AGENT)
    assert server.events_of("agent.delegated") == []


def test_decide_is_never_retried_after_the_request_was_sent(
    server: FakeServer, tmp_path: Path, clock: FakeClock
) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    server.route("POST", "/api/v1/decide", handler=timeout)
    run(server, tmp_path, clock, P.PRE_BASH, fail_mode="closed")
    assert len(server.calls("POST", "/api/v1/decide")) == 1
