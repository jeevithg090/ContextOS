"""Plain-language helpers of the Approval Centre (pure functions)."""

from __future__ import annotations

from app.services.approvals_present import (
    describe_action,
    enforcement_note,
    matched_policy,
    risk_summary,
    session_risk,
)


def test_describe_action_uses_category_method_and_target():
    assert describe_action("WebFetch", "http", {"method": "post"}, "webhook.site") == "send POST to webhook.site"
    assert describe_action("WebFetch", "http", {"url": "https://a.example"}, "a.example") == "fetch a.example"
    assert describe_action("WebFetch", "http", {}, None) == "make an HTTP request with WebFetch"
    assert describe_action("send_email", "email", {}, "ops@acme.test") == "send an email to ops@acme.test"
    assert describe_action("Bash", "shell", {"command": "curl https://x.io"}, "x.io",
                           destination="x.io") == "run a shell command that contacts x.io"
    assert describe_action("Bash", "shell", {"command": "rm -rf build"}, None) == "run the shell command `rm -rf build`"
    assert describe_action("Write", "file_write", {}, "/srv/app.py") == "write to /srv/app.py"
    assert describe_action("deploy", "infrastructure", {}, None) == "change infrastructure with deploy"
    assert describe_action(None, None, None, None) == "use a tool"


def test_describe_action_truncates_long_values():
    phrase = describe_action("Bash", "shell", {"command": "echo " + "a" * 500}, None)
    assert len(phrase) < 120 and phrase.endswith("…`")


def test_matched_policy_and_risk_summary_tolerate_partial_records():
    assert matched_policy({"policy_id": "pol_1", "name": "P", "version": "2"})["version"] is None
    assert matched_policy(None)["name"] == "Unnamed policy"
    summary = risk_summary({"session_score": "41", "destination": {"classification": "SUSPICIOUS"},
                            "secrets_in_arguments": 2})
    assert summary["session_score"] == 41 and summary["destination_classification"] == "SUSPICIOUS"
    assert summary["secrets_in_arguments"] == 2 and summary["trifecta"] is False
    assert risk_summary(None)["destination_classification"] is None


def test_session_risk_separates_decision_time_from_current_evidence():
    snapshot = {"session": {"score": 60, "level": "high", "trifecta": False, "sensitive_access": True},
                "context": {"lowest_trust": "SUSPICIOUS"}}
    state = {"level": "critical", "computed_at": "2026-01-01T00:00:00+00:00",
             "trifecta_evidence": {"sensitive_access": [{"type": "context_item", "id": "ctx_1", "detail": "secret"}]}}
    out = session_risk(snapshot, state, 90)
    legs = {leg["key"]: leg for leg in out["legs"]}
    assert legs["sensitive_access"]["active_at_decision"] is True
    assert legs["untrusted_exposure"]["active_at_decision"] is False
    assert legs["sensitive_access"]["evidence"] == [{"type": "context_item", "id": "ctx_1", "detail": "secret"}]
    assert (out["score_at_decision"], out["current_score"], out["current_level"]) == (60, 90, "critical")
    assert out["context_at_decision"] == {"lowest_trust": "SUSPICIOUS"}


def test_enforcement_note_never_overclaims():
    observed = enforcement_note(status="pending", enforcement="observed", integration="custom", invocation_status=None)
    assert observed.startswith("Observed only")
    advisory = enforcement_note(status="pending", enforcement="advisory", integration="langgraph",
                                invocation_status="pending_approval")
    assert advisory.startswith("Advisory only.") and "may already have run" in advisory
    enforced = enforcement_note(status="pending", enforcement="enforced", integration="claude_code",
                                invocation_status="pending_approval")
    assert enforced.startswith("Claude Code hook paused this call")
    ran = enforcement_note(status="rejected", enforcement="enforced", integration="mcp_gateway",
                           invocation_status="completed")
    assert "not honoured" in ran
    approved = enforcement_note(status="approved", enforcement="enforced", integration="mcp_gateway",
                                invocation_status="completed")
    assert approved.startswith("Approved.")
    late = enforcement_note(status="approved", enforcement="enforced", integration="claude_code",
                            invocation_status="completed", ran_before_decision=True)
    assert "already reported this call as completed" in late
