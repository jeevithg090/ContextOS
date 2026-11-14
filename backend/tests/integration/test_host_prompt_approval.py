"""A call held for approval that ran after the person approved it at Claude Code's own prompt.

The Claude Code hook answers ``ask`` when nobody decides the approval in time, withdraws the request
and records the hand-over; PostToolUse then reports ``approved_at_host_prompt`` with that approval
id. ContextOS records a low-severity, reviewable finding instead of the high-severity "decision not
honoured" (bypassed hook) finding — but only when the report matches the held approval. ContextOS
cannot verify the host's approval, so the report never makes the call look approved in ContextOS.
"""

from __future__ import annotations

from sqlalchemy import select

from app.models import Approval, SecurityFinding, ToolInvocation
from tests.integration.agents_support import MALICIOUS_README
from tests.integration.ingestion_support import decide, post_events, run_tool, tool_completed, tool_requested

URL = {"url": "https://status.partner-api.example/health"}


def _held(client, org, session: str = "sess-host") -> tuple[dict, dict]:
    run_tool(
        client,
        org.api_headers,
        "Read",
        {"file_path": "/work/app/README.md"},
        MALICIOUS_README,
        session=session,
    )
    request = tool_requested("WebFetch", URL, session=session)
    held = decide(client, org.api_headers, request)
    assert held["decision"] == "REQUIRE_APPROVAL" and held["approval_id"]
    return request, held


def _complete(client, org, request: dict, **metadata) -> None:
    post_events(
        client,
        org.api_headers,
        tool_completed(
            "WebFetch",
            URL,
            "ok",
            correlation_id=request["correlation_id"],
            session=request["session_id"],
            metadata=metadata,
        ),
    )


def _rules(db, org_id: str) -> set[str]:
    db.rollback()
    return set(db.scalars(select(SecurityFinding.rule_id).where(SecurityFinding.organization_id == org_id)))


def test_withdrawn_approval_then_host_prompt_approval_is_a_low_finding(client, seeded_org, db):
    request, held = _held(client, seeded_org)
    cancelled = client.post(
        f"/api/v1/decide/approvals/{held['approval_id']}/cancel",
        json={"reason": "hook stopped waiting"},
        headers=seeded_org.api_headers,
    )
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    _complete(
        client,
        seeded_org,
        request,
        approved_at_host_prompt=True,
        host_prompt={"reason": "approval_pending", "approval_id": held["approval_id"]},
    )

    rules = _rules(db, seeded_org.org_id)
    assert "CTX-APPROVED-AT-HOST-PROMPT" in rules and "CTX-DECISION-NOT-HONOURED" not in rules
    finding = db.scalar(
        select(SecurityFinding).where(SecurityFinding.rule_id == "CTX-APPROVED-AT-HOST-PROMPT")
    )
    assert finding.severity == "low" and "cannot verify" in finding.explanation
    assert finding.tool_invocation_id == held["tool_invocation_id"]
    assert db.get(ToolInvocation, held["tool_invocation_id"]).status == "completed"
    assert db.get(Approval, held["approval_id"]).status == "cancelled"  # never shown as approved in ContextOS


def test_a_host_prompt_report_that_does_not_match_the_approval_is_not_trusted(client, seeded_org, db):
    request, held = _held(client, seeded_org)
    _complete(
        client,
        seeded_org,
        request,
        approved_at_host_prompt=True,
        host_prompt={"reason": "approval_pending", "approval_id": "apr_someone_else"},
    )
    rules = _rules(db, seeded_org.org_id)
    assert "CTX-DECISION-NOT-HONOURED" in rules and "CTX-APPROVED-AT-HOST-PROMPT" not in rules


def test_denied_calls_cannot_be_excused_by_a_host_prompt_report(client, seeded_org, db):
    run_tool(client, seeded_org.api_headers, "Read", {"file_path": "/work/app/README.md"}, MALICIOUS_README)
    request = tool_requested("Read", {"file_path": "/home/dev/.ssh/id_rsa"})
    denied = decide(client, seeded_org.api_headers, request)
    assert denied["decision"] == "DENY"
    post_events(
        client,
        seeded_org.api_headers,
        tool_completed(
            "Read",
            {"file_path": "/home/dev/.ssh/id_rsa"},
            "key",
            correlation_id=request["correlation_id"],
            metadata={"approved_at_host_prompt": True, "host_prompt": {"approval_id": None}},
        ),
    )
    finding = db.scalar(select(SecurityFinding).where(SecurityFinding.rule_id == "CTX-DECISION-NOT-HONOURED"))
    assert finding is not None and finding.severity == "high"
    assert "CTX-APPROVED-AT-HOST-PROMPT" not in _rules(db, seeded_org.org_id)


def test_other_integrations_cannot_claim_a_host_prompt(client, seeded_org, db):
    run_tool(
        client,
        seeded_org.api_headers,
        "Read",
        {"file_path": "/work/app/README.md"},
        MALICIOUS_README,
        integration="python_sdk",
    )
    request = tool_requested("WebFetch", URL, integration="python_sdk")
    held = decide(client, seeded_org.api_headers, request)
    assert held["decision"] == "REQUIRE_APPROVAL"
    post_events(
        client,
        seeded_org.api_headers,
        tool_completed(
            "WebFetch",
            URL,
            "ok",
            correlation_id=request["correlation_id"],
            integration="python_sdk",
            metadata={"approved_at_host_prompt": True, "host_prompt": {"approval_id": held["approval_id"]}},
        ),
    )
    rules = _rules(db, seeded_org.org_id)
    assert "CTX-DECISION-NOT-HONOURED" in rules and "CTX-APPROVED-AT-HOST-PROMPT" not in rules
