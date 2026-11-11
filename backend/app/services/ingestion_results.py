"""``tool.completed`` / ``tool.failed``: pair the result with its request and record the result (or
the error text of a failure, which the model also reads) as context whose source is derived
SERVER-SIDE from the tool and its arguments (never from the client).

Pairing: ``correlation_id`` within the session first; otherwise the most recent unfinished call of
the same tool (without a correlation id). A result with no recorded request creates the invocation
as observed (enforcement ``observed``), evaluating policy so the would-be decision is still visible.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.domain.enums import Decision, EventType, FindingCategory, Severity, SourceType, ToolCategory
from app.models import Destination, Tool, ToolInvocation
from app.services.ingestion_context import ContextInput, record_context
from app.services.ingestion_entities import tool_identity
from app.services.ingestion_findings import raise_finding
from app.services.ingestion_handlers import known_tool, mcp_server_ceiling
from app.services.ingestion_known_secrets import redact_session_text
from app.services.ingestion_state import PipelineState, preview_of, result_text
from app.services.ingestion_tools import decide_request

# Statuses meaning ContextOS did not let the call run (or it was still waiting for a person).
NOT_ALLOWED = {"denied", "rejected", "pending_approval", "expired", "cancelled"}
FINISHED = {"completed", "failed"}  # a repeated result for the same call is not a new transfer
_QUERY_KEYS = ("query", "q", "search_query", "search", "keywords")
_WEB_CATEGORIES = {ToolCategory.HTTP.value, ToolCategory.BROWSER.value}


def find_invocation(st: PipelineState, tool: Tool | None) -> ToolInvocation | None:
    assert st.session is not None
    base = select(ToolInvocation).where(
        ToolInvocation.organization_id == st.ctx.org_id, ToolInvocation.session_id == st.session.id
    )
    cid = st.env.correlation_id
    if cid:
        found = st.db.scalars(
            base.where(ToolInvocation.correlation_id == cid).order_by(ToolInvocation.requested_at.desc()).limit(1)
        ).first()
        if found is not None:
            return found
    if tool is None:
        return None
    return st.db.scalars(
        base.where(
            ToolInvocation.tool_id == tool.id,
            ToolInvocation.completed_at.is_(None),
            ToolInvocation.correlation_id.is_(None),
        ).order_by(ToolInvocation.requested_at.desc()).limit(1)
    ).first()


def _first(resources: list[dict[str, Any]], kind: str) -> str | None:
    return next((str(r["id"]) for r in resources if isinstance(r, dict) and r.get("kind") == kind and r.get("id")), None)


def result_source(tool: Tool, inv: ToolInvocation) -> tuple[str, str, str]:
    """(source_type, identifier, display_name) for a tool result, from the server's own records."""
    category, resources = tool.category, list(inv.resources or [])
    if category == ToolCategory.FILE_READ.value:
        path = _first(resources, "file")
        if path:
            return SourceType.FILE.value, path, path
    if category in _WEB_CATEGORIES:
        url = _first(resources, "url")
        if url:
            return SourceType.WEB.value, url, url
    if tool.server:
        ident = f"{tool.server}/{tool.name}"
        return SourceType.MCP_TOOL.value, ident, f"MCP tool {ident}"
    if category == ToolCategory.SEARCH.value:
        args = inv.arguments_redacted or {}
        query = next((str(args[k]) for k in _QUERY_KEYS if isinstance(args.get(k), str) and args[k].strip()), None)
        if query:
            return SourceType.WEB.value, f"search:{query[:300]}", f"Web search: {query[:200]}"
    ident = f"{tool.provider}/{tool.name}"
    return SourceType.TOOL_OUTPUT.value, ident, f"Output of {ident}"


def handle_tool_result(st: PipelineState, started: float) -> None:
    env = st.env
    assert env.tool is not None and st.session is not None and st.agent is not None
    provider, name, _server = tool_identity(env.tool, st.integration_kind)
    tool = known_tool(st, provider, name)
    inv = find_invocation(st, tool)
    first_seen = inv is None
    if inv is None:
        inv = decide_request(st, started=started, completed=True).invocation
        tool = st.db.get(Tool, inv.tool_id)
    elif tool is None or tool.id != inv.tool_id:
        tool = st.db.get(Tool, inv.tool_id)
    assert tool is not None
    prior_status = inv.status
    failed = env.event_type == EventType.TOOL_FAILED or env.is_error
    inv.status = "failed" if failed else "completed"
    inv.completed_at = st.now
    inv.result_event_id = st.event.id
    st.refs["tool_invocation_id"] = inv.id
    text, content_type = result_text(env.result)
    if failed:
        # The error text reaches the model like any result (and can carry injected instructions),
        # so it is recorded and scanned as context too.
        text = text or str((env.metadata or {}).get("error") or "")
        if st.store_previews:
            error = redact_session_text(st, text) or ""
            inv.error = (error[:1999] + "…" if len(error) > 2000 else error) or "Tool reported a failure"
        else:  # the organisation stores no content text: keep only the fact and the size
            inv.error = (f"Tool reported a failure ({len(text):,} characters of error output; content previews "
                         "are disabled)") if text else "Tool reported a failure"
    if text:
        source_type, identifier, display = result_source(tool, inv)
        outcome = record_context(st, ContextInput(
            source_type=source_type, identifier=identifier, display_name=display, raw_text=text,
            content_type=content_type if env.content_type == "text/plain" else env.content_type,
            tool_invocation_id=inv.id,
            item_metadata={"tool": f"{tool.provider}/{tool.name}", **({"tool_failed": True} if failed else {})},
            trust_ceiling=mcp_server_ceiling(st, tool.server) if source_type == SourceType.MCP_TOOL.value else None,
        ))
        inv.result_context_item_id = outcome.item.id
        if not failed:
            inv.result_summary = preview_of(redact_session_text(st, text) or "") if st.store_previews else None
    if not first_seen and not failed and prior_status not in FINISHED:
        _count_late_transfer(st, inv)
    if not first_seen and prior_status in NOT_ALLOWED:
        _decision_not_honoured(st, inv, tool, prior_status)


def _count_late_transfer(st: PipelineState, inv: ToolInvocation) -> None:
    """A call whose transfer was not counted when it was decided (held for approval, or blocked at an
    enforcing boundary) has now completed, so the data did reach its destination: count it.

    Calls decided ALLOW / AUDIT / RESTRICT, and every observed call, were counted at request time
    (``ingestion_tools``); ``blocked_count`` keeps recording the decision itself.
    """
    if not inv.destination_id:
        return
    held = inv.decision == Decision.REQUIRE_APPROVAL and inv.enforcement != "observed"
    blocked = inv.decision == Decision.DENY and inv.enforcement == "enforced"
    if not (held or blocked):
        return
    dest = st.db.scalar(select(Destination).where(
        Destination.organization_id == st.ctx.org_id, Destination.id == inv.destination_id))
    if dest is None:
        return
    dest.transfer_count = (dest.transfer_count or 0) + 1
    sensitive = (inv.sensitive_data_detected or bool(inv.matched_session_fingerprints)
                 or any(isinstance(r, dict) and r.get("sensitive") for r in inv.resources or []))
    if sensitive:
        dest.sensitive_transfer_count = (dest.sensitive_transfer_count or 0) + 1
    st.refs["destination_id"] = dest.id


def _decision_not_honoured(st: PipelineState, inv: ToolInvocation, tool: Tool, prior_status: str) -> None:
    """The tool reported a result although ContextOS had not allowed it to run."""
    enforced = inv.enforcement == "enforced"
    st.refs["executed_despite"] = prior_status
    raise_finding(
        st,
        category=FindingCategory.POLICY_VIOLATION.value,
        rule_id="CTX-DECISION-NOT-HONOURED",
        title=f"{tool.name} ran although ContextOS returned {inv.decision} ({prior_status.replace('_', ' ')})"[:400],
        explanation=(
            f"ContextOS returned {inv.decision} for this call ({inv.enforcement}), yet the integration reported "
            f"that the tool {'completed' if inv.status == 'completed' else 'ran and failed'}. "
            + ("The integration is expected to enforce decisions, so this indicates a misconfigured or bypassed "
               "hook." if enforced else "This integration does not enforce decisions, so the call ran anyway.")
        ),
        severity=Severity.HIGH.value if enforced else Severity.MEDIUM.value,
        confidence=0.9,
        evidence=[{"type": "tool_invocation", "id": inv.id, "excerpt": None,
                   "detail": f"status before the result: {prior_status}; decision {inv.decision}"}],
        tool_invocation_id=inv.id,
        policy_decision_id=inv.policy_decision_id,
        destination_id=inv.destination_id,
    )
