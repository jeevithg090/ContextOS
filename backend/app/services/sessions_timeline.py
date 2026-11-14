"""Session timelines: the plain-language, server-ordered history of one agent session.

Built from the ingested-event log (already redacted) of the caller's organisation, joined to the
records each event produced (context items, tool calls, decisions, findings). Decisions are worded
by their enforcement mode: only enforced decisions are described as denials or holds; advisory
decisions say the integration may not honour them, and observed ones that nothing was prevented.
Entries are listed in recorded order; order is not causation.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import Session

from app.domain.enums import SEVERITY_RANK
from app.models import (
    Agent,
    AgentSession,
    ContextItem,
    ContextSource,
    Destination,
    IngestedEvent,
    PolicyDecision,
    SecurityFinding,
    Tool,
    ToolInvocation,
)
from app.services.scoping import get_scoped, paginate, scoped

_QUERY_KEYS = ("query", "q", "search_query", "search", "keywords")
_TOOL_EVENTS = {"tool.requested", "tool.completed", "tool.failed"}
_SOURCE_TITLES = {
    "file": "Read file {}",
    "repository": "Read repository file {}",
    "web": "Fetched web page {}",
    "browser": "Viewed page {}",
    "document": "Read document {}",
    "email": "Read email {}",
    "api": "Received API response from {}",
    "mcp_server": "Received content from MCP server {}",
    "mcp_tool": "Received MCP tool output {}",
    "database": "Read database result {}",
    "user_upload": "Received uploaded file {}",
    "tool_output": "Received tool output {}",
    "agent_output": "Received output from agent {}",
    "system": "Loaded system context {}",
}
_COMPLETED = {
    "file_read": "Read file {}",
    "file_write": "Wrote file {}",
    "http": "Fetched {}",
    "browser": "Browsed {}",
    "shell": "Ran `{}`",
    "search": "Searched for “{}”",
}
_ENFORCED = {
    "ALLOW": "Allowed {}",
    "AUDIT": "Allowed {} (audited)",
    "RESTRICT": "Restricted {}",
    "DENY": "Denied {}",
    "REQUIRE_APPROVAL": "Held {} for approval",
}
_ADVISED = {
    "ALLOW": "Advised to allow {}",
    "AUDIT": "Advised to allow {} (audit)",
    "RESTRICT": "Advised to restrict {}",
    "DENY": "Advised to deny {}",
    "REQUIRE_APPROVAL": "Advised to require approval for {}",
}
_EXPLANATION_CHARS = 1000

__all__ = ["clip", "session_timeline", "timeline_entries", "timeline_query"]


def timeline_query(org_id: str, session: AgentSession, agent_name: str) -> Select[Any]:
    """The session's events, events recorded elsewhere that delivered content into it (a parent's
    delegation carrying this session's task) and events that failed before the session was resolved
    (matched by the integration's session id and agent name kept in their redacted payload)."""
    delivered = select(ContextItem.event_id).where(
        ContextItem.organization_id == org_id,
        ContextItem.session_id == session.id,
        ContextItem.origin_session_id.is_not(None),
    )
    payload = IngestedEvent.payload_redacted
    failed = and_(
        IngestedEvent.session_id.is_(None),
        IngestedEvent.processing_status == "error",
        payload["session_id"].as_string() == session.external_session_id,
        payload["agent"]["name"].as_string() == agent_name,
    )
    return scoped(IngestedEvent, org_id).where(
        or_(IngestedEvent.session_id == session.id, IngestedEvent.id.in_(delivered), failed)
    )


def session_timeline(
    db: Session,
    org_id: str,
    session_id: str,
    *,
    limit: int,
    offset: int,
    focus_invocation_id: str | None = None,
) -> dict[str, Any]:
    """One page of the timeline in server sequence order. With ``focus_invocation_id`` the page that
    contains that tool call's first event is returned (``offset`` is ignored)."""
    session = get_scoped(db, AgentSession, session_id, org_id, label="Session")
    agent = get_scoped(db, Agent, session.agent_id, org_id, label="Agent")
    query = timeline_query(org_id, session, agent.name)
    focus: list[str] = []
    if focus_invocation_id:
        inv = db.scalar(
            scoped(ToolInvocation, org_id).where(
                ToolInvocation.id == focus_invocation_id, ToolInvocation.session_id == session.id
            )
        )
        event_ids = [e for e in ((inv.request_event_id, inv.result_event_id) if inv else ()) if e]
        first = (
            db.scalar(
                select(func.min(IngestedEvent.sequence)).where(
                    IngestedEvent.organization_id == org_id, IngestedEvent.id.in_(event_ids)
                )
            )
            if event_ids
            else None
        )
        if first is not None:
            before = (
                db.scalar(
                    select(func.count()).select_from(query.where(IngestedEvent.sequence < first).subquery())
                )
                or 0
            )
            offset, focus = (int(before) // limit) * limit, event_ids
    rows, total = paginate(db, query.order_by(IngestedEvent.sequence), limit=limit, offset=offset)
    return {
        "items": timeline_entries(db, org_id, session, rows),
        "total": total,
        "limit": limit,
        "offset": offset,
        "focus_event_ids": focus,
    }


def timeline_entries(
    db: Session, org_id: str, session: AgentSession, rows: list[IngestedEvent]
) -> list[dict[str, Any]]:
    """Display entries for ``rows`` (events of ``session``'s timeline, in the order given).

    ``explanation`` is the recorded decision explanation for tool requests (``None`` otherwise).
    """
    refs = [r.refs or {} for r in rows]
    inv_ids = {str(r["tool_invocation_id"]) for r in refs if r.get("tool_invocation_id")}
    item_ids = {str(i) for r in refs for i in _item_ids(r)}
    dec_ids = {str(r["policy_decision_id"]) for r in refs if r.get("policy_decision_id")}
    fnd_ids = {str(f) for r in refs for f in r.get("finding_ids") or []}
    invs = (
        {
            inv.id: (inv, tool)
            for inv, tool in db.execute(
                select(ToolInvocation, Tool)
                .join(Tool, Tool.id == ToolInvocation.tool_id)
                .where(ToolInvocation.organization_id == org_id, ToolInvocation.id.in_(inv_ids))
            )
        }
        if inv_ids
        else {}
    )
    dest_ids = {inv.destination_id for inv, _t in invs.values() if inv.destination_id}
    dests = (
        dict(
            db.execute(
                select(Destination.id, Destination.identifier).where(
                    Destination.organization_id == org_id, Destination.id.in_(dest_ids)
                )
            ).all()
        )
        if dest_ids
        else {}
    )
    items = (
        {
            r.id: r
            for r in db.execute(
                select(
                    ContextItem.id,
                    ContextItem.session_id,
                    ContextItem.trust_level,
                    ContextItem.content_length,
                    ContextItem.sensitivity,
                    ContextItem.detection_summary,
                    ContextSource.source_type,
                    ContextSource.identifier,
                    ContextSource.display_name,
                )
                .join(ContextSource, ContextSource.id == ContextItem.source_id)
                .where(ContextItem.organization_id == org_id, ContextItem.id.in_(item_ids))
            )
        }
        if item_ids
        else {}
    )
    decisions = (
        {
            r.id: r
            for r in db.execute(
                select(
                    PolicyDecision.id,
                    PolicyDecision.decision,
                    PolicyDecision.enforcement,
                    PolicyDecision.explanation,
                ).where(PolicyDecision.organization_id == org_id, PolicyDecision.id.in_(dec_ids))
            )
        }
        if dec_ids
        else {}
    )
    severities = (
        dict(
            db.execute(
                select(SecurityFinding.id, SecurityFinding.severity).where(
                    SecurityFinding.organization_id == org_id, SecurityFinding.id.in_(fnd_ids)
                )
            ).all()
        )
        if fnd_ids
        else {}
    )

    out = []
    for row, ref in zip(rows, refs, strict=True):
        other = row.session_id is not None and row.session_id != session.id
        candidates = [items[i] for i in _item_ids(ref) if i in items]
        item = next(
            (c for c in candidates if c.session_id == session.id), candidates[0] if candidates else None
        )
        inv, tool = invs.get(str(ref.get("tool_invocation_id") or ""), (None, None))
        dec = decisions.get(str(ref.get("policy_decision_id") or ""))
        decision = dec.decision if dec else None
        enforcement = dec.enforcement if dec else None
        sevs = [severities[f] for f in ref.get("finding_ids") or [] if f in severities]
        payload = row.payload_redacted or {}
        if row.processing_status == "error":
            title = f"Could not process {row.event_type} event"
            summary = clip(row.processing_error, 300) or "The pipeline recorded an error for this event."
        elif row.event_type in _TOOL_EVENTS:
            dest = dests.get(inv.destination_id) if inv and inv.destination_id else None
            title, summary = _tool_text(row.event_type, payload, ref, inv, tool, item, dec, dest)
        else:
            title, summary = _describe(row.event_type, payload, ref, item, other)
        out.append(
            {
                "id": row.id,
                "sequence": row.sequence,
                "received_at": row.received_at,
                "occurred_at": row.occurred_at,
                "event_type": row.event_type,
                "title": title,
                "summary": summary,
                "trust_level": item.trust_level if item else None,
                "decision": decision,
                "enforcement": enforcement,
                "explanation": clip(dec.explanation, _EXPLANATION_CHARS) if dec else None,
                "severity": max(sevs, key=lambda s: SEVERITY_RANK.get(s, 0)) if sevs else None,
                "processing_status": row.processing_status,
                "from_other_session": other,
                "tool": {"name": tool.name, "category": tool.category, "status": inv.status if inv else None}
                if tool
                else None,
                "refs": {
                    "context_item_id": item.id if item else None,
                    "tool_invocation_id": inv.id if inv else None,
                    "policy_decision_id": dec.id if dec else None,
                    "finding_ids": [str(f) for f in ref.get("finding_ids") or []],
                    "approval_id": ref.get("approval_id"),
                    "child_session_id": ref.get("child_session_id") if not other else None,
                    "source_id": ref.get("source_id"),
                    "destination_id": ref.get("destination_id"),
                },
            }
        )
    return out


def _item_ids(ref: dict[str, Any]) -> list[str]:
    many = ref.get("context_item_ids") or []
    return [str(i) for i in many] or ([str(ref["context_item_id"])] if ref.get("context_item_id") else [])


# ----------------------------------------------------------------------------- plain-language text


def clip(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _basename(path: str) -> str:
    parts = [p for p in re.split(r"[\\/]", path.strip()) if p]
    return clip(parts[-1] if parts else path, 60) or path


def _url_label(url: str) -> str:
    parts = urlsplit(url if "://" in url else f"//{url}")
    host = parts.hostname or url
    path = parts.path if parts.path not in ("", "/") else ""
    return clip(host + path, 60) or host


def _preview(digest: Any) -> str | None:
    if not isinstance(digest, dict):
        return None
    if digest.get("preview"):
        return clip(digest["preview"], 200)
    length = digest.get("length")
    return f"{int(length):,} characters (content previews are disabled)" if isinstance(length, int) else None


def _meta_summary(meta: Any) -> str | None:
    if not isinstance(meta, dict):
        return None
    parts = [
        f"{k.replace('_', ' ')}: {clip(meta[k], 60)}"
        for k in ("model", "cwd", "permission_mode", "reason")
        if isinstance(meta.get(k), str | int | float) and str(meta[k]).strip()
    ]
    return " · ".join(parts) or None


def _arg(args: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _target(
    category: str, inv: ToolInvocation | None, args: dict[str, Any], dest: str | None
) -> tuple[str, str] | None:
    res = [r for r in ((inv.resources if inv else None) or []) if isinstance(r, dict) and r.get("id")]

    def first(*kinds: str) -> str | None:
        return next((str(r["id"]) for r in res if r.get("kind") in kinds), None)

    if category in ("file_read", "file_write"):
        path = first("file", "glob") or _arg(args, "file_path", "path", "notebook_path", "pattern")
        return ("file", _basename(path)) if path else None
    if category in ("shell", "code_execution"):
        cmd = _arg(args, "command", "cmd", "code", "script")
        return ("command", clip(cmd, 60) or "") if cmd else None
    if category == "search":
        query = _arg(args, *_QUERY_KEYS)
        return ("query", clip(query, 60) or "") if query else None
    url = first("url") or _arg(args, "url")
    if url:
        return "url", _url_label(url)
    if dest:
        return "dest", clip(dest, 60) or dest
    other = first("host", "email", "channel", "table", "agent", "file")
    return ("resource", clip(other, 60) or "") if other else None


def _phrase(name: str, target: tuple[str, str] | None) -> str:
    if not target:
        return name
    kind, label = target
    if kind == "command":
        return f"{name} `{label}`"
    if kind == "query":
        return f"{name} for “{label}”"
    return f"{name} to {label}" if kind in ("url", "dest") else f"{name} {label}"


def _tool_text(
    event_type: str,
    payload: dict[str, Any],
    ref: dict[str, Any],
    inv: ToolInvocation | None,
    tool: Tool | None,
    item: Any,
    dec: Any,
    dest: str | None,
) -> tuple[str, str | None]:
    name = tool.name if tool else str((payload.get("tool") or {}).get("name") or "Tool")
    category = tool.category if tool else "other"
    args = (inv.arguments_redacted if inv else payload.get("arguments")) or {}
    target = _target(category, inv, args if isinstance(args, dict) else {}, dest)
    phrase = _phrase(name, target)
    if event_type == "tool.requested":
        if dec is None:
            return f"Requested {phrase}", None
        explanation = clip(dec.explanation, 300)
        if dec.enforcement == "enforced":
            return _ENFORCED.get(dec.decision, "Decided {}").format(phrase), explanation
        if dec.enforcement == "advisory":
            return _ADVISED.get(dec.decision, "Advised on {}").format(phrase), (
                f"Advisory: the integration may not honour this decision. {explanation or ''}".strip()
            )
        return f"Observed request: {phrase}", (
            f"Policy outcome {dec.decision} recorded after the fact; nothing could be prevented. {explanation or ''}".strip()
        )
    if event_type == "tool.failed" or payload.get("is_error"):
        return f"{phrase} failed", clip(inv.error if inv else None, 300)
    if ref.get("executed_despite") and inv is not None:
        return (
            f"{phrase} ran although ContextOS returned {inv.decision}",
            f"The call was {str(ref['executed_despite']).replace('_', ' ')} when the integration reported a result.",
        )
    template = _COMPLETED.get(category)
    title = template.format(target[1]) if template and target else f"{phrase} completed"
    if item is not None:
        summary = f"Result recorded as context: {int(item.content_length or 0):,} characters, trust {item.trust_level}."
    else:
        summary = "No result content was reported."
    return title, summary


def _describe(
    event_type: str, payload: dict[str, Any], ref: dict[str, Any], item: Any, other: bool
) -> tuple[str, str | None]:
    if event_type == "session.started":
        return "Session started", _meta_summary(payload.get("metadata"))
    if event_type == "session.ended":
        return "Session ended", _meta_summary(payload.get("metadata"))
    if event_type == "prompt.submitted":
        return "User prompt submitted", _preview(payload.get("content"))
    if event_type == "context.ingested":
        return _context_title(item, payload), _context_summary(item)
    if event_type == "agent.delegated":
        d = payload.get("delegation") or {}
        if other:
            parent = (payload.get("agent") or {}).get("name") or "another agent"
            return f"Task received from {parent}", _preview(d.get("task"))
        child = (d.get("child_agent") or {}).get("name") or "another agent"
        return f"Delegated to {child}", _preview(d.get("task"))
    if event_type == "agent.message":
        msg = payload.get("message") or {}
        return f"Message from {msg.get('from_agent') or 'another agent'}", _preview(msg.get("content"))
    if event_type == "mcp.server_connected":
        src = payload.get("source") or {}
        tools = (payload.get("metadata") or {}).get("tools")
        flagged = len(ref.get("poisoned_tool_ids") or [])
        summary = f"{len(tools)} tool(s) listed" if isinstance(tools, list) else None
        if flagged:
            summary = f"{summary or 'Tools listed'}; {flagged} tool description(s) flagged by detection"
        label = clip(src.get("display_name") or src.get("identifier"), 60)
        return (f"Connected MCP server {label}" if label else "Connected MCP server"), summary
    return event_type.replace(".", " ").capitalize(), None


def _context_title(item: Any, payload: dict[str, Any]) -> str:
    src = payload.get("source") or {}
    source_type = item.source_type if item else str(src.get("type") or "other")
    identifier = item.identifier if item else str(src.get("identifier") or "")
    display = (item.display_name if item else src.get("display_name")) or identifier
    if source_type == "user_prompt":
        return "Received user prompt"
    if source_type in ("file", "repository", "user_upload", "document"):
        label = _basename(display or identifier)
    elif source_type in ("web", "browser", "api"):
        label = _url_label(identifier or display)
    else:
        label = clip(display, 60) or "unnamed source"
    return _SOURCE_TITLES.get(source_type, "Ingested context from {}").format(label)


def _context_summary(item: Any) -> str | None:
    if item is None:
        return None
    text = f"{int(item.content_length or 0):,} characters, {item.sensitivity}."
    detection = item.detection_summary or {}
    cats = [str(c).replace("_", " ") for c in detection.get("categories") or []]
    if detection.get("max_severity") and cats:
        text += f" Detected: {', '.join(sorted(set(cats))[:3])} ({detection['max_severity']})."
    return text
