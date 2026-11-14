"""Per-event-type handlers for context-bearing events: prompts, context, inter-agent messages,
delegations and MCP server connections.

Cross-agent contamination: content that arrives from another agent inherits the lowest trust seen
in the session it came from, and when that session had prompt-injection detections the receiving
session gets a ``cross_agent_contamination`` finding. That is an observed relationship between the
sessions, not proof that the injection propagated.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.domain.enums import SEVERITY_RANK, FindingCategory, FindingStatus, Severity, SourceType
from app.engines.detection import analyze_content
from app.engines.trust import canonicalize_source
from app.models import Agent, AgentSession, ContextSource, SecurityFinding, Tool
from app.services.ingestion_context import ContextInput, ContextOutcome, record_context
from app.services.ingestion_entities import (
    find_agent_by_name,
    find_session_by_external,
    lowest_session_trust,
    resolve_agent,
    resolve_session,
    upsert_relationship,
    upsert_tool,
)
from app.services.ingestion_findings import raise_finding
from app.services.ingestion_risk import MANIPULATION_CATEGORIES, update_session_risk
from app.services.ingestion_state import PipelineState, redact_str

MAX_MCP_TOOLS = 500
_MEDIUM = SEVERITY_RANK[Severity.MEDIUM]


def handle_prompt(st: PipelineState) -> None:
    assert st.agent is not None and st.env.content is not None
    env = st.env
    identifier = env.source.identifier if env.source else f"user:{st.agent.name}"
    record_context(
        st,
        ContextInput(
            source_type=SourceType.USER_PROMPT.value,
            identifier=identifier,
            display_name=(env.source.display_name if env.source else None) or f"Prompts to {st.agent.name}",
            raw_text=env.content,
            content_type=env.content_type,
            item_metadata=env.metadata,
        ),
    )


def handle_context(st: PipelineState) -> None:
    env = st.env
    assert env.source is not None and env.content is not None
    record_context(
        st,
        ContextInput(
            source_type=env.source.type.value,
            identifier=env.source.identifier,
            display_name=env.source.display_name,
            raw_text=env.content,
            content_type=env.content_type,
            source_metadata=env.source.metadata,
            item_metadata=env.metadata,
        ),
    )


# -- inter-agent content ---------------------------------------------------------------------------


def _injection_findings(st: PipelineState, session_id: str) -> list[SecurityFinding]:
    """Open content findings in a session that indicate manipulative (injected) content."""
    rows = st.db.scalars(
        select(SecurityFinding)
        .where(
            SecurityFinding.organization_id == st.ctx.org_id,
            SecurityFinding.session_id == session_id,
            SecurityFinding.context_item_id.is_not(None),
            SecurityFinding.category.in_(sorted(MANIPULATION_CATEGORIES)),
            SecurityFinding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]),
        )
        .limit(50)
    ).all()
    return [f for f in rows if SEVERITY_RANK.get(f.severity, 0) >= _MEDIUM]


def _record_agent_content(
    st: PipelineState,
    *,
    origin_agent: Agent | None,
    origin_name: str,
    origin_session: AgentSession | None,
    raw_text: str,
    kind: str,
) -> ContextOutcome:
    """Content produced by another agent entering the current session (message or delegated task)."""
    assert st.agent is not None and st.session is not None
    inherited = lowest_session_trust(st.db, st.ctx.org_id, origin_session.id) if origin_session else None
    outcome = record_context(
        st,
        ContextInput(
            source_type=SourceType.AGENT_OUTPUT.value,
            identifier=f"agent:{origin_name}",
            display_name=f"Output of agent {origin_name}",
            raw_text=raw_text,
            item_metadata={
                "kind": kind,
                "origin_agent_name": origin_name,
                "origin_session_known": origin_session is not None,
            },
            origin_agent_id=origin_agent.id if origin_agent else None,
            origin_session_id=origin_session.id if origin_session else None,
            inherited_level=inherited,
        ),
    )
    if origin_session is None:
        return outcome
    injected = _injection_findings(st, origin_session.id)
    if injected:
        noun = "message" if kind == "message" else "delegated task"
        raise_finding(
            st,
            category=FindingCategory.CROSS_AGENT_CONTAMINATION.value,
            rule_id="CTX-CROSS-AGENT-001",
            title=f"A {noun} from agent '{origin_name}', whose session had prompt-injection detections, "
            f"reached agent '{st.agent.name}'"[:400],
            explanation=(
                f"The session of agent '{origin_name}' that produced this {noun} had {len(injected)} open "
                f"prompt-injection finding(s) on content it consumed. The {noun} entered agent '{st.agent.name}' "
                f"with trust {outcome.item.trust_level} (the lowest trust seen in the origin session), so injected "
                "instructions may have crossed the agent boundary. This is an observed relationship between the "
                "sessions, not proof that the injection propagated."
            ),
            severity=Severity.HIGH.value,
            confidence=0.75,
            evidence=[
                {
                    "type": "context_item",
                    "id": outcome.item.id,
                    "excerpt": None,
                    "detail": f"{noun} received",
                },
                {
                    "type": "session",
                    "id": origin_session.id,
                    "excerpt": None,
                    "detail": f"origin session of {origin_name}",
                },
                *[
                    {
                        "type": "finding",
                        "id": f.id,
                        "excerpt": None,
                        "detail": f"{f.severity} {f.category}: {f.title[:160]}",
                    }
                    for f in injected[:10]
                ],
            ],
            source_id=outcome.source.id,
            context_item_id=outcome.item.id,
        )
    return outcome


def handle_message(st: PipelineState) -> None:
    assert st.agent is not None and st.session is not None and st.env.message is not None
    msg = st.env.message
    origin_agent = find_agent_by_name(st.db, st.ctx.org_id, msg.from_agent)
    origin_session = None
    if msg.from_session_id:
        origin_session = find_session_by_external(
            st.db, st.ctx.org_id, msg.from_session_id, origin_agent.id if origin_agent else None
        ) or find_session_by_external(st.db, st.ctx.org_id, msg.from_session_id)
        if origin_session is not None and origin_agent is None:
            origin_agent = st.db.get(Agent, origin_session.agent_id)
    if origin_session is not None and origin_session.id == st.session.id:
        origin_session = None  # an agent echoing its own session is not inter-agent content
    _record_agent_content(
        st,
        origin_agent=origin_agent,
        origin_name=msg.from_agent,
        origin_session=origin_session,
        raw_text=msg.content,
        kind="message",
    )
    if origin_session is not None:
        upsert_relationship(st, origin_session, st.session, "messages")


def handle_delegation(st: PipelineState) -> None:
    """The reporting (parent) agent delegated work: register the child session and its task as context."""
    assert st.agent is not None and st.session is not None and st.env.delegation is not None
    d = st.env.delegation
    parent_agent, parent_session = st.agent, st.session
    child_agent = resolve_agent(st, d.child_agent)
    child_session = resolve_session(st, child_agent, d.child_session_id, parent=parent_session)
    st.refs["child_session_id"] = child_session.id
    st.refs["child_agent_id"] = child_agent.id
    if d.task:
        st.agent, st.session = child_agent, child_session
        try:
            _record_agent_content(
                st,
                origin_agent=parent_agent,
                origin_name=parent_agent.name,
                origin_session=parent_session,
                raw_text=d.task,
                kind="delegated_task",
            )
            child_session.event_count = (child_session.event_count or 0) + 1
            child_session.last_event_at = st.now
            update_session_risk(st)
        finally:
            st.agent, st.session = parent_agent, parent_session
    upsert_relationship(st, parent_session, child_session, "delegates_to")


# -- MCP -------------------------------------------------------------------------------------------


def _mcp_tools(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in (metadata.get("tools") or [])[:MAX_MCP_TOOLS]:
        if isinstance(entry, str) and entry.strip():
            out.append({"name": entry.strip()[:200], "description": ""})
        elif isinstance(entry, dict) and str(entry.get("name") or "").strip():
            desc = entry.get("description")
            out.append(
                {
                    "name": str(entry["name"]).strip()[:200],
                    "description": desc if isinstance(desc, str) else "",
                }
            )
    return out


def handle_mcp_connected(st: PipelineState) -> None:
    """Scan every advertised tool description for poisoning; the listing itself is context."""
    env = st.env
    assert env.source is not None and st.agent is not None
    server = env.source.identifier.strip()
    server_key = server.lower()
    tools = _mcp_tools(env.metadata or {})
    extra: dict[str, list[dict[str, Any]]] = {}
    sections = [env.content] if env.content else []
    poisoned: list[str] = []
    for spec in tools:
        tool = upsert_tool(
            st,
            provider=f"mcp:{server_key}",
            name=spec["name"],
            server=server_key,
            description=spec["description"],
        )
        result = (
            analyze_content(spec["description"], source_type=SourceType.MCP_SERVER.value)
            if spec["description"]
            else None
        )
        metadata = dict(tool.tool_metadata or {})
        metadata["last_listed_at"] = st.now.isoformat()
        metadata["description_length"] = len(spec["description"])
        if result and result.hits:
            poisoned.append(tool.id)
            metadata["poisoning"] = {
                "rule_ids": sorted({h.rule_id for h in result.hits}),
                "max_severity": result.max_severity,
                "detected_at": st.now.isoformat(),
                "event_id": st.event.id,
            }
            for hit in result.hits:
                extra.setdefault(hit.rule_id, []).append(
                    {
                        "type": "tool",
                        "id": tool.id,
                        "excerpt": st.scrub(hit.excerpt),
                        "detail": f"description of tool '{spec['name']}' on MCP server '{redact_str(server, limit=200)}'",
                    }
                )
        else:
            metadata.pop("poisoning", None)
        tool.tool_metadata = metadata
        sections.append(f"Tool {spec['name']}: {spec['description']}")
    if poisoned:
        st.refs["poisoned_tool_ids"] = poisoned
    outcome = record_context(
        st,
        ContextInput(
            source_type=SourceType.MCP_SERVER.value,
            identifier=server,
            display_name=env.source.display_name,
            raw_text="\n\n".join(sections),
            source_metadata={**(env.source.metadata or {}), "tool_count": len(tools)},
            item_metadata={
                "kind": "mcp_tool_listing",
                "tool_count": len(tools),
                "tool_names": [t["name"] for t in tools][:100],
            },
            extra_evidence=extra,
        ),
    )
    # The server's classification after this listing, so a gateway can hide a BLOCKED server's tools
    # without a separate read of the source (the value is the server's, never the client's).
    st.refs["source_trust_level"] = outcome.source.trust_level


def mcp_server_ceiling(st: PipelineState, server: str | None) -> tuple[str, str] | None:
    """An MCP tool's output is never more trusted than the server that provides it."""
    if not server:
        return None
    canonical, _ = canonicalize_source(SourceType.MCP_SERVER.value, server)
    source = st.db.scalar(
        select(ContextSource).where(
            ContextSource.organization_id == st.ctx.org_id,
            ContextSource.source_type == SourceType.MCP_SERVER.value,
            ContextSource.identifier == (redact_str(canonical, limit=2048) or server.lower()),
        )
    )
    if source is None:
        return None
    return source.trust_level, (
        f"Capped at {source.trust_level} because the MCP server '{source.identifier}' that provides this tool is "
        f"classified {source.trust_level}."
    )


def known_tool(st: PipelineState, provider: str, name: str) -> Tool | None:
    return st.db.scalar(
        select(Tool).where(
            Tool.organization_id == st.ctx.org_id, Tool.provider == provider, Tool.name == name
        )
    )
