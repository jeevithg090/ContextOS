"""Entity resolution for the ingestion pipeline: agents, sessions, integrations, sources, tools,
destinations, agent relationships and provenance edges.

Every lookup filters on the event's organisation. Names and identifiers reported by integrations
are redacted before they are stored.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.domain.enums import TRUST_RANK, ProvenanceNodeType, ProvenanceRelation
from app.engines.redaction import redact_value
from app.engines.risk import classify_tool
from app.events.envelope import AgentRef, ToolRef
from app.models import (
    Agent,
    AgentRelationship,
    AgentSession,
    ContextItem,
    ContextSource,
    Integration,
    ProvenanceEdge,
    Tool,
)
from app.services.ingestion_state import PipelineState, bounded, redact_str

N = ProvenanceNodeType
R = ProvenanceRelation
_ENVIRONMENTS = {"development", "staging", "production"}


# -- provenance ------------------------------------------------------------------------------------


def add_edge(
    st: PipelineState,
    src_type: str,
    src_id: str,
    dst_type: str,
    dst_id: str,
    relation: str,
    *,
    session_id: str | None = None,
    confidence: str = "observed",
    metadata: dict[str, Any] | None = None,
    unique: bool = False,
) -> ProvenanceEdge | None:
    """Record an observed relationship. Edges never assert causation (see models.context)."""
    db, org = st.db, st.ctx.org_id
    if unique:
        exists = db.scalar(
            select(ProvenanceEdge.id).where(
                ProvenanceEdge.organization_id == org, ProvenanceEdge.src_type == src_type,
                ProvenanceEdge.src_id == src_id, ProvenanceEdge.dst_type == dst_type,
                ProvenanceEdge.dst_id == dst_id, ProvenanceEdge.relation == relation,
            ).limit(1)
        )
        if exists:
            return None
    edge = ProvenanceEdge(
        id=new_id("provenance_edge"),
        organization_id=org,
        src_type=src_type,
        src_id=src_id,
        dst_type=dst_type,
        dst_id=dst_id,
        relation=relation,
        session_id=session_id if session_id is not None else (st.session.id if st.session else None),
        event_id=st.event.id,
        observed_at=st.now,
        confidence=confidence,
        edge_metadata=metadata or {},
    )
    db.add(edge)
    if unique:
        db.flush()  # make it visible to the next uniqueness check (autoflush is off)
    return edge


# -- agents, sessions, integrations ----------------------------------------------------------------


def find_agent_by_name(db: Session, org_id: str, name: str) -> Agent | None:
    return db.scalar(select(Agent).where(Agent.organization_id == org_id, Agent.name == name))


def resolve_agent(st: PipelineState, ref: AgentRef) -> Agent:
    """Agent by (org, name); auto-registers on first sight with the reported framework/version.

    The environment is taken only at registration: a reporting integration cannot later move an
    agent out of ``production`` (that would sidestep production-only policies); admins change it.
    """
    db, org = st.db, st.ctx.org_id
    agent = find_agent_by_name(db, org, ref.name)
    if agent is None:
        environment = (ref.environment or "development").strip().lower()
        agent = Agent(
            id=new_id("agent"),
            organization_id=org,
            name=ref.name,
            framework=ref.framework or "custom",
            version=ref.version,
            environment=environment if environment in _ENVIRONMENTS else "development",
            is_simulation=st.ctx.is_simulation,
            labels=[],
            declared_capabilities={},
            last_seen_at=st.now,
        )
        db.add(agent)
        db.flush()
        return agent
    if ref.version and ref.version != agent.version:
        agent.version = ref.version
    if ref.framework and agent.framework in (None, "", "custom") and ref.framework != "custom":
        agent.framework = ref.framework
    agent.last_seen_at = st.now
    return agent


def find_session_by_external(db: Session, org_id: str, external_id: str, agent_id: str | None = None) -> AgentSession | None:
    query = select(AgentSession).where(
        AgentSession.organization_id == org_id, AgentSession.external_session_id == external_id
    )
    if agent_id is not None:
        query = query.where(AgentSession.agent_id == agent_id)
    return db.scalars(query.order_by(AgentSession.created_at.desc()).limit(1)).first()


def resolve_session(
    st: PipelineState, agent: Agent, external_id: str, *, parent: AgentSession | None = None
) -> AgentSession:
    db, org = st.db, st.ctx.org_id
    session = find_session_by_external(db, org, external_id, agent.id)
    if session is None:
        session = AgentSession(
            id=new_id("agent_session"),
            organization_id=org,
            agent_id=agent.id,
            external_session_id=external_id,
            status="active",
            started_at=st.now,
            session_metadata={},
            risk_state={},
            risk_score=0,
            event_count=0,
            is_simulation=st.ctx.is_simulation,
            simulation_run_id=st.ctx.simulation_run_id,
        )
        db.add(session)
        db.flush()
        add_edge(st, N.AGENT, agent.id, N.SESSION, session.id, R.AGENT_RAN_SESSION, session_id=session.id)
    if parent is not None and session.parent_session_id is None and parent.id != session.id:
        link_delegation(st, parent, session)
    return session


def link_delegation(st: PipelineState, parent: AgentSession, child: AgentSession) -> None:
    child.parent_session_id = parent.id
    add_edge(st, N.SESSION, parent.id, N.SESSION, child.id, R.SESSION_DELEGATED_TO, session_id=child.id, unique=True)
    upsert_relationship(st, parent, child, "delegates_to")


def upsert_relationship(st: PipelineState, parent: AgentSession, child: AgentSession, kind: str) -> AgentRelationship | None:
    if parent.agent_id == child.agent_id:
        return None
    db, org = st.db, st.ctx.org_id
    rel = db.scalar(
        select(AgentRelationship).where(
            AgentRelationship.organization_id == org,
            AgentRelationship.parent_agent_id == parent.agent_id,
            AgentRelationship.child_agent_id == child.agent_id,
            AgentRelationship.relationship_type == kind,
        )
    )
    if rel is None:
        rel = AgentRelationship(
            id=new_id("agent_relationship"), organization_id=org, parent_agent_id=parent.agent_id,
            child_agent_id=child.agent_id, relationship_type=kind, first_seen_at=st.now, event_count=0,
        )
        db.add(rel)
    rel.event_count = (rel.event_count or 0) + 1
    rel.last_seen_at = st.now
    rel.last_parent_session_id = parent.id
    rel.last_child_session_id = child.id
    db.flush()
    parent_low, child_low = lowest_session_trust(db, org, parent.id), lowest_session_trust(db, org, child.id)
    rel.crosses_trust_boundary = bool(
        parent_low and child_low and TRUST_RANK.get(child_low, 2) < TRUST_RANK.get(parent_low, 2)
    )
    return rel


def lowest_session_trust(db: Session, org_id: str, session_id: str) -> str | None:
    """Lowest trust observed among a session's context (item trust at ingest or its source's current trust)."""
    rows = db.execute(
        select(ContextItem.trust_level, ContextSource.trust_level)
        .join(ContextSource, ContextSource.id == ContextItem.source_id)
        .where(ContextItem.organization_id == org_id, ContextItem.session_id == session_id)
    ).all()
    lowest: str | None = None
    for item_level, source_level in rows:
        for level in (item_level, source_level):
            if level in TRUST_RANK and (lowest is None or TRUST_RANK[level] < TRUST_RANK[lowest]):
                lowest = level
    return lowest


def touch_integration(st: PipelineState, *, decision: bool) -> Integration | None:
    """Integration health counters. Simulation traffic never marks a real integration as connected."""
    if st.ctx.is_simulation:
        return None
    kind = st.integration_kind
    integration = st.caches.integrations.get(kind)
    if integration is None:
        integration = st.db.scalar(
            select(Integration).where(
                Integration.organization_id == st.ctx.org_id, Integration.kind == kind, Integration.name == kind
            )
        )
        if integration is None:
            integration = Integration(
                id=new_id("integration"), organization_id=st.ctx.org_id, kind=kind, name=kind,
                status="connected", config={}, event_count=0, decision_count=0,
            )
            st.db.add(integration)
            st.db.flush()
        st.caches.integrations[kind] = integration
    integration.status = "connected"
    integration.last_event_at = st.now
    integration.event_count = (integration.event_count or 0) + 1
    if decision:
        integration.decision_count = (integration.decision_count or 0) + 1
    return integration


# -- sources ---------------------------------------------------------------------------------------


def upsert_source(
    st: PipelineState,
    source_type: str,
    canonical: str,
    domain: str | None,
    *,
    display_name: str | None,
    metadata: dict[str, Any] | None,
) -> ContextSource:
    """Source by (org, type, canonical identifier). ``is_simulation`` is set when simulated traffic
    creates the source and cleared the first time real traffic observes it."""
    db, org = st.db, st.ctx.org_id
    source = db.scalar(
        select(ContextSource).where(
            ContextSource.organization_id == org,
            ContextSource.source_type == source_type,
            ContextSource.identifier == canonical,
        )
    )
    if source is None:
        source = ContextSource(
            id=new_id("context_source"),
            organization_id=org,
            source_type=source_type,
            identifier=canonical,
            display_name=redact_str(display_name, limit=400),
            domain=domain,
            trust_level="UNKNOWN",
            trust_capabilities=[],
            trust_reasons=[],
            first_seen_at=st.now,
            observation_count=0,
            finding_count=0,
            source_metadata={},
            is_simulation=st.ctx.is_simulation,
        )
        db.add(source)
        db.flush()
    elif display_name and not source.display_name:
        source.display_name = redact_str(display_name, limit=400)
    if source.is_simulation and not st.ctx.is_simulation:
        source.is_simulation = False  # observed by real traffic: no longer simulation-only (never set back)
    source.observation_count = (source.observation_count or 0) + 1
    source.last_seen_at = st.now
    if metadata:
        redacted, _ = redact_value(metadata)
        source.source_metadata = bounded({**(source.source_metadata or {}), **redacted})
    return source


# -- tools -----------------------------------------------------------------------------------------


def tool_identity(ref: ToolRef, integration: str) -> tuple[str, str, str | None]:
    """(provider, name, server) used as the Tool key. MCP tools are keyed ``mcp:<server>`` + bare name,
    whether reported as ``mcp__server__tool`` (Claude Code) or name + server (MCP gateway)."""
    name, server = ref.name.strip(), (ref.server or "").strip() or None
    provider = (ref.provider or "unknown").strip() or "unknown"
    if name.startswith("mcp__"):
        srv, sep, tool = name[5:].partition("__")
        if sep and tool:
            name, server = tool, server or srv
    elif provider.lower().startswith("mcp:") and not server:
        server = provider.split(":", 1)[1] or None
    if server:
        return f"mcp:{server.lower()}", name, server.lower()
    if provider == "unknown" and integration:
        provider = integration
    return provider, name, None


def upsert_tool(
    st: PipelineState,
    *,
    provider: str,
    name: str,
    server: str | None,
    category_hint: str | None = None,
    description: str | None = None,
    count_invocation: bool = False,
) -> Tool:
    """Tool row with its server-side, argument-independent classification."""
    db, org = st.db, st.ctx.org_id
    tool = db.scalar(select(Tool).where(Tool.organization_id == org, Tool.provider == provider, Tool.name == name))
    inherent = classify_tool(name, provider, category_hint=category_hint, server=server)
    if tool is None:
        tool = Tool(
            id=new_id("tool"), organization_id=org, provider=provider, name=name, server=server,
            first_seen_at=st.now, invocation_count=0, tool_metadata={},
        )
        db.add(tool)
    tool.category = inherent.category
    tool.risk_level = inherent.risk_level
    tool.last_seen_at = st.now
    if description is not None:
        tool.description = redact_str(description, limit=4000)
    metadata = dict(tool.tool_metadata or {})
    metadata["classification_reason"] = redact_str(inherent.reason, limit=1000)
    if category_hint:
        metadata["category_hint"] = str(category_hint)
        metadata["category_hint_mismatch"] = str(category_hint) != inherent.category
    tool.tool_metadata = metadata
    if count_invocation and not st.ctx.is_simulation:  # Simulation Lab calls never inflate real usage counts
        tool.invocation_count = (tool.invocation_count or 0) + 1
    db.flush()
    return tool
