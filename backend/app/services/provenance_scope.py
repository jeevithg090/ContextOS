"""Provenance scopes: which recorded relationships belong to a session, agent, context item or finding.

Edges come from ``ProvenanceEdge`` rows recorded by the ingestion pipeline (``observed`` or
``inferred``) plus, for findings no edge points at, the subject stored on the finding row itself
(``basis="finding_record"``). None of them is a causal claim. Every query filters on the caller's
organisation; reads are bounded (``MAX_EDGES`` edges, ``MAX_SCOPE_SESSIONS`` sessions).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.domain.enums import ProvenanceNodeType, RiskLevel
from app.engines.risk.session import LEVEL_THRESHOLDS
from app.models import Agent, AgentSession, ContextItem, ContextSource, ProvenanceEdge, SecurityFinding
from app.schemas.provenance import GraphScopeOut
from app.services import provenance_nodes as nodes_mod
from app.services.scoping import find_scoped, scoped

N = ProvenanceNodeType
PE = ProvenanceEdge
FINDING_EVIDENCE = "finding_evidence"
# Lowest score the risk engine calls "high" (taken from the engine, never re-stated here).
HIGH_RISK_SCORE = next(t for t, level in LEVEL_THRESHOLDS if level == RiskLevel.HIGH)
MAX_EDGES = 3000
_MAX_SCOPE_SESSIONS = 40
_MAX_FINDINGS = 200
_CHUNK = 400
_HUB_TYPES = {N.AGENT.value, N.TOOL.value}  # link unrelated sessions; never expanded through

Key = tuple[str, str]  # (node type, record id)

__all__ = [
    "FINDING_EVIDENCE", "HIGH_RISK_SCORE", "MAX_EDGES", "Collected", "Key", "RawEdge", "agent_scope", "auto_scope",
    "finding_record_edges", "finding_scope", "findings_where", "graph_id", "item_scope", "raw_edge",
    "recent_activity", "session_scope",
]


def graph_id(k: Key) -> str:
    return f"{k[0]}:{k[1]}"


@dataclass
class RawEdge:
    id: str
    src: Key
    dst: Key
    relation: str
    confidence: str
    observed_at: datetime | None
    session_id: str | None
    basis: str = "provenance_edge"
    metadata: dict[str, Any] = field(default_factory=dict)


def raw_edge(e: ProvenanceEdge) -> RawEdge:
    return RawEdge(e.id, (e.src_type, e.src_id), (e.dst_type, e.dst_id), e.relation, e.confidence or "observed",
                   e.observed_at, e.session_id, metadata=e.edge_metadata or {})


@dataclass
class Collected:
    scope: GraphScopeOut
    edges: dict[str, RawEdge]
    roots: set[Key]
    truncation: str | None = None


def _chunks(values: Iterable[str]) -> Iterable[list[str]]:
    items = list(values)
    for i in range(0, len(items), _CHUNK):
        yield items[i:i + _CHUNK]


# -- finding-record edges -------------------------------------------------------------------------


def finding_record_edges(db: Session, org_id: str, findings: list[SecurityFinding]) -> list[RawEdge]:
    """Link findings that no provenance edge points at to the subject recorded on the finding."""
    if not findings:
        return []
    linked: set[str] = set()
    for chunk in _chunks(f.id for f in findings):
        linked.update(db.scalars(select(PE.dst_id).where(
            PE.organization_id == org_id, PE.dst_type == N.FINDING.value, PE.dst_id.in_(chunk))))
    out: list[RawEdge] = []
    for f in findings:
        if f.id in linked:
            continue
        if f.tool_invocation_id:
            subject: Key = (N.TOOL_INVOCATION.value, f.tool_invocation_id)
        elif f.context_item_id:
            subject = (N.CONTEXT_ITEM.value, f.context_item_id)
        elif f.session_id:
            subject = (N.SESSION.value, f.session_id)
        else:
            continue
        out.append(RawEdge(f"fr_{f.id}", subject, (N.FINDING.value, f.id), FINDING_EVIDENCE, "observed",
                           f.first_seen_at, f.session_id, basis="finding_record"))
    return out


def findings_where(db: Session, org_id: str, *conditions: Any) -> list[SecurityFinding]:
    return list(db.scalars(scoped(SecurityFinding, org_id).where(*conditions)
                           .order_by(SecurityFinding.last_seen_at.desc()).limit(_MAX_FINDINGS)))


# -- scope collection -----------------------------------------------------------------------------


def _related_sessions(db: Session, org_id: str, root: AgentSession) -> list[str]:
    """The session, its delegating ancestors and its delegated descendants (bounded)."""
    ids, seen = [root.id], {root.id}
    current = root
    while current.parent_session_id and len(ids) < _MAX_SCOPE_SESSIONS:
        parent = find_scoped(db, AgentSession, current.parent_session_id, org_id)
        if parent is None or parent.id in seen:
            break
        ids.insert(0, parent.id)
        seen.add(parent.id)
        current = parent
    frontier = [root.id]
    while frontier and len(ids) < _MAX_SCOPE_SESSIONS:
        children = db.scalars(scoped(AgentSession, org_id).where(AgentSession.parent_session_id.in_(frontier))
                              .with_only_columns(AgentSession.id).limit(_MAX_SCOPE_SESSIONS - len(ids)))
        frontier = [c for c in children if c not in seen]
        seen.update(frontier)
        ids.extend(frontier)
    return ids


def _session_edges(db: Session, org_id: str, ids: list[str]) -> tuple[dict[str, RawEdge], bool]:
    cond = or_(PE.session_id.in_(ids), and_(PE.src_type == N.SESSION.value, PE.src_id.in_(ids)),
               and_(PE.dst_type == N.SESSION.value, PE.dst_id.in_(ids)))
    rows = list(db.scalars(scoped(PE, org_id).where(cond).order_by(PE.observed_at.desc(), PE.id).limit(MAX_EDGES + 1)))
    edges = {r.id: raw_edge(r) for r in rows[:MAX_EDGES]}
    for e in finding_record_edges(db, org_id, findings_where(db, org_id, SecurityFinding.session_id.in_(ids))):
        edges[e.id] = e
    return edges, len(rows) > MAX_EDGES


def _expand(db: Session, org_id: str, seeds: set[Key], depth: int) -> tuple[dict[str, RawEdge], bool]:
    """Edges within ``depth`` hops of ``seeds`` in either direction (agents and tools are not crossed)."""
    edges: dict[str, RawEdge] = {}
    seen, frontier = set(seeds), set(seeds)
    for _ in range(depth):
        by_type: dict[str, list[str]] = defaultdict(list)
        for node_type, ref in frontier:
            if node_type not in _HUB_TYPES:
                by_type[node_type].append(ref)
        if not by_type:
            break
        conds = [cond for node_type, refs in by_type.items() for chunk in _chunks(refs) for cond in (
            and_(PE.src_type == node_type, PE.src_id.in_(chunk)), and_(PE.dst_type == node_type, PE.dst_id.in_(chunk)))]
        rows = db.scalars(scoped(PE, org_id).where(or_(*conds)).order_by(PE.observed_at.desc(), PE.id).limit(MAX_EDGES + 1))
        frontier = set()
        for row in rows:
            if row.id in edges:
                continue
            if len(edges) >= MAX_EDGES:
                return edges, True
            raw = edges[row.id] = raw_edge(row)
            for end in (raw.src, raw.dst):
                if end not in seen:
                    seen.add(end)
                    frontier.add(end)
    return edges, False


def _sessions_in(edges: dict[str, RawEdge]) -> list[str]:
    return sorted({end[1] for e in edges.values() for end in (e.src, e.dst) if end[0] == N.SESSION.value})


def _agent_name(db: Session, org_id: str, agent_id: str) -> str:
    agent = find_scoped(db, Agent, agent_id, org_id)
    return agent.name if agent else "Unknown agent"


def session_scope(db: Session, org_id: str, session: AgentSession, reason: str | None = None) -> Collected:
    ids = _related_sessions(db, org_id, session)
    edges, capped = _session_edges(db, org_id, ids)
    extra = len(ids) - 1
    label = f"{_agent_name(db, org_id, session.agent_id)} · {session.external_session_id}"
    scope = GraphScopeOut(
        kind="session", id=session.id,
        label=label + (f" (+{extra} session{'s' * (extra > 1)} linked by delegation)" if extra else ""),
        auto_selected=reason is not None, reason=reason, session_ids=ids,
        root_node_ids=[graph_id((N.SESSION.value, session.id))], is_simulation=session.is_simulation,
    )
    return Collected(scope, edges, {(N.SESSION.value, session.id)},
                     f"Only the {MAX_EDGES} most recent relationships were read." if capped else None)


def recent_activity() -> Any:
    return func.coalesce(AgentSession.last_event_at, AgentSession.started_at)


def agent_scope(db: Session, org_id: str, agent: Agent) -> Collected:
    base = scoped(AgentSession, org_id).where(AgentSession.agent_id == agent.id)
    sessions = list(db.scalars(base.order_by(recent_activity().desc()).limit(_MAX_SCOPE_SESSIONS)))
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    ids = [s.id for s in sessions]
    edges, capped = _session_edges(db, org_id, ids) if ids else ({}, False)
    notes = []
    if total > len(ids):
        notes.append(f"Showing the {len(ids)} most recent of {total} sessions.")
    if capped:
        notes.append(f"Only the {MAX_EDGES} most recent relationships were read.")
    scope = GraphScopeOut(kind="agent", id=agent.id, label=agent.name, session_ids=ids,
                          root_node_ids=[graph_id((N.AGENT.value, agent.id))], is_simulation=agent.is_simulation)
    return Collected(scope, edges, {(N.AGENT.value, agent.id)}, " ".join(notes) or None)


def item_scope(db: Session, org_id: str, item: ContextItem, depth: int) -> Collected:
    root = (N.CONTEXT_ITEM.value, item.id)
    edges, capped = _expand(db, org_id, {root}, depth)
    for e in finding_record_edges(db, org_id, findings_where(db, org_id, SecurityFinding.context_item_id == item.id)):
        edges[e.id] = e
    source = find_scoped(db, ContextSource, item.source_id, org_id)
    label = f"Context from {nodes_mod.compact(source.display_name or source.identifier) if source else 'unknown source'}"
    scope = GraphScopeOut(kind="context_item", id=item.id, label=label, session_ids=_sessions_in(edges), depth=depth,
                          root_node_ids=[graph_id(root)], is_simulation=item.is_simulation)
    return Collected(scope, edges, {root}, f"Only the first {MAX_EDGES} relationships were read." if capped else None)


def finding_scope(db: Session, org_id: str, finding: SecurityFinding, depth: int) -> Collected:
    root = (N.FINDING.value, finding.id)
    seeds = {root}
    for node_type, ref in ((N.CONTEXT_ITEM, finding.context_item_id), (N.TOOL_INVOCATION, finding.tool_invocation_id),
                           (N.DESTINATION, finding.destination_id)):
        if ref:
            seeds.add((node_type.value, ref))
    if len(seeds) == 1 and finding.session_id:
        seeds.add((N.SESSION.value, finding.session_id))
    edges, capped = _expand(db, org_id, seeds, depth)
    for e in finding_record_edges(db, org_id, [finding]):
        edges[e.id] = e
    scope = GraphScopeOut(kind="finding", id=finding.id, label=finding.title, session_ids=_sessions_in(edges), depth=depth,
                          root_node_ids=[graph_id(root)], is_simulation=finding.is_simulation)
    return Collected(scope, edges, {root}, f"Only the first {MAX_EDGES} relationships were read." if capped else None)


def auto_scope(db: Session, org_id: str) -> Collected | None:
    """No scope requested: the most recent high-risk session (real activity before simulations)."""
    order = (AgentSession.is_simulation.asc(), recent_activity().desc())
    risky = db.scalar(scoped(AgentSession, org_id).where(AgentSession.risk_score >= HIGH_RISK_SCORE).order_by(*order).limit(1))
    if risky is not None:
        return session_scope(db, org_id, risky, f"No scope was chosen, so this is the most recent high-risk session "
                                                 f"(risk {risky.risk_score}/100).")
    latest = db.scalar(scoped(AgentSession, org_id).order_by(*order).limit(1))
    if latest is None:
        return None
    return session_scope(db, org_id, latest, "No scope was chosen and no high-risk session has been recorded, "
                                              "so this is the most recent session.")
