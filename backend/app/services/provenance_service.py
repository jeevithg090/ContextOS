"""Provenance / Context Trust Graph: scope collection, node resolution, risky paths, inspector detail.

Edges come from ``ProvenanceEdge`` rows recorded by the ingestion pipeline (``observed`` or ``inferred``)
plus, for findings no edge points at, the subject stored on the finding row itself
(``basis="finding_record"``). None of them is a causal claim — see ``OBSERVED_RELATIONSHIP_NOTE``.

Every query filters on the caller's organisation; ids from another organisation resolve to 404.
Graphs are bounded: at most ``_MAX_EDGES`` edges are read and at most ``limit`` nodes returned. Nodes on
risky paths and the scope root are kept first, so truncation never hides the paths it reports.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationFailedError
from app.core.security import sha256_hex
from app.domain.enums import SEVERITY_RANK, TRUST_RANK, ProvenanceNodeType, ProvenanceRelation
from app.engines.provenance import OBSERVED_RELATIONSHIP_NOTE, build_graph, find_risky_paths
from app.models import (
    Agent,
    AgentSession,
    ContextItem,
    ContextSource,
    ProvenanceEdge,
    SecurityFinding,
)
from app.schemas.provenance import (
    GraphEdgeOut,
    GraphNodeOut,
    GraphScopeOut,
    GraphStatsOut,
    NodeDetailOut,
    NodeFieldOut,
    NodeLinkOut,
    ProvenanceGraphOut,
    RiskyPathOut,
    ScopeAgentOut,
    ScopeFindingOut,
    ScopeOptionsOut,
    ScopeSessionOut,
)
from app.services import provenance_nodes as nodes_mod
from app.services.scoping import find_scoped, get_scoped, scoped

N = ProvenanceNodeType
R = ProvenanceRelation
PE = ProvenanceEdge
NODE_TYPES = {t.value for t in N}
DEFAULT_NODE_LIMIT = 400
DEFAULT_DEPTH = 2
FINDING_EVIDENCE = "finding_evidence"
HIGH_RISK_SCORE = 50  # engines.risk: score >= 50 is "high"
_MAX_EDGES = 3000
_MAX_SCOPE_SESSIONS = 40
_MAX_FINDINGS = 200
_MAX_LINKS = 60
_CHUNK = 400
_HUB_TYPES = {N.AGENT.value, N.TOOL.value}  # link unrelated sessions; never expanded through
_TYPE_PRIORITY = {"session": 0, "finding": 1, "context_item": 1, "tool_invocation": 1, "source": 2,
                  "destination": 2, "resource": 3, "policy_decision": 4, "tool": 5, "agent": 5}
RELATION_LABELS = {
    R.SOURCE_PRODUCED_ITEM.value: "produced",
    R.ITEM_ENTERED_SESSION.value: "entered session",
    R.SESSION_INVOKED_TOOL.value: "requested tool call",
    R.INVOCATION_USED_TOOL.value: "used tool",
    R.INVOCATION_ACCESSED_RESOURCE.value: "accessed",
    R.INVOCATION_SENT_TO.value: "sent data to",
    R.INVOCATION_RETURNED_ITEM.value: "returned content",
    R.AGENT_RAN_SESSION.value: "ran session",
    R.SESSION_DELEGATED_TO.value: "delegated to",
    R.AGENT_MESSAGED.value: "sent message",
    R.ITEM_TRIGGERED_FINDING.value: "raised finding",
    R.INVOCATION_DECIDED_BY.value: "evaluated by policy",
    FINDING_EVIDENCE: "recorded as finding evidence",
}

Key = tuple[str, str]  # (node type, record id)


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


def _raw(e: ProvenanceEdge) -> RawEdge:
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


def _finding_record_edges(db: Session, org_id: str, findings: list[SecurityFinding]) -> list[RawEdge]:
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


def _findings_where(db: Session, org_id: str, *conditions: Any) -> list[SecurityFinding]:
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
    rows = list(db.scalars(scoped(PE, org_id).where(cond).order_by(PE.observed_at.desc(), PE.id).limit(_MAX_EDGES + 1)))
    edges = {r.id: _raw(r) for r in rows[:_MAX_EDGES]}
    for e in _finding_record_edges(db, org_id, _findings_where(db, org_id, SecurityFinding.session_id.in_(ids))):
        edges[e.id] = e
    return edges, len(rows) > _MAX_EDGES


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
        rows = db.scalars(scoped(PE, org_id).where(or_(*conds)).order_by(PE.observed_at.desc(), PE.id).limit(_MAX_EDGES + 1))
        frontier = set()
        for row in rows:
            if row.id in edges:
                continue
            if len(edges) >= _MAX_EDGES:
                return edges, True
            raw = edges[row.id] = _raw(row)
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


def _session_scope(db: Session, org_id: str, session: AgentSession, reason: str | None = None) -> Collected:
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
                     f"Only the {_MAX_EDGES} most recent relationships were read." if capped else None)


def _recent() -> Any:
    return func.coalesce(AgentSession.last_event_at, AgentSession.started_at)


def _agent_scope(db: Session, org_id: str, agent: Agent) -> Collected:
    base = scoped(AgentSession, org_id).where(AgentSession.agent_id == agent.id)
    sessions = list(db.scalars(base.order_by(_recent().desc()).limit(_MAX_SCOPE_SESSIONS)))
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    ids = [s.id for s in sessions]
    edges, capped = _session_edges(db, org_id, ids) if ids else ({}, False)
    notes = []
    if total > len(ids):
        notes.append(f"Showing the {len(ids)} most recent of {total} sessions.")
    if capped:
        notes.append(f"Only the {_MAX_EDGES} most recent relationships were read.")
    scope = GraphScopeOut(kind="agent", id=agent.id, label=agent.name, session_ids=ids,
                          root_node_ids=[graph_id((N.AGENT.value, agent.id))], is_simulation=agent.is_simulation)
    return Collected(scope, edges, {(N.AGENT.value, agent.id)}, " ".join(notes) or None)


def _item_scope(db: Session, org_id: str, item: ContextItem, depth: int) -> Collected:
    root = (N.CONTEXT_ITEM.value, item.id)
    edges, capped = _expand(db, org_id, {root}, depth)
    for e in _finding_record_edges(db, org_id, _findings_where(db, org_id, SecurityFinding.context_item_id == item.id)):
        edges[e.id] = e
    source = find_scoped(db, ContextSource, item.source_id, org_id)
    label = f"Context from {nodes_mod.compact(source.display_name or source.identifier) if source else 'unknown source'}"
    scope = GraphScopeOut(kind="context_item", id=item.id, label=label, session_ids=_sessions_in(edges), depth=depth,
                          root_node_ids=[graph_id(root)], is_simulation=item.is_simulation)
    return Collected(scope, edges, {root}, f"Only the first {_MAX_EDGES} relationships were read." if capped else None)


def _finding_scope(db: Session, org_id: str, finding: SecurityFinding, depth: int) -> Collected:
    root = (N.FINDING.value, finding.id)
    seeds = {root}
    for node_type, ref in ((N.CONTEXT_ITEM, finding.context_item_id), (N.TOOL_INVOCATION, finding.tool_invocation_id),
                           (N.DESTINATION, finding.destination_id)):
        if ref:
            seeds.add((node_type.value, ref))
    if len(seeds) == 1 and finding.session_id:
        seeds.add((N.SESSION.value, finding.session_id))
    edges, capped = _expand(db, org_id, seeds, depth)
    for e in _finding_record_edges(db, org_id, [finding]):
        edges[e.id] = e
    scope = GraphScopeOut(kind="finding", id=finding.id, label=finding.title, session_ids=_sessions_in(edges), depth=depth,
                          root_node_ids=[graph_id(root)], is_simulation=finding.is_simulation)
    return Collected(scope, edges, {root}, f"Only the first {_MAX_EDGES} relationships were read." if capped else None)


def _auto_scope(db: Session, org_id: str) -> Collected | None:
    """No scope requested: the most recent high-risk session (real activity before simulations)."""
    order = (AgentSession.is_simulation.asc(), _recent().desc())
    risky = db.scalar(scoped(AgentSession, org_id).where(AgentSession.risk_score >= HIGH_RISK_SCORE).order_by(*order).limit(1))
    if risky is not None:
        return _session_scope(db, org_id, risky, f"No scope was chosen, so this is the most recent high-risk session "
                                                 f"(risk {risky.risk_score}/100).")
    latest = db.scalar(scoped(AgentSession, org_id).order_by(*order).limit(1))
    if latest is None:
        return None
    return _session_scope(db, org_id, latest, "No scope was chosen and no high-risk session has been recorded, "
                                              "so this is the most recent session.")


# -- assembly -------------------------------------------------------------------------------------


def _importance(node: GraphNodeOut) -> int:
    score = 0
    if node.trust_level in TRUST_RANK:
        score += max(0, 3 - TRUST_RANK[node.trust_level])
    score += SEVERITY_RANK.get(node.severity or "", -1) + 1
    score += 2 * int(node.sensitive or node.contains_secrets)
    score += 2 * int(node.decision in ("DENY", "REQUIRE_APPROVAL"))
    return score


def _select(nodes: dict[Key, GraphNodeOut], roots: set[Key], paths: list[Any], limit: int) -> set[Key]:
    if len(nodes) <= limit:
        return set(nodes)
    by_gid = {graph_id(k): k for k in nodes}
    kept = {k for k in roots if k in nodes}
    for path in paths:
        path_keys = {by_gid[g] for g in path.node_ids if g in by_gid}
        if len(kept | path_keys) <= limit:
            kept |= path_keys
    rest = sorted((k for k in nodes if k not in kept), key=lambda k: (
        _TYPE_PRIORITY.get(k[0], 9), -_importance(nodes[k]),
        -(nodes[k].observed_at.timestamp() if nodes[k].observed_at else 0), k))
    kept.update(rest[:max(0, limit - len(kept))])
    return kept


def _path_out(path: Any) -> RiskyPathOut:
    data = path.to_dict()
    return RiskyPathOut(id="rp_" + sha256_hex("|".join(path.edge_ids))[:16], **data)


def _assemble(db: Session, org_id: str, col: Collected, limit: int) -> ProvenanceGraphOut:
    raw_edges = list(col.edges.values())
    keys = {end for e in raw_edges for end in (e.src, e.dst)} | col.roots
    found = nodes_mod.resolve(db, org_id, keys, nodes_mod.resource_meta(raw_edges))
    full = build_graph([r.engine for r in found.values()], [_engine_edge(e) for e in raw_edges])
    resolved = {k: r.out for k, r in found.items()}
    paths = find_risky_paths(full, max_depth=8, max_results=25)
    kept = _select(resolved, col.roots, paths, limit)
    kept_gids = {graph_id(k) for k in kept}
    edges = [e for e in full.edges if e["src"] in kept_gids and e["dst"] in kept_gids]
    degree = {gid for e in edges for gid in (e["src"], e["dst"])}
    root_gids = {graph_id(k) for k in col.roots}
    nodes = [resolved[k] for k in kept if graph_id(k) in degree or graph_id(k) in root_gids]
    shown = {n.id for n in nodes}
    paths = [p for p in paths if all(g in shown for g in p.node_ids)]
    origins = {p.origin_id for p in paths}
    for n in nodes:
        n.risk_origin = n.id in origins
    nodes.sort(key=lambda n: (_TYPE_PRIORITY.get(n.type, 9), n.observed_at.timestamp() if n.observed_at else 0, n.id))

    truncation = col.truncation
    if len(nodes) < len(resolved):
        dropped = len(resolved) - len(nodes)
        note = (f"{dropped} of {len(resolved)} nodes are hidden to keep the graph readable (limit {limit}). Nodes on "
                f"risky paths and the scope itself are always kept; narrow the scope to see the rest.")
        truncation = f"{truncation} {note}" if truncation else note
    counts: dict[str, int] = defaultdict(int)
    for n in nodes:
        counts[n.type] += 1
    stats = GraphStatsOut(
        node_count=len(nodes), edge_count=len(edges), available_node_count=len(resolved), node_counts=dict(counts),
        session_count=counts.get(N.SESSION.value, 0),
        inferred_edge_count=sum(1 for e in edges if e["confidence"] == "inferred"),
        dropped_edge_count=int(full.metadata.get("dropped_edge_count", 0)), risky_path_count=len(paths),
        untrusted_node_count=sum(1 for n in nodes if n.trust_level in ("UNKNOWN", "EXTERNAL", "SUSPICIOUS", "BLOCKED")),
    )
    return ProvenanceGraphOut(
        scope=col.scope, nodes=nodes, edges=[_edge_out(e) for e in edges], risky_paths=[_path_out(p) for p in paths],
        truncated=truncation is not None, truncation_reason=truncation, limit=limit, stats=stats,
        disclaimer=OBSERVED_RELATIONSHIP_NOTE,
    )


def _engine_edge(e: RawEdge) -> dict[str, Any]:
    return {"id": e.id, "src": graph_id(e.src), "dst": graph_id(e.dst), "relation": e.relation,
            "confidence": e.confidence, "observed_at": e.observed_at, "session_id": e.session_id, "basis": e.basis}


def _edge_out(e: dict[str, Any]) -> GraphEdgeOut:
    return GraphEdgeOut(id=e["id"], src=e["src"], dst=e["dst"], relation=e["relation"],
                        relation_label=RELATION_LABELS.get(e["relation"], e["relation"].replace("_", " ")),
                        confidence=e["confidence"], basis=e.get("basis") or "provenance_edge",
                        observed_at=e.get("observed_at"), session_id=e.get("session_id"))


def _empty(limit: int) -> ProvenanceGraphOut:
    return ProvenanceGraphOut(
        scope=GraphScopeOut(kind="none", label="No activity recorded yet"), nodes=[], edges=[], risky_paths=[],
        truncated=False, limit=limit, disclaimer=OBSERVED_RELATIONSHIP_NOTE,
        stats=GraphStatsOut(node_count=0, edge_count=0, available_node_count=0, node_counts={}, session_count=0,
                            inferred_edge_count=0, dropped_edge_count=0, risky_path_count=0, untrusted_node_count=0),
    )


def build_provenance_graph(
    db: Session, org_id: str, *, session_id: str | None = None, agent_id: str | None = None,
    context_item_id: str | None = None, finding_id: str | None = None, depth: int = DEFAULT_DEPTH,
    limit: int = DEFAULT_NODE_LIMIT,
) -> ProvenanceGraphOut:
    """The provenance graph for one scope; without a scope, the most recent high-risk session."""
    requested = [v for v in (session_id, agent_id, context_item_id, finding_id) if v]
    if len(requested) > 1:
        raise ValidationFailedError("Choose one scope: session_id, agent_id, context_item_id or finding_id")
    collected: Collected | None
    if session_id:
        collected = _session_scope(db, org_id, get_scoped(db, AgentSession, session_id, org_id, label="Session"))
    elif agent_id:
        collected = _agent_scope(db, org_id, get_scoped(db, Agent, agent_id, org_id, label="Agent"))
    elif context_item_id:
        item = get_scoped(db, ContextItem, context_item_id, org_id, label="Context item")
        collected = _item_scope(db, org_id, item, depth)
    elif finding_id:
        finding = get_scoped(db, SecurityFinding, finding_id, org_id, label="Finding")
        collected = _finding_scope(db, org_id, finding, depth)
    else:
        collected = _auto_scope(db, org_id)
    return _empty(limit) if collected is None else _assemble(db, org_id, collected, limit)


# -- node inspector -------------------------------------------------------------------------------

_FINDING_SUBJECT: dict[str, Callable[[str], Any]] = {
    N.TOOL_INVOCATION.value: lambda ref: SecurityFinding.tool_invocation_id == ref,
    N.CONTEXT_ITEM.value: lambda ref: SecurityFinding.context_item_id == ref,
    N.SESSION.value: lambda ref: SecurityFinding.session_id == ref,
    N.FINDING.value: lambda ref: SecurityFinding.id == ref,
}


def node_detail(db: Session, org_id: str, node_type: str, ref_id: str) -> NodeDetailOut:
    if node_type not in NODE_TYPES:
        raise NotFoundError(f"Unknown provenance node type '{node_type}'")
    key: Key = (node_type, ref_id)
    cond = or_(and_(PE.src_type == node_type, PE.src_id == ref_id), and_(PE.dst_type == node_type, PE.dst_id == ref_id))
    rows = [_raw(r) for r in db.scalars(scoped(PE, org_id).where(cond).order_by(PE.observed_at.desc(), PE.id).limit(_MAX_LINKS))]
    total = db.scalar(select(func.count()).select_from(scoped(PE, org_id).where(cond).subquery())) or 0
    if node_type in _FINDING_SUBJECT:
        extra = [e for e in _finding_record_edges(db, org_id, _findings_where(db, org_id, _FINDING_SUBJECT[node_type](ref_id)))
                 if key in (e.src, e.dst)]
        rows.extend(extra)
        total += len(extra)
    meta = nodes_mod.resource_meta(rows)
    found = nodes_mod.resolve(db, org_id, {key} | {end for e in rows for end in (e.src, e.dst)}, meta)
    if key not in found or (node_type == N.RESOURCE.value and ref_id not in meta):
        raise NotFoundError(f"{node_type.replace('_', ' ').capitalize()} '{ref_id}' not found")
    resolved = {k: r.out for k, r in found.items()}
    node = resolved[key]
    fields, notes, preview, preview_label = nodes_mod.describe(db, org_id, node_type, ref_id, meta)
    links: list[NodeLinkOut] = []
    for e in rows:
        out = e.src == key
        other = resolved.get(e.dst if out else e.src)
        if other is None:
            continue
        links.append(NodeLinkOut(node=other, relation=e.relation, confidence=e.confidence, basis=e.basis,  # type: ignore[arg-type]
                                 relation_label=RELATION_LABELS.get(e.relation, e.relation.replace("_", " ")),
                                 direction="out" if out else "in", observed_at=e.observed_at))
    return NodeDetailOut(node=node, fields=[NodeFieldOut(**f) for f in fields], notes=notes, preview=preview,
                         preview_label=preview_label, links=links, link_total=total, disclaimer=OBSERVED_RELATIONSHIP_NOTE)


# -- scope picker ---------------------------------------------------------------------------------


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def scope_options(db: Session, org_id: str, *, q: str | None = None, limit: int = 25) -> ScopeOptionsOut:
    """Sessions and findings (most recent first) and agents the graph can be scoped to."""
    text = (q or "").strip()
    sq = (select(AgentSession, Agent).join(Agent, Agent.id == AgentSession.agent_id)
          .where(AgentSession.organization_id == org_id, Agent.organization_id == org_id))
    aq = (select(Agent, func.count(AgentSession.id)).outerjoin(
        AgentSession, and_(AgentSession.agent_id == Agent.id, AgentSession.organization_id == org_id))
        .where(Agent.organization_id == org_id).group_by(Agent.id))
    if text:
        pattern = _like(text)
        sq = sq.where(or_(Agent.name.ilike(pattern, escape="\\"), AgentSession.external_session_id.ilike(pattern, escape="\\"),
                          AgentSession.id == text))
        aq = aq.where(or_(Agent.name.ilike(pattern, escape="\\"), Agent.id == text))
    sessions = [
        ScopeSessionOut(id=s.id, agent_id=a.id, agent_name=a.name, external_session_id=s.external_session_id,
                        status=s.status, risk_score=s.risk_score or 0, risk_level=(s.risk_state or {}).get("level"),
                        started_at=s.started_at, last_event_at=s.last_event_at, is_simulation=s.is_simulation)
        for s, a in db.execute(sq.order_by(_recent().desc()).limit(limit))
    ]
    agents = [
        ScopeAgentOut(id=a.id, name=a.name, framework=a.framework, environment=a.environment, risk_score=a.risk_score or 0,
                      session_count=int(count), last_seen_at=a.last_seen_at, is_simulation=a.is_simulation)
        for a, count in db.execute(aq.order_by(Agent.name).limit(100))
    ]
    fq = (select(SecurityFinding, Agent.name).outerjoin(
        Agent, and_(Agent.id == SecurityFinding.agent_id, Agent.organization_id == org_id))
        .where(SecurityFinding.organization_id == org_id))
    if text:
        pattern = _like(text)
        fq = fq.where(or_(SecurityFinding.title.ilike(pattern, escape="\\"), SecurityFinding.rule_id.ilike(pattern, escape="\\"),
                          SecurityFinding.id == text))
    findings = [
        ScopeFindingOut(id=f.id, title=f.title, severity=f.severity, category=f.category, status=f.status,
                        session_id=f.session_id, agent_name=agent_name, last_seen_at=f.last_seen_at,
                        is_simulation=f.is_simulation)
        for f, agent_name in db.execute(fq.order_by(SecurityFinding.last_seen_at.desc(), SecurityFinding.id).limit(limit))
    ]
    return ScopeOptionsOut(sessions=sessions, agents=agents, findings=findings)
