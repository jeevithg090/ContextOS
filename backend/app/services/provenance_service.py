"""Provenance / Context Trust Graph: graph assembly, risky paths, inspector detail and scope picker.

Scope collection (which recorded relationships belong to a session, agent, item or finding) lives
in ``provenance_scope``; node resolution in ``provenance_nodes``. Edges are observed relationships
recorded by the ingestion pipeline (or the subject stored on a finding); none of them is a causal
claim — see ``OBSERVED_RELATIONSHIP_NOTE``.

Every query filters on the caller's organisation; ids from another organisation resolve to 404.
Graphs are bounded: at most ``MAX_EDGES`` edges are read and at most ``limit`` nodes returned. Nodes on
risky paths and the scope root are kept first, so truncation never hides the paths it reports.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationFailedError
from app.core.security import sha256_hex
from app.domain.enums import SEVERITY_RANK, TRUST_RANK, ProvenanceNodeType, ProvenanceRelation
from app.engines.provenance import OBSERVED_RELATIONSHIP_NOTE, build_graph, find_risky_paths
from app.models import Agent, AgentSession, ContextItem, ProvenanceEdge, SecurityFinding
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
from app.services.provenance_scope import (
    FINDING_EVIDENCE,
    HIGH_RISK_SCORE,
    MAX_EDGES,
    Collected,
    Key,
    RawEdge,
    agent_scope,
    auto_scope,
    finding_record_edges,
    finding_scope,
    findings_where,
    graph_id,
    item_scope,
    raw_edge,
    recent_activity,
    session_scope,
)
from app.services.scoping import get_scoped, scoped

N = ProvenanceNodeType
R = ProvenanceRelation
PE = ProvenanceEdge
NODE_TYPES = {t.value for t in N}
DEFAULT_NODE_LIMIT = 400
DEFAULT_DEPTH = 2
MAX_PATHS = 25
_MAX_PATH_DEPTH = 8
_MAX_LINKS = 60
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

__all__ = [
    "DEFAULT_DEPTH", "DEFAULT_NODE_LIMIT", "HIGH_RISK_SCORE", "MAX_EDGES", "RELATION_LABELS", "RawEdge",
    "build_provenance_graph", "graph_id", "node_detail", "risky_paths_for_session", "scope_options",
]


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


def _analyse(db: Session, org_id: str, col: Collected) -> tuple[dict[Key, Any], Any, list[Any]]:
    """Resolve every node of the scope, build the engine graph and find its risky paths."""
    raw_edges = list(col.edges.values())
    keys = {end for e in raw_edges for end in (e.src, e.dst)} | col.roots
    found = nodes_mod.resolve(db, org_id, keys, nodes_mod.resource_meta(raw_edges))
    full = build_graph([r.engine for r in found.values()], [_engine_edge(e) for e in raw_edges])
    return found, full, find_risky_paths(full, max_depth=_MAX_PATH_DEPTH, max_results=MAX_PATHS)


def _assemble(db: Session, org_id: str, col: Collected, limit: int) -> ProvenanceGraphOut:
    found, full, paths = _analyse(db, org_id, col)
    resolved = {k: r.out for k, r in found.items()}
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
        collected = session_scope(db, org_id, get_scoped(db, AgentSession, session_id, org_id, label="Session"))
    elif agent_id:
        collected = agent_scope(db, org_id, get_scoped(db, Agent, agent_id, org_id, label="Agent"))
    elif context_item_id:
        item = get_scoped(db, ContextItem, context_item_id, org_id, label="Context item")
        collected = item_scope(db, org_id, item, depth)
    elif finding_id:
        finding = get_scoped(db, SecurityFinding, finding_id, org_id, label="Finding")
        collected = finding_scope(db, org_id, finding, depth)
    else:
        collected = auto_scope(db, org_id)
    return _empty(limit) if collected is None else _assemble(db, org_id, collected, limit)


def risky_paths_for_session(db: Session, org_id: str, session_id: str) -> list[RiskyPathOut]:
    """Risky paths of one session's scope (the session and the sessions linked to it by delegation).

    Unlike the graph view no node limit applies, so every path the analysis finds is returned (at
    most ``MAX_PATHS``). Paths are sequences of observed relationships, never proof of causation.
    Raises ``NotFoundError`` for a session of another organisation.
    """
    session = get_scoped(db, AgentSession, session_id, org_id, label="Session")
    _found, _full, paths = _analyse(db, org_id, session_scope(db, org_id, session))
    return [_path_out(p) for p in paths]


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
    rows = [raw_edge(r) for r in db.scalars(scoped(PE, org_id).where(cond).order_by(PE.observed_at.desc(), PE.id).limit(_MAX_LINKS))]
    total = db.scalar(select(func.count()).select_from(scoped(PE, org_id).where(cond).subquery())) or 0
    if node_type in _FINDING_SUBJECT:
        extra = [e for e in finding_record_edges(db, org_id, findings_where(db, org_id, _FINDING_SUBJECT[node_type](ref_id)))
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
        for s, a in db.execute(sq.order_by(recent_activity().desc()).limit(limit))
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
