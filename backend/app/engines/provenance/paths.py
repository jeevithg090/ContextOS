"""Risky-path analysis over a provenance graph.

A risky path starts at an untrusted origin (a source or context item whose trust is BLOCKED,
SUSPICIOUS, UNKNOWN or EXTERNAL, or which detection flagged at medium severity or worse), runs through
one or more sessions (``session_delegated_to`` / agent messages give multi-agent paths), and ends at a
tool invocation that accessed a sensitive resource, sent data to a destination that is not
TRUSTED/APPROVED, or that policy denied or held for approval.

Paths describe relationships ContextOS observed; they are never presented as proof of causation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.engines.provenance.assess import Assessment, assess, priority
from app.engines.provenance.graph import GraphIndex, ProvenanceGraph
from app.engines.provenance.search import walks_from
from app.engines.provenance.signals import (
    ADVISORY_ONLY,
    AWAITING_APPROVAL,
    NOT_PREVENTED,
    PREVENTED,
    InvocationAnalysis,
    analyze_invocation,
    is_origin,
)

DEFAULT_MAX_RESULTS = 25
# Work bounds so a very large graph cannot make a request hang; results are still severity-sorted.
_MAX_ORIGINS = 500
_MAX_WALKS_PER_ORIGIN = 200
_MAX_CANDIDATES = 5000
# How much of the action was stopped; a path never hides one whose action was stopped less.
_STOPPED_RANK = {NOT_PREVENTED: 0, ADVISORY_ONLY: 1, AWAITING_APPROVAL: 2, PREVENTED: 3}


@dataclass
class RiskyPath:
    node_ids: list[str]
    edge_ids: list[str]
    severity: str
    title: str
    explanation: str
    score: int = 0
    category: str | None = None  # suggested domain.enums.FindingCategory
    outcome: str = NOT_PREVENTED  # prevented | awaiting_approval | advisory_only | not_prevented
    origin_id: str | None = None
    sink_id: str | None = None  # the tool invocation the path ends at
    session_ids: list[str] = field(default_factory=list)
    cross_session: bool = False
    order_verified: bool = True  # False when a timestamp was missing for some step
    reasons: list[str] = field(default_factory=list)  # evidence lines, plain language
    related_origin_ids: list[str] = field(default_factory=list)  # other untrusted origins on the same route
    inferred_edge_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_ids": self.node_ids,
            "edge_ids": self.edge_ids,
            "severity": self.severity,
            "title": self.title,
            "explanation": self.explanation,
            "score": self.score,
            "category": self.category,
            "outcome": self.outcome,
            "origin_id": self.origin_id,
            "sink_id": self.sink_id,
            "session_ids": self.session_ids,
            "cross_session": self.cross_session,
            "order_verified": self.order_verified,
            "reasons": self.reasons,
            "related_origin_ids": self.related_origin_ids,
            "inferred_edge_ids": self.inferred_edge_ids,
        }


def _route_key(index: GraphIndex, a: Assessment) -> tuple[str, tuple[str, ...]]:
    """Paths that share everything from the first session onwards differ only in which origin fed it."""
    nodes = a.walk.nodes
    first_session = next((i for i, n in enumerate(nodes) if index.type_of(n) == "session"), 0)
    return a.sink.node_id, tuple(nodes[first_session:])


def _merge_same_route(index: GraphIndex, candidates: list[Assessment]) -> list[Assessment]:
    groups: dict[tuple[str, tuple[str, ...]], list[Assessment]] = {}
    for a in candidates:
        groups.setdefault(_route_key(index, a), []).append(a)
    merged: list[Assessment] = []
    for members in groups.values():
        members.sort(key=lambda m: (-m.score, -len(m.node_ids), tuple(m.node_ids)))
        best = members[0]
        on_path = set(best.node_ids)
        related: list[str] = []
        for other in members[1:]:
            for node_id in other.walk.nodes:
                if index.type_of(node_id) == "session":
                    break
                if node_id not in on_path and node_id not in related:
                    related.append(node_id)
        best.related_origin_ids = related
        merged.append(best)
    return merged


def _drop_contained(candidates: list[Assessment]) -> list[Assessment]:
    """Drop a path whose nodes all lie on a stronger kept path that already explains its tool call —
    unless that stronger path's outcome would make this action look more stopped than it was."""
    ordered = sorted(candidates, key=lambda a: (-a.score, -len(a.node_ids), tuple(a.node_ids)))
    kept: list[Assessment] = []
    explaining: dict[str, list[tuple[Assessment, frozenset[str]]]] = {}
    for a in ordered:
        nodes = frozenset(a.node_ids)
        if any(
            nodes <= k_nodes and _STOPPED_RANK[k.sink.outcome] <= _STOPPED_RANK[a.sink.outcome]
            for k, k_nodes in explaining.get(a.sink.node_id, [])
        ):
            continue
        kept.append(a)
        for invocation in a.explained_invocations:
            explaining.setdefault(invocation, []).append((a, nodes))
    return kept


def _to_path(a: Assessment) -> RiskyPath:
    return RiskyPath(
        node_ids=a.node_ids,
        edge_ids=a.edge_ids,
        severity=a.severity,
        title=a.title,
        explanation=a.explanation,
        score=a.score,
        category=a.category,
        outcome=a.sink.outcome,
        origin_id=a.origin,
        sink_id=a.sink.node_id,
        session_ids=a.sessions,
        cross_session=len(a.sessions) > 1,
        order_verified=a.walk.order_verified,
        reasons=a.reasons,
        related_origin_ids=a.related_origin_ids,
        inferred_edge_ids=a.inferred_edge_ids,
    )


def find_risky_paths(
    graph: ProvenanceGraph, *, max_depth: int = 8, max_results: int = DEFAULT_MAX_RESULTS
) -> list[RiskyPath]:
    """Risky paths in ``graph``, most severe first, deduplicated and capped at ``max_results``.

    ``max_depth`` bounds the number of edges between the origin and the tool invocation (resource,
    destination and decision leaves hanging off the invocation do not count).
    """
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    if max_results < 1:
        raise ValueError("max_results must be at least 1")
    index = GraphIndex(graph)
    cache: dict[str, InvocationAnalysis] = {}

    def analyze(inv_id: str) -> InvocationAnalysis:
        if inv_id not in cache:
            cache[inv_id] = analyze_invocation(index, inv_id)
        return cache[inv_id]

    origins = [node_id for node_id, node in graph.nodes.items() if is_origin(node)][:_MAX_ORIGINS]
    candidates: list[Assessment] = []
    for origin in origins:
        walks = walks_from(
            index, origin, max_depth=max_depth, limit=_MAX_WALKS_PER_ORIGIN, is_sink=lambda inv: analyze(inv).risky
        )
        candidates.extend(assess(index, walk, analyze(walk.sink), analyze) for walk in walks)
        if len(candidates) >= _MAX_CANDIDATES:
            break

    results = _drop_contained(_merge_same_route(index, candidates))
    results.sort(key=priority)
    return [_to_path(a) for a in results[:max_results]]
