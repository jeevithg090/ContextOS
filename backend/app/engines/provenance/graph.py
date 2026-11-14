"""Provenance graph assembly: normalise, deduplicate and validate nodes and edges.

Nodes are ``{"id", "type", "label", ...attributes}`` where ``type`` is a
``domain.enums.ProvenanceNodeType`` value. Edges are ``{"id", "src", "dst", "relation", "confidence",
...}``; ``confidence`` is ``"observed"`` (directly recorded) or ``"inferred"`` (derived by ContextOS,
e.g. a secret-fingerprint match). Every edge is an observed or inferred relationship — never a causal
claim (see ``OBSERVED_RELATIONSHIP_NOTE``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from app.engines.provenance._util import OBSERVED_RELATIONSHIP_NOTE

DEFAULT_CONFIDENCE = "observed"
UNSPECIFIED_RELATION = "unspecified"
_MAX_LISTED_DROPPED = 50


@dataclass
class ProvenanceGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)  # id -> node
    edges: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": self.edges, "metadata": self.metadata}


@dataclass(frozen=True)
class EdgeRef:
    edge: dict[str, Any]
    other: str  # the node at the far end of the edge

    @property
    def id(self) -> str:
        return self.edge["id"]


class GraphIndex:
    """Adjacency view over a graph. Edges whose endpoints are not nodes are ignored."""

    def __init__(self, graph: ProvenanceGraph) -> None:
        self.nodes = graph.nodes
        self.out: dict[str, list[EdgeRef]] = {}
        self.inc: dict[str, list[EdgeRef]] = {}
        self.edges_by_id: dict[str, dict[str, Any]] = {}
        for edge in graph.edges:
            src, dst = edge.get("src"), edge.get("dst")
            if src not in graph.nodes or dst not in graph.nodes or "id" not in edge:
                continue
            self.edges_by_id[edge["id"]] = edge
            self.out.setdefault(src, []).append(EdgeRef(edge, dst))
            self.inc.setdefault(dst, []).append(EdgeRef(edge, src))

    def type_of(self, node_id: str) -> str:
        return str(self.nodes[node_id].get("type") or "")

    def out_of_type(self, node_id: str, *types: str) -> list[EdgeRef]:
        return [ref for ref in self.out.get(node_id, []) if self.type_of(ref.other) in types]

    def in_of_type(self, node_id: str, *types: str) -> list[EdgeRef]:
        return [ref for ref in self.inc.get(node_id, []) if self.type_of(ref.other) in types]


def _normalise_node(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    node_id = raw.get("id")
    if node_id is None or str(node_id) == "":
        return None
    node = dict(raw)
    node["id"] = str(node_id)
    node["type"] = str(raw.get("type") or "").strip().lower()
    label = raw.get("label")
    node["label"] = str(label) if label not in (None, "") else node["id"]
    return node


def _merge_into(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Fill attributes the first occurrence lacks; the first occurrence wins on conflicts."""
    for key, value in incoming.items():
        if value is not None and existing.get(key) in (None, "", [], {}):
            existing[key] = value


def _normalise_edge(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    src, dst = raw.get("src"), raw.get("dst")
    if src in (None, "") or dst in (None, ""):
        return None
    edge = dict(raw)
    edge["src"], edge["dst"] = str(src), str(dst)
    edge["relation"] = str(raw.get("relation") or UNSPECIFIED_RELATION)
    edge["confidence"] = str(raw.get("confidence") or DEFAULT_CONFIDENCE).lower()
    edge_id = raw.get("id")
    edge["id"] = (
        str(edge_id) if edge_id not in (None, "") else f"{edge['src']}->{edge['dst']}:{edge['relation']}"
    )
    return edge


def build_graph(nodes: Iterable[Mapping[str, Any]], edges: Iterable[Mapping[str, Any]]) -> ProvenanceGraph:
    """Assemble a graph from loosely-collected nodes and edges.

    - Nodes are deduplicated by id; a later duplicate only fills attributes the first one lacks.
      Nodes without an id are discarded (``invalid_node_count``).
    - Edges are deduplicated by id. Edges whose ``src``/``dst`` is absent or not among the nodes are
      dropped and counted in ``metadata["dropped_edge_count"]`` (first ids in ``dropped_edge_ids``) so a
      viewer can tell the graph is partial rather than silently losing relationships.
    - ``relation`` and ``confidence`` are preserved (defaults: ``"unspecified"``, ``"observed"``).
    Inputs are never mutated.
    """
    graph = ProvenanceGraph()
    duplicate_nodes = invalid_nodes = 0
    for raw in nodes:
        node = _normalise_node(raw) if isinstance(raw, Mapping) else None
        if node is None:
            invalid_nodes += 1
            continue
        existing = graph.nodes.get(node["id"])
        if existing is None:
            graph.nodes[node["id"]] = node
        else:
            duplicate_nodes += 1
            _merge_into(existing, node)

    seen_edges: set[str] = set()
    dropped_ids: list[str] = []
    dropped = duplicate_edges = 0
    for raw in edges:
        edge = _normalise_edge(raw) if isinstance(raw, Mapping) else None
        if edge is None or edge["src"] not in graph.nodes or edge["dst"] not in graph.nodes:
            dropped += 1
            if edge is not None and len(dropped_ids) < _MAX_LISTED_DROPPED:
                dropped_ids.append(edge["id"])
            continue
        if edge["id"] in seen_edges:
            duplicate_edges += 1
            continue
        seen_edges.add(edge["id"])
        graph.edges.append(edge)

    graph.metadata = {
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "duplicate_node_count": duplicate_nodes,
        "invalid_node_count": invalid_nodes,
        "duplicate_edge_count": duplicate_edges,
        "dropped_edge_count": dropped,
        "dropped_edge_ids": dropped_ids,
        "inferred_edge_count": sum(1 for e in graph.edges if e["confidence"] == "inferred"),
        "note": OBSERVED_RELATIONSHIP_NOTE,
    }
    return graph
