"""STUB — to be implemented by the provenance work package. Keep these signatures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProvenanceGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)  # id -> node
    edges: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": self.edges}


@dataclass
class RiskyPath:
    node_ids: list[str]
    edge_ids: list[str]
    severity: str
    title: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_ids": self.node_ids,
            "edge_ids": self.edge_ids,
            "severity": self.severity,
            "title": self.title,
            "explanation": self.explanation,
        }


def receipt_fields(item: dict[str, Any]) -> dict[str, Any]:
    raise NotImplementedError


def sign_receipt(fields: dict[str, Any]) -> str:
    raise NotImplementedError


def verify_receipt(fields: dict[str, Any], signature: str) -> bool:
    raise NotImplementedError


def build_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> ProvenanceGraph:
    raise NotImplementedError


def find_risky_paths(graph: ProvenanceGraph, *, max_depth: int = 8) -> list[RiskyPath]:
    raise NotImplementedError
