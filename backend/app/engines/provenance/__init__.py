"""Provenance engine (pure; no database access).

CONTRACT:

    receipt_fields(item: dict) -> dict             # canonical subset of a ContextItem that a receipt attests to
    sign_receipt(fields: dict) -> str              # keyed HMAC over canonical JSON (purpose "context-receipt-v1")
    verify_receipt(fields: dict, signature) -> bool

    build_graph(nodes, edges) -> ProvenanceGraph   # nodes: [{"id","type","label","trust_level"?,"risk"?,...}]
                                                   # edges: [{"id","src","dst","relation","confidence"}]
    find_risky_paths(graph, *, max_depth=8) -> list[RiskyPath]
        Paths from an untrusted node (source/context_item with trust in UNTRUSTED_LEVELS or with
        detections) through a session to a tool invocation that accessed a sensitive resource and/or
        sent data to a non-approved destination. Each path explains itself and states that edges are
        observed relationships, not proven causation.
"""

from app.engines.provenance.engine import (
    ProvenanceGraph,
    RiskyPath,
    build_graph,
    find_risky_paths,
    receipt_fields,
    sign_receipt,
    verify_receipt,
)

__all__ = [
    "ProvenanceGraph",
    "RiskyPath",
    "build_graph",
    "find_risky_paths",
    "receipt_fields",
    "sign_receipt",
    "verify_receipt",
]
