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

Additions (backwards compatible):

    canonical_json(fields) -> str                  # the exact text a receipt signature covers
    RECEIPT_VERSION ("1"), RECEIPT_PURPOSE ("context-receipt-v1"), OBSERVED_RELATIONSHIP_NOTE
    ProvenanceGraph.metadata                       # counts incl. dropped_edge_count / dropped_edge_ids
    find_risky_paths(..., max_results=25)
    RiskyPath extra fields: score, category, outcome (prevented|awaiting_approval|advisory_only|
        not_prevented), origin_id, sink_id, session_ids, cross_session, order_verified, reasons,
        related_origin_ids, inferred_edge_ids

Node attributes the risky-path analysis reads are documented in ``signals.py``.
"""

from app.engines.provenance.engine import (
    OBSERVED_RELATIONSHIP_NOTE,
    RECEIPT_PURPOSE,
    RECEIPT_VERSION,
    ProvenanceGraph,
    RiskyPath,
    build_graph,
    canonical_json,
    find_risky_paths,
    receipt_fields,
    sign_receipt,
    verify_receipt,
)

__all__ = [
    "OBSERVED_RELATIONSHIP_NOTE",
    "RECEIPT_PURPOSE",
    "RECEIPT_VERSION",
    "ProvenanceGraph",
    "RiskyPath",
    "build_graph",
    "canonical_json",
    "find_risky_paths",
    "receipt_fields",
    "sign_receipt",
    "verify_receipt",
]
