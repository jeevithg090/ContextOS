"""Provenance engine public surface (pure; no database access).

Implementation is split by responsibility:

- ``receipts``  canonical context-receipt fields, signing and verification
- ``graph``     node/edge normalisation, deduplication and adjacency
- ``signals``   reading trust / detection / sensitivity / destination / decision signals off nodes
- ``search``    time-aware directed walks from untrusted origins to tool invocations
- ``assess``    explainable scoring of a walk; ``explain`` turns it into plain language
- ``paths``     ``RiskyPath`` and ``find_risky_paths`` (merging, deduplication, ordering, caps)
"""

from __future__ import annotations

from app.engines.provenance._util import OBSERVED_RELATIONSHIP_NOTE
from app.engines.provenance.graph import ProvenanceGraph, build_graph
from app.engines.provenance.paths import RiskyPath, find_risky_paths
from app.engines.provenance.receipts import (
    RECEIPT_PURPOSE,
    RECEIPT_VERSION,
    canonical_json,
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
