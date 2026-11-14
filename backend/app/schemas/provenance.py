"""Provenance / Context Trust Graph schemas.

Mirrored by ``frontend/src/features/provenance/types.ts``. Graph node ids are ``"<type>:<ref_id>"`` so
ids from different tables can never collide; ``ref_id`` is the record id used for links.

Every edge is a relationship ContextOS observed (or inferred, e.g. a secret-fingerprint match) — never
a claim that content caused an action. ``disclaimer`` carries that statement on every response.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

ScopeKind = Literal["session", "agent", "context_item", "finding", "none"]
EdgeBasis = Literal["provenance_edge", "finding_record"]
FieldValue = str | int | float | bool | list[str] | None


class GraphNodeOut(BaseModel):
    id: str = Field(description='Graph id: "<type>:<ref_id>"')
    type: str = Field(description="domain.enums.ProvenanceNodeType")
    ref_id: str = Field(description="Id of the underlying record (resource ids are '<kind>:<identifier>')")
    label: str
    subtitle: str | None = Field(default=None, description="Short metadata line shown under the label")
    session_id: str | None = Field(
        default=None, description="Owning session, for links to tool calls / decisions"
    )
    trust_level: str | None = None
    severity: str | None = Field(
        default=None, description="Finding severity or the item's highest detection severity"
    )
    decision: str | None = None
    enforcement: str | None = None
    risk_level: str | None = None
    risk_score: int | None = None
    sensitive: bool = False
    contains_secrets: bool = False
    is_simulation: bool = False
    risk_origin: bool = Field(default=False, description="Starts at least one risky path in this graph")
    observed_at: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphEdgeOut(BaseModel):
    id: str
    src: str
    dst: str
    relation: str
    relation_label: str
    confidence: str = Field(description='"observed" (recorded) or "inferred" (derived by ContextOS)')
    basis: EdgeBasis = Field(
        default="provenance_edge",
        description="provenance_edge: recorded by the pipeline; finding_record: the subject stored on the finding",
    )
    observed_at: datetime | None = None
    session_id: str | None = None


class RiskyPathOut(BaseModel):
    id: str
    node_ids: list[str]
    edge_ids: list[str]
    severity: str
    title: str
    explanation: str
    score: int
    category: str | None = None
    outcome: str = Field(description="prevented | awaiting_approval | advisory_only | not_prevented")
    origin_id: str | None = None
    sink_id: str | None = None
    session_ids: list[str] = Field(default_factory=list)
    cross_session: bool = False
    order_verified: bool = True
    reasons: list[str] = Field(default_factory=list)
    related_origin_ids: list[str] = Field(default_factory=list)
    inferred_edge_ids: list[str] = Field(default_factory=list)


class GraphScopeOut(BaseModel):
    kind: ScopeKind
    id: str | None = None
    label: str
    auto_selected: bool = False
    reason: str | None = Field(default=None, description="Why this scope was chosen when none was requested")
    session_ids: list[str] = Field(default_factory=list, description="Sessions whose activity is included")
    depth: int | None = Field(default=None, description="Hops expanded (context item / finding scopes)")
    root_node_ids: list[str] = Field(default_factory=list)
    is_simulation: bool = False


class GraphStatsOut(BaseModel):
    node_count: int
    edge_count: int
    available_node_count: int = Field(description="Nodes in scope before the size limit was applied")
    node_counts: dict[str, int]
    session_count: int
    inferred_edge_count: int
    dropped_edge_count: int = Field(description="Edges whose endpoint record could not be resolved")
    risky_path_count: int
    untrusted_node_count: int


class ProvenanceGraphOut(BaseModel):
    scope: GraphScopeOut
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    risky_paths: list[RiskyPathOut]
    truncated: bool
    truncation_reason: str | None = None
    limit: int
    stats: GraphStatsOut
    disclaimer: str


class NodeFieldOut(BaseModel):
    key: str
    label: str
    value: FieldValue = None
    kind: Literal[
        "text",
        "mono",
        "datetime",
        "number",
        "bool",
        "list",
        "trust",
        "severity",
        "decision",
        "enforcement",
        "risk",
    ] = "text"


class NodeLinkOut(BaseModel):
    node: GraphNodeOut
    relation: str
    relation_label: str
    direction: Literal["in", "out"] = Field(
        description="out: this node -> linked node; in: linked node -> this node"
    )
    confidence: str
    basis: EdgeBasis = "provenance_edge"
    observed_at: datetime | None = None


class NodeDetailOut(BaseModel):
    node: GraphNodeOut
    fields: list[NodeFieldOut]
    notes: list[str] = Field(
        default_factory=list, description="Plain-language explanations recorded for this node"
    )
    preview: str | None = Field(
        default=None, description="Redacted, truncated content (item text, call arguments)"
    )
    preview_label: str | None = None
    links: list[NodeLinkOut]
    link_total: int
    disclaimer: str


class ScopeSessionOut(BaseModel):
    id: str
    agent_id: str
    agent_name: str
    external_session_id: str
    status: str
    risk_score: int
    risk_level: str | None = None
    started_at: datetime
    last_event_at: datetime | None = None
    is_simulation: bool = False


class ScopeAgentOut(BaseModel):
    id: str
    name: str
    framework: str
    environment: str
    risk_score: int
    session_count: int
    last_seen_at: datetime | None = None
    is_simulation: bool = False


class ScopeFindingOut(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    status: str
    session_id: str | None = None
    agent_name: str | None = None
    last_seen_at: datetime
    is_simulation: bool = False


class ScopeOptionsOut(BaseModel):
    sessions: list[ScopeSessionOut]
    agents: list[ScopeAgentOut]
    findings: list[ScopeFindingOut] = Field(default_factory=list, description="Most recently seen first")
