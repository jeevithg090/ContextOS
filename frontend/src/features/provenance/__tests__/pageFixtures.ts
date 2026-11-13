/** API fixtures for the provenance page, typed against ../types (mirrors backend/app/schemas/provenance.py). */
import type { GraphEdge, GraphNode, NodeDetail, ProvenanceGraph } from "../types";

function node(overrides: Partial<GraphNode> & Pick<GraphNode, "id" | "type" | "ref_id" | "label">): GraphNode {
  return {
    subtitle: null,
    session_id: "ses_main",
    trust_level: null,
    severity: null,
    decision: null,
    enforcement: null,
    risk_level: null,
    risk_score: null,
    sensitive: false,
    contains_secrets: false,
    is_simulation: false,
    risk_origin: false,
    observed_at: "2026-11-10T09:05:00Z",
    attributes: {},
    ...overrides,
  };
}

function edge(overrides: Partial<GraphEdge> & Pick<GraphEdge, "id" | "src" | "dst" | "relation" | "relation_label">): GraphEdge {
  return { confidence: "observed", basis: "provenance_edge", observed_at: "2026-11-10T09:05:01Z", session_id: "ses_main", ...overrides };
}

export const NODES: GraphNode[] = [
  node({ id: "source:src_docs", type: "source", ref_id: "src_docs", label: "docs.vendor.example", subtitle: "Web page", trust_level: "SUSPICIOUS", risk_origin: true }),
  node({ id: "context_item:ctx_readme", type: "context_item", ref_id: "ctx_readme", label: "Vendor setup guide", trust_level: "EXTERNAL", severity: "high" }),
  node({ id: "session:ses_main", type: "session", ref_id: "ses_main", label: "payments-coder · sess-7f3a", risk_level: "high", risk_score: 72 }),
  node({ id: "tool_invocation:inv_exfil", type: "tool_invocation", ref_id: "inv_exfil", label: "WebFetch collector.example", decision: "DENY", enforcement: "enforced" }),
  node({ id: "tool_invocation:inv_curl", type: "tool_invocation", ref_id: "inv_curl", label: "Bash curl upload.example", decision: "DENY", enforcement: "advisory" }),
  node({ id: "destination:dst_collector", type: "destination", ref_id: "dst_collector", label: "collector.example", trust_level: "UNKNOWN" }),
];

export const EDGES: GraphEdge[] = [
  edge({ id: "e1", src: "source:src_docs", dst: "context_item:ctx_readme", relation: "produced", relation_label: "Produced" }),
  edge({ id: "e2", src: "context_item:ctx_readme", dst: "session:ses_main", relation: "consumed_by", relation_label: "Consumed by" }),
  edge({ id: "e3", src: "session:ses_main", dst: "tool_invocation:inv_exfil", relation: "requested", relation_label: "Requested" }),
  edge({ id: "e4", src: "tool_invocation:inv_exfil", dst: "destination:dst_collector", relation: "targeted", relation_label: "Targeted", confidence: "inferred" }),
];

export const GRAPH: ProvenanceGraph = {
  scope: {
    kind: "session",
    id: "ses_main",
    label: "Session sess-7f3a (payments-coder)",
    auto_selected: true,
    reason: "Showing the most recent high-risk session.",
    session_ids: ["ses_main"],
    depth: null,
    root_node_ids: ["session:ses_main"],
    is_simulation: false,
  },
  nodes: NODES,
  edges: EDGES,
  risky_paths: [
    {
      id: "path_prevented",
      node_ids: ["source:src_docs", "context_item:ctx_readme", "session:ses_main", "tool_invocation:inv_exfil"],
      edge_ids: ["e1", "e2", "e3"],
      severity: "critical",
      title: "Untrusted page reached a session that tried to send a credential out",
      explanation: "Content from a suspicious source entered the session before an outbound request carrying a credential.",
      score: 88,
      category: "exfiltration",
      outcome: "prevented",
      origin_id: "source:src_docs",
      sink_id: "tool_invocation:inv_exfil",
      session_ids: ["session:ses_main"],
      cross_session: false,
      order_verified: true,
      reasons: ["Suspicious origin (+30)", "Credential in arguments (+40)"],
      related_origin_ids: [],
      inferred_edge_ids: [],
    },
    {
      id: "path_advisory",
      node_ids: ["source:src_docs", "session:ses_main", "tool_invocation:inv_curl"],
      edge_ids: ["e1", "e2"],
      severity: "high",
      title: "Untrusted page reached a session that ran curl",
      explanation: "A denial was returned, but the integration may not have honoured it.",
      score: 61,
      category: "exfiltration",
      outcome: "advisory_only",
      origin_id: "source:src_docs",
      sink_id: "tool_invocation:inv_curl",
      session_ids: ["session:ses_main"],
      cross_session: false,
      order_verified: false,
      reasons: ["Suspicious origin (+30)"],
      related_origin_ids: [],
      inferred_edge_ids: [],
    },
  ],
  truncated: false,
  truncation_reason: null,
  limit: 200,
  stats: {
    node_count: 6,
    edge_count: 4,
    available_node_count: 6,
    node_counts: { source: 1, context_item: 1, session: 1, tool_invocation: 2, destination: 1 },
    session_count: 1,
    inferred_edge_count: 1,
    dropped_edge_count: 0,
    risky_path_count: 2,
    untrusted_node_count: 2,
  },
  disclaimer: "Edges are observed relationships, not causation.",
};

export const EMPTY_GRAPH: ProvenanceGraph = {
  ...GRAPH,
  scope: { kind: "none", id: null, label: "Nothing recorded", auto_selected: true, reason: null, session_ids: [], depth: null, root_node_ids: [], is_simulation: false },
  nodes: [],
  edges: [],
  risky_paths: [],
  stats: { ...GRAPH.stats, node_count: 0, edge_count: 0, available_node_count: 0, node_counts: {}, session_count: 0, inferred_edge_count: 0, risky_path_count: 0, untrusted_node_count: 0 },
};

export const SOURCE_DETAIL: NodeDetail = {
  node: NODES[0],
  fields: [
    { key: "identifier", label: "Identifier", value: "https://docs.vendor.example/setup", kind: "mono" },
    { key: "trust_level", label: "Trust", value: "SUSPICIOUS", kind: "trust" },
  ],
  notes: ["Classified SUSPICIOUS by the trust rule “Vendor docs”."],
  preview: null,
  preview_label: null,
  links: [{ node: NODES[1], relation: "produced", relation_label: "Produced", direction: "out", confidence: "observed", basis: "provenance_edge", observed_at: "2026-11-10T09:05:01Z" }],
  link_total: 1,
  disclaimer: "Observed relationships, not causation.",
};
