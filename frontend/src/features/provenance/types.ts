/**
 * Provenance / Context Trust Graph contract. Mirrors backend/app/schemas/provenance.py.
 * Graph node ids are "<type>:<ref_id>"; `ref_id` is the underlying record id used for links.
 */

export const PROVENANCE_NODE_TYPES = [
  "source",
  "context_item",
  "session",
  "agent",
  "tool",
  "tool_invocation",
  "resource",
  "destination",
  "finding",
  "policy_decision",
] as const;
export type ProvenanceNodeType = (typeof PROVENANCE_NODE_TYPES)[number];

export type ScopeKind = "session" | "agent" | "context_item" | "finding" | "none";
export type EdgeBasis = "provenance_edge" | "finding_record";
export type PathOutcome = "prevented" | "awaiting_approval" | "advisory_only" | "not_prevented";

export interface GraphNode {
  id: string;
  type: ProvenanceNodeType | string;
  ref_id: string;
  label: string;
  subtitle: string | null;
  session_id: string | null;
  trust_level: string | null;
  severity: string | null;
  decision: string | null;
  enforcement: string | null;
  risk_level: string | null;
  risk_score: number | null;
  sensitive: boolean;
  contains_secrets: boolean;
  is_simulation: boolean;
  risk_origin: boolean;
  observed_at: string | null;
  attributes: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  src: string;
  dst: string;
  relation: string;
  relation_label: string;
  /** "observed" (recorded directly) or "inferred" (derived by ContextOS, e.g. a fingerprint match). */
  confidence: string;
  basis: EdgeBasis;
  observed_at: string | null;
  session_id: string | null;
}

export interface RiskyPath {
  id: string;
  node_ids: string[];
  edge_ids: string[];
  severity: string;
  title: string;
  explanation: string;
  score: number;
  category: string | null;
  outcome: PathOutcome | string;
  origin_id: string | null;
  sink_id: string | null;
  session_ids: string[];
  cross_session: boolean;
  order_verified: boolean;
  reasons: string[];
  related_origin_ids: string[];
  inferred_edge_ids: string[];
}

export interface GraphScope {
  kind: ScopeKind;
  id: string | null;
  label: string;
  auto_selected: boolean;
  reason: string | null;
  session_ids: string[];
  depth: number | null;
  root_node_ids: string[];
  is_simulation: boolean;
}

export interface GraphStats {
  node_count: number;
  edge_count: number;
  available_node_count: number;
  node_counts: Record<string, number>;
  session_count: number;
  inferred_edge_count: number;
  dropped_edge_count: number;
  risky_path_count: number;
  untrusted_node_count: number;
}

export interface ProvenanceGraph {
  scope: GraphScope;
  nodes: GraphNode[];
  edges: GraphEdge[];
  risky_paths: RiskyPath[];
  truncated: boolean;
  truncation_reason: string | null;
  limit: number;
  stats: GraphStats;
  disclaimer: string;
}

export type NodeFieldKind =
  | "text"
  | "mono"
  | "datetime"
  | "number"
  | "bool"
  | "list"
  | "trust"
  | "severity"
  | "decision"
  | "enforcement"
  | "risk";

export interface NodeField {
  key: string;
  label: string;
  value: string | number | boolean | string[] | null;
  kind: NodeFieldKind;
}

export interface NodeLink {
  node: GraphNode;
  relation: string;
  relation_label: string;
  /** out: inspected node -> linked node; in: linked node -> inspected node. */
  direction: "in" | "out";
  confidence: string;
  basis: EdgeBasis;
  observed_at: string | null;
}

export interface NodeDetail {
  node: GraphNode;
  fields: NodeField[];
  notes: string[];
  preview: string | null;
  preview_label: string | null;
  links: NodeLink[];
  link_total: number;
  disclaimer: string;
}

export interface ScopeSession {
  id: string;
  agent_id: string;
  agent_name: string;
  external_session_id: string;
  status: string;
  risk_score: number;
  risk_level: string | null;
  started_at: string;
  last_event_at: string | null;
  is_simulation: boolean;
}

export interface ScopeAgent {
  id: string;
  name: string;
  framework: string;
  environment: string;
  risk_score: number;
  session_count: number;
  last_seen_at: string | null;
  is_simulation: boolean;
}

export interface ScopeFinding {
  id: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  session_id: string | null;
  agent_name: string | null;
  last_seen_at: string;
  is_simulation: boolean;
}

export interface ScopeOptions {
  sessions: ScopeSession[];
  agents: ScopeAgent[];
  /** Most recently seen first. */
  findings: ScopeFinding[];
}

/** What the page asks the graph endpoint for (exactly one scope, or none for the auto scope). */
export interface GraphQuery {
  session_id?: string;
  agent_id?: string;
  context_item_id?: string;
  finding_id?: string;
  depth?: number;
  limit?: number;
}
