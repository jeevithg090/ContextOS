/**
 * Context Explorer types. Mirrors backend/app/schemas/context.py exactly — change both together.
 * Every string here was redacted server-side before it was stored; raw context never reaches the UI.
 */
import type { Severity, TrustLevel } from "@/lib/domain";

export type SourceType =
  | "web"
  | "repository"
  | "file"
  | "document"
  | "email"
  | "api"
  | "mcp_server"
  | "mcp_tool"
  | "browser"
  | "database"
  | "user_upload"
  | "user_prompt"
  | "tool_output"
  | "agent_output"
  | "system"
  | "other";

export type Sensitivity = "public" | "internal" | "confidential" | "secret";

export interface SourceRef {
  id: string;
  source_type: SourceType | string;
  identifier: string;
  display_name: string | null;
  domain: string | null;
  /** The source's CURRENT classification (an item's own trust_level is the trust at ingest). */
  trust_level: TrustLevel | string;
}

export interface AgentRef {
  id: string;
  name: string | null;
}

export interface SessionRef {
  id: string;
  external_session_id: string | null;
  status: string | null;
}

export interface DetectionCounts {
  score: number;
  max_severity: Severity | null;
  hit_count: number;
  rule_ids: string[];
  categories: string[];
}

export interface ContextItemSummary {
  id: string;
  source: SourceRef;
  trust_level: TrustLevel | string;
  trust_capabilities: string[];
  sensitivity: Sensitivity | string;
  contains_secrets: boolean;
  detection: DetectionCounts;
  finding_count: number;
  agent: AgentRef;
  session: SessionRef;
  collected_via: string;
  collected_at: string;
  received_at: string;
  content_type: string;
  content_length: number;
  tool_invocation_id: string | null;
  is_simulation: boolean;
}

export interface DetectionHit {
  rule_id: string;
  category: string;
  title: string;
  severity: Severity | string;
  confidence: number;
  technique: string;
  explanation: string;
  /** "finding": the persisted finding's explanation; "category": a general description of the category. */
  explanation_source: "finding" | "category";
  excerpt: string | null;
  finding_id: string | null;
}

export interface DetectionDetail extends DetectionCounts {
  classifier_score: number | null;
  hits: DetectionHit[];
  findings_suppressed_reason: string | null;
}

export interface FindingRef {
  id: string;
  title: string;
  category: string;
  rule_id: string;
  severity: Severity | string;
  status: string;
  confidence: number;
  last_seen_at: string;
  incident_id: string | null;
}

export interface ProvenanceEdge {
  id: string;
  relation: string;
  src: { type: string; id: string };
  dst: { type: string; id: string };
  confidence: "observed" | "inferred" | string;
  observed_at: string;
}

export interface ToolInvocationRef {
  id: string;
  tool_name: string | null;
  tool_provider: string | null;
  tool_category: string | null;
  status: string;
  decision: string | null;
  enforcement: string;
  requested_at: string;
  completed_at: string | null;
}

export interface ContextItemDetail extends Omit<ContextItemSummary, "detection"> {
  event_id: string;
  content_hash: string | null;
  redacted_preview: string | null;
  preview_stored: boolean;
  preview_truncated: boolean;
  secret_fingerprint_count: number;
  secret_types: Array<{ type: string; count: number }>;
  detection: DetectionDetail;
  findings: FindingRef[];
  tool_invocation: ToolInvocationRef | null;
  origin_agent: AgentRef | null;
  origin_session_id: string | null;
  item_metadata: Record<string, unknown>;
  provenance: ProvenanceEdge[];
  provenance_note: string;
  has_receipt_signature: boolean;
}

export interface SubsequentEvent {
  id: string;
  sequence: number;
  event_type: string;
  summary: string;
  occurred_at: string;
  received_at: string;
  processing_status: string;
  tool_name: string | null;
  decision: string | null;
  enforcement: string | null;
  tool_invocation_id: string | null;
  policy_decision_id: string | null;
  context_item_id: string | null;
  finding_ids: string[];
}

/** The canonical fields the HMAC signature covers (backend/app/engines/provenance/receipts.py). */
export interface ReceiptFields {
  receipt_version: string;
  context_item_id: string | null;
  organization_id: string | null;
  source: { type: string | null; identifier: string | null; trust_level_at_ingest: string };
  agent_id: string | null;
  session_id: string | null;
  event_id: string | null;
  collected_via: string | null;
  collected_at: string | null;
  received_at: string | null;
  content_hash: string | null;
  content_length: number;
  content_type: string | null;
  sensitivity: string | null;
  contains_secrets: boolean;
  secret_fingerprint_count: number;
  detection: { score: number; max_severity: string | null; rule_ids: string[] };
  tool_invocation_id: string | null;
}

export type VerificationStatus = "valid" | "invalid" | "missing";

export interface ContextReceipt {
  receipt: ReceiptFields;
  signature: string | null;
  signature_valid: boolean;
  verification: { status: VerificationStatus; algorithm: string; purpose: string; explanation: string };
  timestamps: { collected_at: string; received_at: string; skew_seconds: number; explanation: string };
  statement: { summary: string; proves: string[]; does_not_prove: string[] };
  related: {
    source: SourceRef;
    agent: AgentRef;
    session: SessionRef;
    tool_invocation: ToolInvocationRef | null;
    findings: FindingRef[];
    subsequent_events: SubsequentEvent[];
    more_subsequent_events: boolean;
    subsequent_events_note: string;
  };
  is_simulation: boolean;
  generated_at: string;
}

export interface FacetCount {
  value: string;
  count: number;
}

export interface ContextFacets {
  total: number;
  by_trust_level: FacetCount[];
  by_sensitivity: FacetCount[];
  by_source_type: FacetCount[];
  with_detections: number;
  with_secrets: number;
  simulated_total: number;
}

export interface ContextSourceSummary {
  id: string;
  source_type: SourceType | string;
  identifier: string;
  display_name: string | null;
  domain: string | null;
  owner: string | null;
  trust_level: TrustLevel | string;
  trust_capabilities: string[];
  manually_classified: boolean;
  first_seen_at: string;
  last_seen_at: string;
  observation_count: number;
  item_count: number;
  agent_count: number;
  session_count: number;
  finding_count: number;
  open_finding_count: number;
  max_finding_severity: Severity | null;
  items_with_detections: number;
}

export interface ContextSourceDetail extends ContextSourceSummary {
  trust_reasons: string[];
  trust_rule: { id: string; name: string; pattern: string; trust_level: string; enabled: boolean } | null;
  source_metadata: Record<string, unknown>;
  recent_items: ContextItemSummary[];
  findings: FindingRef[];
  consumers: Array<{ agent: AgentRef; item_count: number; session_count: number; last_received_at: string }>;
}

/** Query parameters accepted by GET /context/items and GET /context/facets. */
export interface ItemFilters {
  q?: string;
  source_id?: string;
  source_type?: string;
  agent_id?: string;
  session_id?: string;
  trust_level?: string[];
  sensitivity?: string[];
  has_detections?: boolean;
  contains_secrets?: boolean;
  since?: string;
  include_simulated?: boolean;
}

export type SourceSort = "last_seen" | "items" | "findings";

/** Query parameters accepted by GET /context/sources. */
export interface SourceFilters {
  q?: string;
  source_type?: string;
  trust_level?: string;
  has_findings?: boolean;
  include_simulated?: boolean;
  sort?: SourceSort;
}
