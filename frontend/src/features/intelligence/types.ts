/**
 * Security Intelligence types. Mirrors backend/app/schemas/findings.py exactly — every value is
 * computed by the server from persisted rows. Evidence excerpts were redacted before storage.
 */
import type { FindingStatus, Severity } from "@/lib/domain";

export interface AgentRef {
  id: string;
  name: string;
}

export interface SessionRef {
  id: string;
  external_session_id: string;
}

export interface SourceRef {
  id: string;
  source_type: string;
  identifier: string;
  display_name: string | null;
  trust_level: string;
}

export interface IncidentRef {
  id: string;
  number: number;
  title: string;
  status: string;
  severity: string;
}

export interface FindingSummary {
  id: string;
  title: string;
  category: string;
  rule_id: string;
  severity: Severity | string;
  /** 0..1 — how sure the detector is that this is a real problem. */
  confidence: number;
  status: FindingStatus | string;
  agent: AgentRef | null;
  session: SessionRef | null;
  source: SourceRef | null;
  incident: IncidentRef | null;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  is_simulation: boolean;
}

/* ----------------------------------------------------------------------------- stats */

export type StatsWindow = "24h" | "7d" | "30d" | "90d";

export type SeverityCounts = Record<Severity, number>;

export interface CategoryCount {
  category: string;
  count: number;
}

export interface TrendPoint extends SeverityCounts {
  /** Start of the bucket (UTC). */
  t: string;
  total: number;
}

export interface TopSource extends SourceRef {
  /** Findings first seen in the window for this source, excluding false positives. */
  count: number;
  max_severity: string | null;
}

export interface AgentFacet {
  id: string;
  name: string;
  count: number;
}

export interface Mttr {
  mean_seconds: number | null;
  median_seconds: number | null;
  resolved_count: number;
}

export interface OpenBacklog {
  total: number;
  needs_triage: number;
  acknowledged: number;
  by_severity: SeverityCounts;
  by_category: CategoryCount[];
  oldest_first_seen_at: string | null;
}

export interface PeriodStats {
  total: number;
  by_severity: SeverityCounts;
  by_category: CategoryCount[];
  by_status: Record<string, number>;
  trend: TrendPoint[];
  top_sources: TopSource[];
  mttr: Mttr;
}

export interface FindingStats {
  window: StatsWindow;
  bucket: "hour" | "day";
  since: string;
  until: string;
  include_simulated: boolean;
  /** Open simulated findings left out because simulations are hidden. */
  simulated_open: number;
  open: OpenBacklog;
  period: PeriodStats;
  agents: AgentFacet[];
  categories: CategoryCount[];
}

/* ----------------------------------------------------------------------------- detail */

export interface ResolvedEvidence {
  type: string;
  id: string | null;
  label: string | null;
  session_id: string | null;
  excerpt: string | null;
  detail: string | null;
  /** False when the referenced record no longer exists in this organisation. */
  found: boolean;
}

export interface RelatedAgent {
  id: string;
  name: string;
  framework: string;
  environment: string;
  status: string;
}

export interface RelatedSession {
  id: string;
  external_session_id: string;
  status: string;
  started_at: string;
  risk_score: number;
  risk_level: string;
  trifecta: boolean;
}

export interface RelatedSource extends SourceRef {
  finding_count: number;
  max_finding_severity: string | null;
  manually_classified: boolean;
}

export interface RelatedContextItem {
  id: string;
  collected_via: string;
  received_at: string;
  trust_level: string;
  sensitivity: string;
  contains_secrets: boolean;
  content_length: number;
  retrieved_by: { id: string; tool_name: string } | null;
}

export interface RelatedInvocation {
  id: string;
  session_id: string;
  tool_name: string;
  tool_category: string;
  status: string;
  decision: string | null;
  enforcement: string;
  requested_at: string;
}

export interface MatchedPolicy {
  policy_id: string | null;
  name: string;
  outcome: string | null;
  mode: string | null;
}

export interface RelatedDecision {
  id: string;
  session_id: string;
  decision: string;
  enforcement: string;
  explanation: string;
  evaluated_at: string;
  matched_policies: MatchedPolicy[];
}

export interface RelatedDestination {
  id: string;
  kind: string;
  identifier: string;
  classification: string;
}

export interface RelatedTask {
  id: string;
  key: string;
  title: string;
  priority: string;
  column: string | null;
  done: boolean;
  archived: boolean;
}

export interface FindingRelated {
  agent: RelatedAgent | null;
  session: RelatedSession | null;
  source: RelatedSource | null;
  context_item: RelatedContextItem | null;
  tool_invocation: RelatedInvocation | null;
  decision: RelatedDecision | null;
  destination: RelatedDestination | null;
  incident: IncidentRef | null;
  tasks: RelatedTask[];
}

export interface IncidentCandidate extends IncidentRef {
  reason: string;
}

export interface HistoryEntry {
  action: string;
  from_status: string | null;
  to_status: string | null;
  actor: string;
  note: string | null;
  occurred_at: string;
}

export interface FindingDetail extends FindingSummary {
  explanation: string;
  remediation: string | null;
  resolution_note: string | null;
  resolved_by: { id: string; name: string } | null;
  evidence: ResolvedEvidence[];
  related: FindingRelated;
  history: HistoryEntry[];
  allowed_transitions: string[];
  incident_candidates: IncidentCandidate[];
  provenance_note: string;
}

/* ----------------------------------------------------------------------------- requests */

export interface FindingFilters {
  status?: string[];
  severity?: string[];
  category?: string[];
  agent_id?: string;
  session_id?: string;
  source_id?: string;
  incident_id?: string;
  include_simulated?: boolean;
  q?: string;
  sort?: "severity" | "recent" | "first_seen" | "occurrences";
}

export interface FindingUpdate {
  status?: string;
  resolution_note?: string;
}

export interface LinkIncidentInput {
  incident_id?: string;
  title?: string;
}

export interface LinkIncidentResult {
  created: boolean;
  incident: IncidentRef;
  finding: FindingSummary;
}

/** Subset of the workspace's FromFindingResult that this feature relies on. */
export interface RemediationTaskResult {
  /** False when an open task for this finding already existed (it is returned instead). */
  created: boolean;
  task: { id: string; key: string; title: string };
}
