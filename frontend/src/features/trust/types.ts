/**
 * Trust Centre API types. Mirrors backend/app/schemas/trust.py exactly.
 */
import type { TrustLevel } from "@/lib/domain";

export type AppliesTo = "source" | "destination" | "both";
export type Scope = "source" | "destination";
export type MatchField = "identifier" | "domain";
export type Capability = "read" | "instruct" | "execute" | "credential_access" | "send";
export type DestinationKind = "domain" | "ip" | "email" | "service" | "agent" | "unknown";
export type CheckResult = "pass" | "warn" | "fail" | "unknown";

export const SOURCE_TYPES = [
  "web",
  "repository",
  "file",
  "document",
  "email",
  "api",
  "mcp_server",
  "mcp_tool",
  "browser",
  "database",
  "user_upload",
  "user_prompt",
  "tool_output",
  "agent_output",
  "system",
  "other",
] as const;
export type SourceType = (typeof SOURCE_TYPES)[number];

export interface ReassessSummary {
  sources_checked: number;
  sources_changed: number;
  destinations_checked: number;
  destinations_changed: number;
  truncated: boolean;
  limit: number;
}

export interface RuleRef {
  id: string | null;
  name: string;
  pattern: string;
  match_field: MatchField;
  applies_to: AppliesTo;
  source_type: string | null;
  trust_level: TrustLevel;
  priority: number;
  is_draft: boolean;
}

export interface Check {
  check: string;
  result: CheckResult | string;
  detail: string;
}

export interface Assessment {
  scope: Scope;
  level: TrustLevel;
  capabilities: Capability[];
  reasons: string[];
  canonical_identifier: string;
  domain: string | null;
  kind: string | null;
  matched_rule: RuleRef | null;
  matching_rules: RuleRef[];
  checks: Check[];
  not_verified: string[];
}

export interface ExistingRecord {
  type: Scope;
  id: string;
  current_level: TrustLevel;
  manually_classified: boolean;
  finding_count: number;
  observation_count: number;
  transfer_count: number;
  with_history: Assessment;
}

/* ----------------------------------------------------------------------------- rules */

export interface TrustRule {
  id: string;
  name: string;
  description: string | null;
  applies_to: AppliesTo;
  source_type: string | null;
  match_field: MatchField;
  pattern: string;
  trust_level: TrustLevel;
  capabilities: Capability[];
  priority: number;
  enabled: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  is_default: boolean;
  is_override: boolean;
  classified_sources: number;
  classified_destinations: number;
  reassessment: ReassessSummary | null;
}

export interface TrustRuleInput {
  name: string;
  description?: string | null;
  applies_to: AppliesTo;
  source_type?: SourceType | null;
  match_field: MatchField;
  pattern: string;
  trust_level: TrustLevel;
  capabilities?: Capability[] | null;
  priority?: number;
  enabled?: boolean;
}

export type TrustRulePatch = Partial<TrustRuleInput>;

export interface RuleDeleteResult {
  id: string;
  reassessment: ReassessSummary;
}

export interface RuleTestRequest {
  applies_to: Scope;
  source_type?: SourceType;
  kind?: DestinationKind;
  identifier: string;
  draft?: TrustRuleInput | null;
  replace_rule_id?: string | null;
}

export interface RuleTestResult {
  assessment: Assessment;
  draft_errors: string[];
  draft_matches: boolean | null;
  draft_decides: boolean | null;
  existing: ExistingRecord | null;
  dry_run: boolean;
}

/* ----------------------------------------------------------------------------- sources */

export interface TrustSource {
  id: string;
  source_type: string;
  identifier: string;
  display_name: string | null;
  domain: string | null;
  trust_level: TrustLevel;
  trust_capabilities: Capability[];
  trust_rule_id: string | null;
  trust_rule_name: string | null;
  manually_classified: boolean;
  observation_count: number;
  finding_count: number;
  max_finding_severity: string | null;
  first_seen_at: string;
  last_seen_at: string;
}

export interface HistoryEntry {
  id: string;
  at: string;
  action: string;
  summary: string;
  from_level: TrustLevel | null;
  to_level: TrustLevel | null;
  actor_type: string;
  actor_id: string | null;
  actor_label: string;
  note: string | null;
}

export interface FindingRef {
  id: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  session_id: string | null;
  occurrence_count: number;
  last_seen_at: string;
  is_simulation: boolean;
}

export interface SourceItem {
  id: string;
  session_id: string;
  agent_id: string;
  agent_name: string | null;
  collected_via: string;
  received_at: string;
  trust_level: TrustLevel;
  max_severity: string | null;
  is_simulation: boolean;
}

export interface EvidenceDowngrade {
  level_without_evidence: TrustLevel;
  level: TrustLevel;
  finding_count: number;
  max_severity: string | null;
  explanation: string;
}

export interface ManualClassification {
  at: string;
  actor_label: string;
  level: TrustLevel | null;
  capabilities: Capability[];
  note: string | null;
}

export interface TrustSourceDetail extends TrustSource {
  trust_reasons: string[];
  matched_rule: RuleRef | null;
  evidence_downgrade: EvidenceDowngrade | null;
  manual_classification: ManualClassification | null;
  history: HistoryEntry[];
  findings: FindingRef[];
  findings_total: number;
  recent_items: SourceItem[];
}

export interface SourceClassifyInput {
  trust_level: TrustLevel;
  capabilities?: Capability[] | null;
  note: string;
}

export type SourceSort =
  | "last_seen"
  | "-last_seen"
  | "first_seen"
  | "-first_seen"
  | "observations"
  | "-observations"
  | "findings"
  | "-findings"
  | "trust"
  | "-trust"
  | "identifier"
  | "-identifier";

export interface SourceFilters {
  trust_level?: TrustLevel[];
  source_type?: string;
  q?: string;
  manual?: boolean;
  has_findings?: boolean;
  capability?: Capability;
  sort?: SourceSort;
  limit: number;
  offset: number;
}

/* ----------------------------------------------------------------------------- destinations */

export interface VerificationSummary {
  passed: number;
  warned: number;
  failed: number;
  unknown: number;
}

export interface TrustDestination {
  id: string;
  kind: string;
  identifier: string;
  display_name: string | null;
  classification: TrustLevel;
  trust_rule_id: string | null;
  trust_rule_name: string | null;
  override_rule_id: string | null;
  transfer_count: number;
  blocked_count: number;
  sensitive_transfer_count: number;
  first_seen_at: string;
  last_seen_at: string;
  verification: VerificationSummary;
}

export interface DestinationInvocation {
  id: string;
  session_id: string;
  agent_id: string;
  agent_name: string | null;
  tool_name: string | null;
  status: string;
  decision: string | null;
  enforcement: string;
  policy_decision_id: string | null;
  decision_explanation: string | null;
  requested_at: string;
  sensitive_data_detected: boolean;
  is_simulation: boolean;
}

export interface TrustDestinationDetail extends TrustDestination {
  checks: Check[];
  assessment: Assessment;
  stale: boolean;
  invocations: DestinationInvocation[];
  invocations_total: number;
  decision_counts: Record<string, number>;
  enforcement_counts: Record<string, number>;
  findings: FindingRef[];
}

export interface DestinationClassifyInput {
  classification: TrustLevel;
  note: string;
}

export interface DestinationVerifyResult {
  assessment: Assessment;
  existing: ExistingRecord | null;
  dry_run: boolean;
}

export type DestinationSort =
  | "last_seen"
  | "-last_seen"
  | "first_seen"
  | "-first_seen"
  | "transfers"
  | "-transfers"
  | "blocked"
  | "-blocked"
  | "sensitive"
  | "-sensitive"
  | "identifier"
  | "-identifier";

export interface DestinationFilters {
  classification?: TrustLevel[];
  kind?: string;
  q?: string;
  has_blocked?: boolean;
  sort?: DestinationSort;
  limit: number;
  offset: number;
}

/* ----------------------------------------------------------------------------- summary */

export interface LevelDistribution {
  total: number;
  by_level: Record<TrustLevel, number>;
}

export interface TrustSummary {
  sources: LevelDistribution & { manual: number; with_findings: number; can_instruct: number };
  destinations: LevelDistribution & { with_blocked_calls: number; with_sensitive_transfers: number };
  rules: { total: number; enabled: number; source: number; destination: number };
  sources_with_findings: TrustSource[];
  recently_downgraded: Array<{
    target_type: Scope;
    target_id: string;
    label: string;
    from_level: TrustLevel;
    to_level: TrustLevel;
    at: string;
    actor_label: string;
    summary: string;
  }>;
  downgrade_window_days: number;
}
