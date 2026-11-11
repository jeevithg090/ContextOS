/**
 * Replay Lab types. Mirror backend/app/schemas/replay.py (GET /replay/sessions/{id},
 * POST /replay/counterfactual) and the session/policy list shapes the picker and editor read.
 */
import type { Decision, EnforcementMode } from "@/lib/domain";

/* ----------------------------------------------------------------------------- session picker */

export interface ReplayAgentRef {
  id: string;
  name: string;
  framework: string;
  environment: string;
  status: string;
  is_simulation: boolean;
}

/** Row of GET /sessions (SessionSummaryOut), as much of it as the picker uses. */
export interface ReplaySessionSummary {
  id: string;
  agent: ReplayAgentRef;
  external_session_id: string;
  status: string;
  started_at: string;
  last_event_at: string | null;
  event_count: number;
  risk_score: number;
  risk_level: string;
  trifecta: boolean;
  open_findings: number;
  is_simulation: boolean;
}

export type SessionSort = "recent" | "risk";

export interface SessionPickerFilters {
  q: string;
  sort: SessionSort;
  include_simulated: boolean;
}

/* ----------------------------------------------------------------------------- replay */

export interface ReplaySessionMeta {
  id: string;
  external_session_id: string;
  agent: ReplayAgentRef;
  parent_session_id: string | null;
  status: string;
  started_at: string;
  ended_at: string | null;
  last_event_at: string | null;
  event_count: number;
  /** The live score — not a replayed value. */
  risk_score: number;
  risk_level: string;
  trifecta: boolean;
  is_simulation: boolean;
}

export interface StepRefs {
  context_item_id: string | null;
  tool_invocation_id: string | null;
  policy_decision_id: string | null;
  finding_ids: string[];
  approval_id: string | null;
  child_session_id: string | null;
  source_id: string | null;
  destination_id: string | null;
}

export interface StepOutcome {
  policy_decision_id: string;
  decision: Decision;
  enforcement: EnforcementMode;
  explanation: string;
  matched_policies: string[];
  approval_id: string | null;
  approval_status: string | null;
}

export interface StepFinding {
  id: string;
  title: string;
  severity: string;
  category: string;
  /** Current triage status (may have changed since the step). */
  status: string;
}

export interface StepRisk {
  score: number;
  level: string;
  delta: number;
  trifecta: boolean;
  sensitive_access: boolean;
  untrusted_exposure: boolean;
  outbound_channel: boolean;
  summary: string;
  factors: Array<{ key: string; label: string; weight: number }>;
  /** Always "recomputed from recorded events". */
  basis: string;
}

export interface ReplayStep {
  index: number;
  sequence: number;
  event_id: string;
  event_type: string;
  received_at: string;
  occurred_at: string;
  title: string;
  summary: string | null;
  processing_status: string;
  from_other_session: boolean;
  trust_level: string | null;
  tool: { name: string; category: string; status: string | null } | null;
  refs: StepRefs;
  outcome: StepOutcome | null;
  findings: StepFinding[];
  risk_after: StepRisk;
  recorded_risk: { score: number; level: string; trifecta: boolean } | null;
}

export interface Replay {
  session: ReplaySessionMeta;
  basis: string;
  risk_basis: string;
  risk_note: string;
  total_steps: number;
  decision_steps: number;
  offset: number;
  limit: number;
  truncated: boolean;
  focus_index: number | null;
  steps: ReplayStep[];
}

/* ----------------------------------------------------------------------------- counterfactual */

export type PolicyMode = "enforce" | "monitor";

/** Row of GET /policies, as much of it as the policy-set editor uses. */
export interface ReplayPolicy {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  mode: PolicyMode;
  priority: number;
  outcome: Decision;
  severity: string;
  version: number;
  is_builtin: boolean;
  restrictions: Record<string, unknown>;
  explanation: string;
}

export interface PolicyOverride {
  outcome?: Decision;
  mode?: PolicyMode;
  enabled?: boolean;
}

/** A validated, unsaved policy (PolicyDraft on the server). */
export interface DraftPolicy {
  id?: string;
  name: string;
  description?: string | null;
  outcome: Decision;
  mode?: PolicyMode;
  enabled?: boolean;
  priority?: number;
  severity?: string;
  conditions: Record<string, unknown>;
  restrictions?: Record<string, unknown>;
  tags?: string[];
}

export type PolicyBase = "current" | "none";
export type DefaultDecision = "ALLOW" | "AUDIT" | "REQUIRE_APPROVAL" | "DENY";

export interface PolicySetRequest {
  base: PolicyBase;
  disable_policy_ids: string[];
  overrides: Record<string, PolicyOverride>;
  add_policies: DraftPolicy[];
}

export interface CounterfactualRequest {
  session_id: string;
  policy_set: PolicySetRequest;
  default_decision?: DefaultDecision;
}

export interface EvaluatedPolicy {
  id: string;
  name: string;
  version: number;
  outcome: Decision;
  mode: PolicyMode;
  enabled: boolean;
  priority: number;
  source: "saved" | "draft";
  changes: string[];
}

export interface HypotheticalMatch {
  policy_id: string;
  name: string;
  version: number;
  outcome: Decision;
  mode: PolicyMode;
  severity: string;
  explanation: string;
  draft: boolean;
}

export type PolicyChangeKind = "removed" | "disabled" | "monitor" | "no_longer_matches" | "outcome_changed" | "newly_matches";

export interface PolicyChange {
  policy_id: string;
  name: string;
  change: PolicyChangeKind;
  detail: string;
}

export interface EvidenceField {
  field: string;
  present: boolean;
  value: unknown;
  policies: string[];
}

export interface CounterfactualStep {
  decision_id: string;
  invocation_id: string | null;
  event_id: string | null;
  sequence: number | null;
  step_index: number | null;
  evaluated_at: string;
  tool: { name: string | null; category: string | null };
  is_simulation: boolean;
  original_decision: Decision;
  original_enforcement: EnforcementMode;
  original_matches: string[];
  original_explanation: string;
  hypothetical_decision: Decision;
  changed: boolean;
  hypothetical_matches: HypotheticalMatch[];
  hypothetical_monitor_matches: HypotheticalMatch[];
  hypothetical_restrictions: Record<string, unknown>;
  evaluation_errors: Array<{ policy_id: string; name: string; error: string }>;
  current_decision: Decision;
  drifted: boolean;
  policy_changes: PolicyChange[];
  explanation: string;
  evidence: EvidenceField[];
  after_hypothetical_block: boolean;
}

export interface CounterfactualSummary {
  evaluated: number;
  changed: number;
  would_deny: number;
  would_pause: number;
  would_allow: number;
  would_restrict: number;
  drifted: number;
  transitions: Record<string, number>;
}

export interface NotEvaluable {
  event_id: string | null;
  sequence: number | null;
  event_type: string;
  reason: string;
  policy_decision_id: string | null;
}

export interface CounterfactualResult {
  simulation: true;
  label: string;
  basis: string;
  session_id: string;
  policy_set: { base: PolicyBase; default_decision: Decision; policies: EvaluatedPolicy[]; warnings: string[] };
  steps: CounterfactualStep[];
  summary: CounterfactualSummary;
  caveats: string[];
  not_evaluable_count: number;
  not_evaluable: NotEvaluable[];
  truncated: boolean;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  explanation: string | null;
}
