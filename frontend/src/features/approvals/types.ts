/**
 * Approval Centre types. Mirrors backend/app/schemas/approvals.py exactly; every field is built by
 * the server from persisted rows (arguments are redacted at ingestion, notes before storage).
 */
import type { ApprovalStatus, Decision, EnforcementMode, Severity, TrustLevel } from "@/lib/domain";

export interface UserRef {
  id: string;
  name: string | null;
  email: string | null;
}

export interface AgentRef {
  id: string;
  name: string | null;
  environment: string | null;
}

export interface SessionRef {
  id: string;
  external_session_id: string | null;
  status: string | null;
}

export interface ToolRef {
  name: string | null;
  category: string | null;
  provider: string | null;
  server: string | null;
  risk_level: string | null;
}

export interface ApprovalResource {
  kind: string;
  id: string;
  sensitive: boolean;
  reason: string | null;
}

export interface DestinationRef {
  id: string;
  kind: string;
  identifier: string;
  /** Current classification. */
  classification: TrustLevel | string;
  /** What the policy engine saw when it paused the call. */
  classification_at_decision: TrustLevel | string | null;
}

export interface ApprovalTarget {
  primary: string | null;
  destination: DestinationRef | null;
  resources: ApprovalResource[];
  resource_count: number;
  sensitive_resource_count: number;
}

export interface MatchedPolicy {
  policy_id: string;
  name: string;
  version: number | null;
  outcome: Decision | string | null;
  mode: string | null;
  severity: Severity | string | null;
  /** Which conditions matched, with the observed values. */
  explanation: string;
  /** Current policy description (detail only). */
  description: string | null;
  /** False when the policy was deleted after this decision. */
  exists: boolean;
}

export interface PolicyDecisionRef {
  id: string;
  decision: Decision | string;
  enforcement: EnforcementMode | string;
  explanation: string;
  evaluated_at: string | null;
  deciding_policy: MatchedPolicy | null;
  matched_policies: MatchedPolicy[];
}

/** Risk recorded when the approval was opened. */
export interface RiskSummary {
  session_score: number;
  session_level: string | null;
  trifecta: boolean;
  session_summary: string | null;
  tool_category: string | null;
  tool_risk: string | null;
  destination_classification: TrustLevel | string | null;
  sensitive_resources: string[];
  secrets_in_arguments: number;
  session_secret_matches: number;
  detections: string[];
}

export interface Approval {
  id: string;
  status: ApprovalStatus;
  summary: string;
  /** Plain language, e.g. "send POST to hooks.webhook.site". */
  action: string;
  agent: AgentRef;
  session: SessionRef;
  tool: ToolRef;
  tool_invocation_id: string | null;
  tool_invocation_status: string | null;
  target: ApprovalTarget;
  policy_decision: PolicyDecisionRef | null;
  risk: RiskSummary;
  requires_confirmation: boolean;
  confirmation_reasons: string[];
  requested_at: string;
  expires_at: string | null;
  /** Pending only; computed by the server when the response was built. */
  seconds_remaining: number | null;
  decided_at: string | null;
  decided_by: UserRef | null;
  decision_note: string | null;
  is_simulation: boolean;
}

export interface DestinationCheck {
  check: string;
  result: "pass" | "fail" | "warn" | "unknown" | string;
  detail: string | null;
}

export interface DestinationDetail extends DestinationRef {
  display_name: string | null;
  checks: DestinationCheck[];
  transfer_count: number;
  blocked_count: number;
  sensitive_transfer_count: number;
  first_seen_at: string | null;
}

export interface SecretRef {
  type: string;
  context_item_id: string | null;
}

export interface EvidenceRef {
  type: string;
  id: string | null;
  detail: string | null;
}

export type TrifectaLegKey = "sensitive_access" | "untrusted_exposure" | "outbound_channel";

export interface TrifectaLeg {
  key: TrifectaLegKey;
  label: string;
  active_at_decision: boolean;
  evidence: EvidenceRef[];
}

export interface SessionRisk {
  score_at_decision: number;
  level_at_decision: string | null;
  trifecta_at_decision: boolean;
  legs: TrifectaLeg[];
  current_score: number;
  current_level: string | null;
  summary: string | null;
  evidence_computed_at: string | null;
  /** Context summary the policy engine saw (lowest trust, untrusted item count, injection...). */
  context_at_decision: Record<string, unknown>;
}

export interface ContextItemRef {
  id: string;
  source_id: string;
  source_identifier: string | null;
  source_display_name: string | null;
  source_type: string | null;
  /** Current source trust. */
  source_trust_level: TrustLevel | string | null;
  /** Trust at ingest time. */
  trust_level: TrustLevel | string;
  collected_via: string;
  received_at: string;
  sensitivity: string;
  contains_secrets: boolean;
  detection_max_severity: Severity | string | null;
  detection_hit_count: number;
  /** Redacted, truncated. */
  preview: string | null;
  tool_invocation_id: string | null;
}

export interface FindingRef {
  id: string;
  title: string;
  category: string;
  severity: Severity | string;
  status: string;
  last_seen_at: string;
  linked_to_this_call: boolean;
}

export interface ApprovalActivity {
  id: string;
  seq: number;
  occurred_at: string;
  action: string;
  actor_type: string;
  actor_id: string | null;
  actor_name: string | null;
  details: Record<string, unknown>;
}

export interface ApprovalDetail extends Approval {
  arguments: Record<string, unknown>;
  argument_hash: string | null;
  resources: ApprovalResource[];
  destination: DestinationDetail | null;
  secrets: { in_arguments: SecretRef[]; from_session_context: SecretRef[] };
  detection: { rule_ids: string[]; max_severity: string | null; categories: string[] };
  monitor_matches: MatchedPolicy[];
  session_risk: SessionRisk;
  recent_context: ContextItemRef[];
  context_total: number;
  related_findings: FindingRef[];
  /** What approving / rejecting actually does for the integration that asked. */
  enforcement_note: string;
  activity: ApprovalActivity[];
}

export type ApprovalView = "queue" | "history";

export interface ApprovalListParams {
  view: ApprovalView;
  includeSimulated: boolean;
  limit: number;
  offset: number;
}

export interface DecideInput {
  approve: boolean;
  note?: string | null;
}
