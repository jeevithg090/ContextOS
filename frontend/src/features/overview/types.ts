/**
 * Overview (security command centre) types. Mirrors backend/app/schemas/overview.py exactly.
 * Every number is computed by the server from persisted rows; rows produced by the Simulation Lab
 * carry `is_simulation`.
 */
import type { Decision, EnforcementMode, Severity, TrustLevel } from "@/lib/domain";

export type OverviewWindow = "24h" | "7d" | "30d";
export type Bucket = "hour" | "day";

export interface NavCounts {
  pending_approvals: number;
  open_incidents: number;
  open_findings: number;
}

export interface EnforcementCoverage {
  total: number;
  enforced: number;
  advisory: number;
  observed: number;
  /** enforced / total; null when the window had no decisions. */
  share: number | null;
}

export interface Posture {
  agents_total: number;
  agents_active: number;
  sessions_active: number;
  trifecta_sessions: number;
  sources_by_trust: Record<TrustLevel, number>;
  open_findings_by_severity: Record<Severity, number>;
  open_findings_total: number;
  pending_approvals: number;
  open_incidents: number;
  decisions_by_outcome: Record<Decision, number>;
  decisions_total: number;
  enforcement_coverage: EnforcementCoverage;
  blocked_actions: number;
}

export interface EventPoint {
  t: string;
  live: number;
  simulated: number;
}

export type SeverityPoint = { t: string } & Record<Severity, number>;
export type DecisionPoint = { t: string } & Record<Decision, number>;

export interface Series {
  bucket: Bucket;
  events: EventPoint[];
  findings_by_severity: SeverityPoint[];
  decisions_by_outcome: DecisionPoint[];
}

export interface AgentRef {
  id: string;
  name: string | null;
}

export interface RiskyAgent {
  id: string;
  name: string;
  environment: string;
  framework: string;
  status: string;
  risk_score: number;
  risk_level: string;
  reason: string | null;
  reason_detail: string | null;
  session_id: string | null;
  trifecta: boolean;
  open_findings: number;
  last_seen_at: string | null;
  is_simulation: boolean;
}

export interface FindingItem {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  status: string;
  rule_id: string;
  agent: AgentRef | null;
  session_id: string | null;
  incident_id: string | null;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  is_simulation: boolean;
}

export interface ApprovalItem {
  id: string;
  summary: string;
  agent: AgentRef;
  session_id: string;
  tool_name: string | null;
  requested_at: string;
  expires_at: string | null;
  seconds_remaining: number | null;
  is_simulation: boolean;
}

export interface IncidentItem {
  id: string;
  number: number;
  title: string;
  severity: Severity;
  status: string;
  opened_at: string;
  primary_agent: AgentRef | null;
  is_simulation: boolean;
}

export interface Attention {
  pending_approvals: ApprovalItem[];
  critical_findings: FindingItem[];
  open_incidents: IncidentItem[];
}

export interface BlockedAction {
  invocation_id: string;
  session_id: string;
  agent: AgentRef;
  tool: { name: string | null; category: string | null; server: string | null };
  action: string;
  decision: Decision;
  enforcement: EnforcementMode;
  status: string;
  /** What actually happened, worded by the server for the enforcement mode. */
  outcome: string;
  reason: string | null;
  policy_decision_id: string | null;
  approval_id: string | null;
  at: string;
  is_simulation: boolean;
}

export type IntegrationStatus = "connected" | "stale" | "never_seen" | "error";

export interface IntegrationHealth {
  id: string;
  kind: string;
  name: string;
  status: IntegrationStatus;
  status_reason: string;
  last_event_at: string | null;
  event_count: number;
  decision_count: number;
  enforcement_capable: boolean;
  enforcement_note: string;
  last_error: string | null;
}

export interface ActivityEntry {
  id: string;
  seq: number;
  occurred_at: string;
  actor_type: "user" | "api_key" | "system" | string;
  actor_id: string | null;
  actor_label: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: Record<string, unknown>;
}

export interface Onboarding {
  has_agents: boolean;
  has_api_key: boolean;
  has_events: boolean;
  has_simulations: boolean;
}

export interface SimulatedShare {
  events: number;
  findings: number;
  decisions: number;
}

export interface Overview {
  window: OverviewWindow;
  bucket: Bucket;
  since: string;
  until: string;
  generated_at: string;
  include_simulated: boolean;
  posture: Posture;
  series: Series;
  top_risky_agents: RiskyAgent[];
  recent_findings: FindingItem[];
  attention: Attention;
  recent_blocked_or_paused: BlockedAction[];
  integrations: IntegrationHealth[];
  recent_activity: ActivityEntry[];
  onboarding: Onboarding;
  simulated: SimulatedShare;
}
