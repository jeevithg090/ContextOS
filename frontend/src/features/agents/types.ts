/**
 * Agents & sessions API types. Mirrors backend/app/schemas/agents.py and backend/app/schemas/sessions.py.
 * Every classification (tool category, risk, trust, decision) is computed by the server.
 */
import type { Page } from "@/lib/api";

export type Environment = "development" | "staging" | "production";
export type AgentStatus = "active" | "inactive" | "quarantined";
export type AgentSort = "last_seen" | "risk" | "name" | "created";
export type SessionSort = "recent" | "risk";

export const ENVIRONMENTS: Environment[] = ["development", "staging", "production"];
export const AGENT_STATUSES: AgentStatus[] = ["active", "inactive", "quarantined"];
export const QUARANTINE_LABEL = "quarantined";

export const TOOL_CATEGORIES = [
  "file_read",
  "file_write",
  "shell",
  "http",
  "browser",
  "email",
  "messaging",
  "database",
  "code_execution",
  "infrastructure",
  "agent_delegation",
  "search",
  "mcp",
  "other",
] as const;
export type ToolCategory = (typeof TOOL_CATEGORIES)[number];

/* ----------------------------------------------------------------------------- agents */

export interface AgentSummary {
  id: string;
  name: string;
  description: string | null;
  framework: string;
  version: string | null;
  owner: string | null;
  environment: string;
  labels: string[];
  status: string;
  is_simulation: boolean;
  created_at: string;
  last_seen_at: string | null;
  /** Highest risk score among the agent's active sessions (0-100, higher is riskier). */
  risk_score: number;
  risk_level: string;
  session_count: number;
  active_session_count: number;
  /** Open or acknowledged findings. */
  open_findings: number;
  max_open_severity: string | null;
  declared_tool_count: number;
  observed_tool_count: number;
  integration_kind: string | null;
}

export interface FacetCount {
  value: string;
  count: number;
}

export interface AgentPage extends Page<AgentSummary> {
  facets: { frameworks: FacetCount[]; environments: FacetCount[]; statuses: FacetCount[]; simulated: number };
}

export interface AgentFilters {
  q?: string;
  environment?: string;
  framework?: string;
  status?: string;
  include_simulated?: boolean;
  sort?: AgentSort;
  limit: number;
  offset: number;
}

export interface DeclaredTool {
  name: string;
  category: string;
  risk_level: string;
  category_hint: string | null;
}

export interface IntegrationRef {
  id: string;
  kind: string;
  name: string;
  status: string;
  last_event_at: string | null;
  supports_enforcement: boolean;
  enforcement_basis: string;
}

export interface QuarantinePolicy {
  id: string;
  name: string;
  outcome: string;
  scope: "all_calls" | "some_calls";
}

export interface SuggestedPolicy {
  name: string;
  description: string;
  outcome: string;
  mode: string;
  enabled: boolean;
  priority: number;
  severity: string;
  conditions: Record<string, unknown>;
  tags: string[];
}

export interface QuarantineState {
  active: boolean;
  label: string;
  /** An enabled enforce-mode policy denies or gates every call of a quarantined agent. */
  enforced: boolean;
  policies: QuarantinePolicy[];
  explanation: string;
  suggested_policy: SuggestedPolicy;
}

export interface FindingBrief {
  id: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  session_id: string | null;
  last_seen_at: string;
  occurrence_count: number;
  is_simulation: boolean;
}

export interface RelatedAgent {
  id: string;
  name: string;
  framework: string;
  environment: string;
  status: string;
  risk_score: number;
  risk_level: string;
}

export interface AgentRelationship {
  id: string;
  /** outgoing: this agent delegated to / messaged the other agent. */
  direction: "outgoing" | "incoming";
  relationship_type: string;
  other_agent: RelatedAgent;
  event_count: number;
  crosses_trust_boundary: boolean;
  first_seen_at: string;
  last_seen_at: string;
  last_parent_session_id: string | null;
  last_child_session_id: string | null;
}

export interface AgentDetail extends AgentSummary {
  declared_capabilities: { tools: DeclaredTool[]; permissions: string[]; mcp_servers: string[] };
  integration: IntegrationRef | null;
  findings_by_severity: Record<string, number>;
  recent_findings: FindingBrief[];
  relationships: AgentRelationship[];
  decisions_by_enforcement: Record<string, number>;
  quarantine: QuarantineState;
}

export interface DeclaredToolInput {
  name: string;
  category?: ToolCategory | null;
}

export interface DeclaredCapabilitiesInput {
  tools: DeclaredToolInput[];
  permissions: string[];
  mcp_servers: string[];
}

export interface AgentCreateInput {
  name: string;
  description?: string | null;
  framework?: string;
  version?: string | null;
  owner?: string | null;
  environment?: Environment;
  labels?: string[];
  declared_capabilities?: DeclaredCapabilitiesInput;
}

export interface AgentPatchInput {
  description?: string | null;
  owner?: string | null;
  environment?: Environment;
  labels?: string[];
  status?: AgentStatus;
  declared_capabilities?: DeclaredCapabilitiesInput;
}

export interface AgentTool {
  tool_id: string | null;
  name: string;
  provider: string | null;
  server: string | null;
  category: string;
  risk_level: string;
  classification_reason: string | null;
  declared: boolean;
  observed: boolean;
  invocation_count: number;
  first_used_at: string | null;
  last_used_at: string | null;
  decisions: Record<string, number>;
  statuses: Record<string, number>;
  enforcement: Record<string, number>;
  /** Calls whose arguments contained a credential (stored redacted). */
  credential_calls: number;
}

export interface PostureEvidence {
  type: string;
  id: string;
  detail: string;
}

export interface PostureDimension {
  key: string;
  label: string;
  score: number;
  max_score: number;
  explanation: string;
  evidence: PostureEvidence[];
  recommendation: string | null;
}

export interface AgentPosture {
  agent_id: string;
  score: number;
  grade: string;
  summary: string;
  dimensions: PostureDimension[];
  basis: {
    declared_tool_count: number;
    observed_tool_count: number;
    enabled_policy_count: number;
    approval_policy_count: number;
    trust_rule_count: number;
    untrusted_source_count: number;
    open_finding_count: number;
    sessions_with_trifecta: number;
    total_sessions: number;
    integration_kind: string | null;
    supports_enforcement: boolean;
    decisions_by_enforcement: Record<string, number>;
  };
  computed_at: string;
}

export interface GraphNode {
  id: string;
  name: string;
  owner: string | null;
  framework: string;
  environment: string;
  status: string;
  risk_score: number;
  risk_level: string;
  is_simulation: boolean;
  session_count: number;
  open_findings: number;
}

export interface GraphEdge {
  id: string;
  /** Parent / sending agent. */
  source: string;
  /** Child / receiving agent. */
  target: string;
  relationship_type: string;
  event_count: number;
  crosses_trust_boundary: boolean;
  first_seen_at: string;
  last_seen_at: string;
  last_parent_session_id: string | null;
  last_child_session_id: string | null;
}

export interface AgentGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  note: string;
}

/* ----------------------------------------------------------------------------- sessions */

export interface AgentRef {
  id: string;
  name: string;
  framework: string;
  environment: string;
  status: string;
  is_simulation: boolean;
}

export interface SessionSummary {
  id: string;
  agent: AgentRef;
  external_session_id: string;
  parent_session_id: string | null;
  status: string;
  started_at: string;
  ended_at: string | null;
  last_event_at: string | null;
  event_count: number;
  risk_score: number;
  risk_level: string;
  trifecta: boolean;
  sensitive_access: boolean;
  untrusted_exposure: boolean;
  outbound_channel: boolean;
  open_findings: number;
  child_count: number;
  is_simulation: boolean;
  simulation_run_id: string | null;
}

export interface SessionFilters {
  agent_id?: string;
  status?: string;
  min_risk?: number;
  trifecta?: boolean;
  include_simulated?: boolean;
  q?: string;
  sort?: SessionSort;
  limit: number;
  offset: number;
}

export interface RiskEvidence {
  type: string;
  id: string;
  detail: string;
  label: string | null;
  trust_level: string | null;
  session_id: string | null;
}

export type TrifectaKey = "sensitive_access" | "untrusted_exposure" | "outbound_channel";

export interface TrifectaCondition {
  key: TrifectaKey;
  label: string;
  description: string;
  active: boolean;
  evidence: RiskEvidence[];
}

export interface RiskFactor {
  key: string;
  label: string;
  weight: number;
  explanation: string;
  evidence: RiskEvidence[];
}

export interface SessionRef {
  id: string;
  external_session_id: string;
  agent: AgentRef;
  status: string;
  started_at: string;
  risk_score: number;
  risk_level: string;
  trifecta: boolean;
}

export interface SessionDetail extends SessionSummary {
  metadata: Record<string, unknown>;
  risk: {
    score: number;
    level: string;
    summary: string;
    trifecta: boolean;
    conditions: TrifectaCondition[];
    factors: RiskFactor[];
    computed_at: string | null;
    note: string;
  };
  parent: SessionRef | null;
  children: SessionRef[];
  counts: {
    timeline_entries: number;
    context_items: number;
    untrusted_context_items: number;
    tool_invocations: number;
    decisions: Record<string, number>;
    enforcement: Record<string, number>;
    findings_open: number;
    findings_total: number;
    approvals_pending: number;
    processing_errors: number;
  };
  findings: FindingBrief[];
}

export interface TimelineEntry {
  id: string;
  sequence: number;
  received_at: string;
  occurred_at: string;
  event_type: string;
  title: string;
  summary: string | null;
  trust_level: string | null;
  decision: string | null;
  enforcement: string | null;
  severity: string | null;
  processing_status: string;
  /** Recorded in another session (e.g. the parent's delegation that created this session's task). */
  from_other_session: boolean;
  tool: { name: string; category: string; status: string | null } | null;
  refs: {
    context_item_id: string | null;
    tool_invocation_id: string | null;
    policy_decision_id: string | null;
    finding_ids: string[];
    approval_id: string | null;
    child_session_id: string | null;
    source_id: string | null;
    destination_id: string | null;
  };
}

export interface TimelinePage extends Page<TimelineEntry> {
  /** Entries of the requested tool invocation (request and result). */
  focus_event_ids: string[];
}
