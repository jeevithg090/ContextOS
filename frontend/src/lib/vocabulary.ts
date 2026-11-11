/**
 * The rest of the backend domain vocabulary (backend/app/domain/enums.py) with display labels:
 * trust capabilities, policy and enforcement modes, sources, tools, sensitivity, risk, roles and
 * permissions, event types, provenance and Engineering-Workspace task fields. Re-exported from
 * `@/lib/domain`; `src/lib/__tests__/domainSync.test.ts` fails when the backend adds a value.
 */
import type { Tone } from "./domain";

/** Label for a vocabulary value, falling back to a readable form of an unknown backend value. */
export function labelFrom(labels: Record<string, string>, value?: string | null): string {
  if (!value) return "—";
  return labels[value] ?? value.replace(/[_.:]/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export const TRUST_CAPABILITIES = ["read", "instruct", "execute", "credential_access", "send"] as const;
export type TrustCapability = (typeof TRUST_CAPABILITIES)[number];
export const TRUST_CAPABILITY_LABELS: Record<TrustCapability, string> = {
  read: "Read as data",
  instruct: "Give instructions",
  execute: "Trigger tool execution",
  credential_access: "Lead to credential access",
  send: "Receive data (destinations)",
};

export const POLICY_MODES = ["enforce", "monitor"] as const;
export type PolicyMode = (typeof POLICY_MODES)[number];
export const POLICY_MODE_META: Record<PolicyMode, { label: string; description: string }> = {
  enforce: { label: "Enforce", description: "The decision is returned to the integration and enforced where the integration supports it." },
  monitor: { label: "Monitor", description: "Dry run: the decision is recorded only and never changes the returned outcome." },
};

export const ENFORCEMENT_MODES = ["enforced", "advisory", "observed"] as const;

export const SOURCE_TYPES = [
  "web", "repository", "file", "document", "email", "api", "mcp_server", "mcp_tool", "browser", "database",
  "user_upload", "user_prompt", "tool_output", "agent_output", "system", "other",
] as const;
export type SourceType = (typeof SOURCE_TYPES)[number];
export const SOURCE_TYPE_LABELS: Record<SourceType, string> = {
  web: "Web page",
  repository: "Repository",
  file: "File",
  document: "Document",
  email: "Email",
  api: "API response",
  mcp_server: "MCP server",
  mcp_tool: "MCP tool",
  browser: "Browser page",
  database: "Database",
  user_upload: "Uploaded file",
  user_prompt: "User prompt",
  tool_output: "Tool output",
  agent_output: "Agent output",
  system: "System prompt",
  other: "Other",
};

export const TOOL_CATEGORIES = [
  "file_read", "file_write", "shell", "http", "browser", "email", "messaging", "database", "code_execution",
  "infrastructure", "agent_delegation", "search", "mcp", "other",
] as const;
export type ToolCategory = (typeof TOOL_CATEGORIES)[number];
export const TOOL_CATEGORY_LABELS: Record<ToolCategory, string> = {
  file_read: "File read",
  file_write: "File write",
  shell: "Shell",
  http: "HTTP request",
  browser: "Browser",
  email: "Email",
  messaging: "Messaging",
  database: "Database",
  code_execution: "Code execution",
  infrastructure: "Infrastructure",
  agent_delegation: "Agent delegation",
  search: "Search",
  mcp: "MCP tool",
  other: "Other",
};
/** Categories that can move data out of the environment (the lethal trifecta's outbound channel). */
export const OUTBOUND_TOOL_CATEGORIES: ReadonlySet<ToolCategory> = new Set(["http", "browser", "email", "messaging", "shell", "code_execution", "infrastructure", "mcp"]);

export const SENSITIVITIES = ["public", "internal", "confidential", "secret"] as const;
export type Sensitivity = (typeof SENSITIVITIES)[number];
export const SENSITIVITY_META: Record<Sensitivity, { label: string; tone: Tone }> = {
  public: { label: "Public", tone: "neutral" },
  internal: { label: "Internal", tone: "neutral" },
  confidential: { label: "Confidential", tone: "medium" },
  secret: { label: "Secret", tone: "high" },
};

export const RISK_LEVELS = ["low", "medium", "high", "critical"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];
export const RISK_LEVEL_META: Record<RiskLevel, { label: string; tone: Tone; rank: number }> = {
  low: { label: "Low risk", tone: "low", rank: 1 },
  medium: { label: "Medium risk", tone: "medium", rank: 2 },
  high: { label: "High risk", tone: "high", rank: 3 },
  critical: { label: "Critical risk", tone: "critical", rank: 4 },
};
export function riskTone(level?: string | null): Tone {
  return (level && RISK_LEVEL_META[level as RiskLevel]?.tone) || "neutral";
}

export const ROLE_LABELS: Record<"owner" | "admin" | "security_analyst" | "developer" | "viewer", string> = {
  owner: "Owner",
  admin: "Admin",
  security_analyst: "Security analyst",
  developer: "Developer",
  viewer: "Viewer",
};

export const PERMISSIONS = ["read", "write", "approve", "policy:manage", "trust:manage", "admin", "ingest", "decide"] as const;
export type Permission = (typeof PERMISSIONS)[number];
export const PERMISSION_LABELS: Record<Permission, string> = {
  read: "View data",
  write: "Triage & tasks",
  approve: "Decide approvals",
  "policy:manage": "Edit policies",
  "trust:manage": "Edit trust",
  admin: "Administer",
  ingest: "Report events",
  decide: "Request decisions",
};
/** Scopes an API key may carry (backend API_KEY_SCOPES). */
export const API_KEY_SCOPES = ["ingest", "decide", "read"] as const;

export const EVENT_TYPES = [
  "session.started", "session.ended", "prompt.submitted", "context.ingested", "tool.requested", "tool.completed",
  "tool.failed", "agent.delegated", "agent.message", "mcp.server_connected",
] as const;
export type EventType = (typeof EVENT_TYPES)[number];
export const EVENT_TYPE_LABELS: Record<EventType, string> = {
  "session.started": "Session started",
  "session.ended": "Session ended",
  "prompt.submitted": "Prompt submitted",
  "context.ingested": "Context ingested",
  "tool.requested": "Tool call requested",
  "tool.completed": "Tool call completed",
  "tool.failed": "Tool call failed",
  "agent.delegated": "Delegated to another agent",
  "agent.message": "Agent message",
  "mcp.server_connected": "MCP server connected",
};

export const PROVENANCE_NODE_TYPES = [
  "source", "context_item", "session", "agent", "tool", "tool_invocation", "resource", "destination", "finding", "policy_decision",
] as const;
export type ProvenanceNodeType = (typeof PROVENANCE_NODE_TYPES)[number];
export const PROVENANCE_NODE_LABELS: Record<ProvenanceNodeType, string> = {
  source: "Source",
  context_item: "Context item",
  session: "Session",
  agent: "Agent",
  tool: "Tool",
  tool_invocation: "Tool call",
  resource: "Resource",
  destination: "Destination",
  finding: "Finding",
  policy_decision: "Policy decision",
};

export const PROVENANCE_RELATIONS = [
  "source_produced_item", "item_entered_session", "session_invoked_tool", "invocation_used_tool",
  "invocation_accessed_resource", "invocation_sent_to", "invocation_returned_item", "agent_ran_session",
  "session_delegated_to", "agent_messaged", "item_triggered_finding", "invocation_decided_by",
] as const;
export type ProvenanceRelation = (typeof PROVENANCE_RELATIONS)[number];
/** Observed relationships (recorded by integrations), never claims of causation. */
export const PROVENANCE_RELATION_LABELS: Record<ProvenanceRelation, string> = {
  source_produced_item: "Source produced item",
  item_entered_session: "Item entered session",
  session_invoked_tool: "Session invoked tool call",
  invocation_used_tool: "Call used tool",
  invocation_accessed_resource: "Call accessed resource",
  invocation_sent_to: "Call sent data to",
  invocation_returned_item: "Call returned item",
  agent_ran_session: "Agent ran session",
  session_delegated_to: "Session delegated to",
  agent_messaged: "Agent sent message",
  item_triggered_finding: "Item triggered finding",
  invocation_decided_by: "Call decided by policy",
};

export const TASK_PRIORITIES = ["urgent", "high", "medium", "low", "none"] as const;
export type TaskPriority = (typeof TASK_PRIORITIES)[number];
export const TASK_PRIORITY_META: Record<TaskPriority, { label: string; tone: Tone }> = {
  urgent: { label: "Urgent", tone: "critical" },
  high: { label: "High", tone: "high" },
  medium: { label: "Medium", tone: "medium" },
  low: { label: "Low", tone: "low" },
  none: { label: "No priority", tone: "neutral" },
};

export const TASK_TYPES = [
  "security_vulnerability", "prompt_injection", "agent_misconfiguration", "data_exposure", "integration_bug",
  "backend", "frontend", "performance", "feature", "tech_debt", "task",
] as const;
export type TaskType = (typeof TASK_TYPES)[number];
export const TASK_TYPE_LABELS: Record<TaskType, string> = {
  security_vulnerability: "Security vulnerability",
  prompt_injection: "Prompt injection",
  agent_misconfiguration: "Agent misconfiguration",
  data_exposure: "Data exposure",
  integration_bug: "Integration bug",
  backend: "Backend",
  frontend: "Frontend",
  performance: "Performance",
  feature: "Feature",
  tech_debt: "Tech debt",
  task: "Task",
};

export const VERIFICATION_STATUSES = ["unverified", "pending", "passed", "failed"] as const;
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];
export const VERIFICATION_STATUS_META: Record<VerificationStatus, { label: string; tone: Tone }> = {
  unverified: { label: "Unverified", tone: "neutral" },
  pending: { label: "Verification pending", tone: "warn" },
  passed: { label: "Verified", tone: "ok" },
  failed: { label: "Verification failed", tone: "danger" },
};
