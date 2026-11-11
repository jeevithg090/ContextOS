/**
 * Engineering Workspace vocabularies: task types, priorities, statuses, column keys and colours,
 * reference kinds and limits. Mirrors the literal unions in backend/app/schemas/workspace*.py and
 * app.workspace.templates; re-exported from `./types` (import from either).
 */

export const TASK_TYPES = [
  "security_vulnerability",
  "prompt_injection",
  "agent_misconfiguration",
  "data_exposure",
  "integration_bug",
  "backend",
  "frontend",
  "performance",
  "feature",
  "tech_debt",
  "task",
] as const;
export type TaskType = (typeof TASK_TYPES)[number];

export const TASK_PRIORITIES = ["urgent", "high", "medium", "low", "none"] as const;
export type TaskPriority = (typeof TASK_PRIORITIES)[number];

export const VERIFICATION_STATUSES = ["unverified", "pending", "passed", "failed"] as const;
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];

/** Semantic column category (== app.workspace.templates.STATUS_KEYS). */
export const STATUS_KEYS = [
  "backlog",
  "todo",
  "investigating",
  "ready",
  "in_progress",
  "review",
  "testing",
  "verified",
  "done",
] as const;
export type StatusKey = (typeof STATUS_KEYS)[number];

/** Column colour token names (== app.workspace.templates.COLOR_TOKENS); "#rrggbb" is also accepted. */
export const COLUMN_COLORS = [
  "slate",
  "accent",
  "trusted",
  "approved",
  "external",
  "suspicious",
  "blocked",
  "high",
  "medium",
  "low",
] as const;
export type ColumnColor = (typeof COLUMN_COLORS)[number];

export const AUTOMATION_TRIGGERS = ["pr_linked", "verification_passed", "verification_failed", "fix_attempt_started"] as const;
export type AutomationTrigger = (typeof AUTOMATION_TRIGGERS)[number];

export const BOARD_TEMPLATE_KEYS = [
  "software_development",
  "security_remediation",
  "incident_response",
  "bug_tracking",
  "feature_development",
  "technical_debt",
  "research_experiments",
] as const;
export type BoardTemplateKey = (typeof BOARD_TEMPLATE_KEYS)[number];

export const CARD_FIELDS = ["key", "type", "priority", "severity", "labels", "assignees", "due_date", "subtasks", "verification", "finding"] as const;
export type CardField = (typeof CARD_FIELDS)[number];

export type Swimlane = "none" | "priority" | "assignee";

export const REF_TYPES = [
  "finding",
  "incident",
  "event",
  "session",
  "agent",
  "tool_invocation",
  "policy_decision",
  "context_item",
  "source",
  "approval",
  "destination",
] as const;
export type RefType = (typeof REF_TYPES)[number];

export type DependencyKind = "blocks" | "relates_to";
export type AssigneeRole = "assignee" | "reviewer";

export const LINK_KINDS = ["branch", "commit", "pull_request", "deployment"] as const;
export type LinkKind = (typeof LINK_KINDS)[number];
export type PullRequestState = "open" | "draft" | "merged" | "closed";

export type AttachmentKind = "link" | "log" | "stack_trace" | "note";

export const FIX_STATUSES = ["planned", "in_progress", "claimed_complete", "verified", "failed", "abandoned"] as const;
export type FixStatus = (typeof FIX_STATUSES)[number];
/** Statuses a client may set; `verified` is reached only through a passed verification run. */
export type SettableFixStatus = Exclude<FixStatus, "verified">;

export type AgentTool = "claude_code" | "codex" | "cursor" | "copilot" | "human" | "other";

export const VERIFICATION_KINDS = ["test_run", "code_review", "manual", "deployment", "simulation", "replay"] as const;
export type VerificationKind = (typeof VERIFICATION_KINDS)[number];
export type VerificationRunStatus = "passed" | "failed" | "error" | "pending";

/** Maximum attachment text size accepted by the API (bytes, before redaction). */
export const ATTACHMENT_MAX_BYTES = 100 * 1024;
