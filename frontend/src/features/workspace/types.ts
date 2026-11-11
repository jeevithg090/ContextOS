/**
 * Engineering Workspace API types — boards, columns, tasks and task evidence.
 *
 * Mirrors backend/app/schemas/workspace.py, workspace_boards.py, workspace_tasks.py and
 * workspace_evidence.py. Keep the two in sync: field names and literal unions are the contract.
 *
 * Honesty rules the types carry:
 * - A fix attempt in `claimed_complete` is a claim (`is_claim_only`); only a passed verification run
 *   changes `verification_status`.
 * - Context references (`TaskRef`) point at recorded security data; they are never copies of it.
 */
import type { Severity } from "@/lib/domain";
import type { AgentTool, AssigneeRole, AttachmentKind, AutomationTrigger, BoardTemplateKey, CardField, DependencyKind, FixStatus, LinkKind, PullRequestState, RefType, SettableFixStatus, StatusKey, Swimlane, TaskPriority, TaskType, VerificationKind, VerificationRunStatus, VerificationStatus } from "./vocabulary";

export * from "./vocabulary";

// ---------------------------------------------------------------------------- shared shapes

export interface UserRef {
  id: string;
  name: string;
  email: string;
}

export interface Label {
  id: string;
  name: string;
  color: string;
}

export interface LabelWithUsage extends Label {
  task_count: number;
  created_at: string;
}

export interface Assignee {
  user_id: string;
  name: string;
  email: string;
  role: AssigneeRole;
}

// ---------------------------------------------------------------------------- boards & columns

export interface BoardTemplate {
  key: BoardTemplateKey;
  name: string;
  description: string;
  columns: string[];
  requires_verification: boolean;
}

export interface AutomationRule {
  trigger: AutomationTrigger;
  move_to_column_id: string;
}

export interface BoardConfig {
  card_fields?: CardField[];
  swimlanes?: Swimlane;
  default_task_type?: TaskType;
}

export interface Column {
  id: string;
  board_id: string;
  name: string;
  description: string | null;
  color: string;
  position: number;
  wip_limit: number | null;
  status_key: StatusKey;
  is_done_column: boolean;
  requires_verification: boolean;
  automation: AutomationRule[];
  /** Non-archived tasks currently in the column. */
  task_count: number;
  /** True when a WIP limit is set and the column holds more tasks than it (after an explicit override). */
  wip_exceeded: boolean;
}

/** Compact task representation used on board columns and in task lists. */
export interface TaskCard {
  id: string;
  key: string;
  number: number;
  board_id: string;
  column_id: string;
  column_name: string;
  status_key: StatusKey;
  is_done: boolean;
  position: number;
  title: string;
  task_type: TaskType;
  priority: TaskPriority;
  severity: Severity | null;
  labels: Label[];
  assignees: Assignee[];
  due_date: string | null;
  is_overdue: boolean;
  parent_task_id: string | null;
  subtasks_total: number;
  subtasks_done: number;
  /** Open tasks this task depends on ("blocks" dependencies). */
  blocked_by_open: number;
  verification_status: VerificationStatus;
  related_finding_id: string | null;
  related_incident_id: string | null;
  related_agent_id: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  archived_at: string | null;
}

export interface ColumnWithTasks extends Column {
  tasks: TaskCard[];
}

export interface BoardSummary {
  id: string;
  name: string;
  description: string | null;
  template: BoardTemplateKey | string;
  is_default: boolean;
  config: BoardConfig;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  column_count: number;
  task_count: number;
  /** Tasks not in a done column. */
  open_task_count: number;
}

export interface BoardDetail extends BoardSummary {
  columns: ColumnWithTasks[];
}

export interface BoardCreateInput {
  name: string;
  template?: BoardTemplateKey;
  description?: string | null;
}

export interface BoardPatch {
  name?: string;
  description?: string | null;
  is_default?: boolean;
  config?: BoardConfig;
  /** false restores an archived board. */
  archived?: boolean;
}

export interface ColumnInput {
  name: string;
  description?: string | null;
  color?: string;
  wip_limit?: number | null;
  status_key?: StatusKey;
  requires_verification?: boolean;
  is_done_column?: boolean;
  automation?: AutomationRule[];
  /** Insert index; default is the end. */
  position?: number;
}

export type ColumnPatch = Partial<Omit<ColumnInput, "position">>;

export interface ColumnDeleteResult {
  deleted_column_id: string;
  moved_task_count: number;
  moved_to_column_id: string | null;
  /** Rules in other columns that targeted the deleted column. */
  removed_automation_rules: number;
}

// ---------------------------------------------------------------------------- tasks

export interface AcceptanceCriterion {
  text: string;
  done: boolean;
}

interface TaskFields {
  description?: string | null;
  task_type?: TaskType;
  priority?: TaskPriority;
  severity?: Severity | null;
  due_date?: string | null;
  parent_task_id?: string | null;
  related_agent_id?: string | null;
  related_incident_id?: string | null;
  related_finding_id?: string | null;
  related_files?: string[];
  reproduction_steps?: string | null;
  expected_behaviour?: string | null;
  actual_behaviour?: string | null;
  acceptance_criteria?: Array<{ text: string; done?: boolean }>;
  label_ids?: string[];
}

export interface TaskCreateInput extends TaskFields {
  title: string;
  /** Default: the organisation's default board. */
  board_id?: string;
  /** Default: the board's first column. */
  column_id?: string;
  assignee_ids?: string[];
  override_wip?: boolean;
}

export interface TaskPatch extends TaskFields {
  title?: string;
  resolution?: string | null;
  /** false restores an archived task. */
  archived?: boolean;
}

export interface TaskMoveInput {
  column_id: string;
  /** Index within the target column; default end. */
  position?: number;
  override_wip?: boolean;
}

export type TaskSort = "updated" | "created" | "key" | "due_date" | "priority" | "position";

export interface TaskFilters {
  board_id?: string;
  column_id?: string;
  /** User id, or "me". */
  assignee?: string;
  task_type?: TaskType;
  priority?: TaskPriority;
  /** Label id or name. */
  label?: string;
  /** Title/description text, or a key such as CTX-12. */
  q?: string;
  status_key?: StatusKey;
  related_finding_id?: string;
  related_incident_id?: string;
  parent_task_id?: string;
  overdue?: boolean;
  include_done?: boolean;
  include_archived?: boolean;
  sort?: TaskSort;
  limit?: number;
  offset?: number;
}

export interface TaskBrief {
  id: string;
  key: string;
  title: string;
  status_key: StatusKey;
  is_done: boolean;
  archived: boolean;
}

export interface TaskComment {
  id: string;
  task_id: string;
  author: UserRef | null;
  body: string;
  created_at: string;
  edited_at: string | null;
}

export interface TaskDependency {
  id: string;
  task_id: string;
  depends_on_task_id: string;
  kind: DependencyKind;
  created_at: string;
  /** The task on the other side of the dependency. */
  task: TaskBrief;
}

export interface TaskRef {
  id: string;
  task_id: string;
  ref_type: RefType;
  ref_id: string;
  note: string | null;
  /** Human-readable name of the referenced record (redacted). */
  label: string;
  /** Short status line, e.g. severity and status. */
  detail: string | null;
  /** False when the referenced record has since been deleted. */
  exists: boolean;
  created_at: string;
}

export interface TaskActivity {
  id: string;
  kind: string;
  /** null = system / automation. */
  actor: UserRef | null;
  from_value: string | null;
  to_value: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface TaskAttachment {
  id: string;
  task_id: string;
  name: string;
  kind: AttachmentKind;
  url: string | null;
  /** Redacted text content. */
  content: string | null;
  /** Stored (redacted) content size in bytes. */
  size: number;
  created_by: UserRef | null;
  created_at: string;
}

export interface TaskLink {
  index: number;
  kind: LinkKind;
  url: string | null;
  title: string | null;
  ref: string | null;
  state: PullRequestState | null;
  added_at: string | null;
  added_by: string | null;
}

export type TaskLinks = Record<LinkKind, TaskLink[]>;

export interface FixAttempt {
  id: string;
  task_id: string;
  generated_prompt_id: string | null;
  agent_tool: AgentTool;
  status: FixStatus;
  branch: string | null;
  commit_sha: string | null;
  pr_url: string | null;
  notes: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_by: UserRef | null;
  created_at: string;
  updated_at: string;
  /** True for claimed_complete: a claim, not verification. */
  is_claim_only: boolean;
}

export interface VerificationRun {
  id: string;
  task_id: string;
  fix_attempt_id: string | null;
  kind: VerificationKind;
  status: VerificationRunStatus;
  summary: string;
  command: string | null;
  evidence_url: string | null;
  evidence: Record<string, unknown>;
  simulation_run_id: string | null;
  created_by: UserRef | null;
  created_at: string;
  /** The task's verification status after this run. */
  task_verification_status: VerificationStatus;
}

export interface TaskDetail extends TaskCard {
  board_name: string;
  column: Column;
  description: string;
  reporter: UserRef | null;
  related_files: string[];
  reproduction_steps: string;
  expected_behaviour: string;
  actual_behaviour: string;
  acceptance_criteria: AcceptanceCriterion[];
  resolution: string | null;
  verified_at: string | null;
  reopened_count: number;
  parent: TaskBrief | null;
  subtasks: TaskBrief[];
  /** Tasks this task depends on. */
  blocked_by: TaskDependency[];
  /** Tasks that depend on this task. */
  blocking: TaskDependency[];
  comments: TaskComment[];
  refs: TaskRef[];
  attachments: TaskAttachment[];
  links: TaskLinks;
  fix_attempts: FixAttempt[];
  verification_runs: VerificationRun[];
  /** Newest first (at most 200 entries). */
  activity: TaskActivity[];
  generated_prompt_ids: string[];
}

// ---------------------------------------------------------------------------- remediation link

export interface FromFindingResult {
  /** False when an open task for this finding already existed (it is returned instead). */
  created: boolean;
  task: TaskDetail;
}

export type IncidentTaskMode = "per_finding" | "parent_with_subtasks";

export interface FromIncidentResult {
  incident_id: string;
  mode: IncidentTaskMode;
  parent_task_id: string | null;
  created_count: number;
  existing_count: number;
  tasks: Array<{ finding_id: string | null; created: boolean; task: TaskCard }>;
}

// ---------------------------------------------------------------------------- evidence inputs

export interface AssigneeInput {
  user_id: string;
  role?: AssigneeRole;
}

export interface RefInput {
  ref_type: RefType;
  ref_id: string;
  note?: string | null;
}

export interface AttachmentInput {
  name: string;
  kind?: AttachmentKind;
  url?: string | null;
  /** At most ATTACHMENT_MAX_BYTES; secrets are redacted by the server before storage. */
  content?: string | null;
}

export interface LinkInput {
  kind: LinkKind;
  url?: string | null;
  title?: string | null;
  /** Branch name, commit SHA or environment. */
  ref?: string | null;
  /** Pull requests only. */
  state?: PullRequestState | null;
}

export interface FixAttemptInput {
  agent_tool?: AgentTool;
  generated_prompt_id?: string | null;
  status?: SettableFixStatus;
  branch?: string | null;
  commit_sha?: string | null;
  pr_url?: string | null;
  notes?: string | null;
}

export type FixAttemptPatch = Omit<FixAttemptInput, "agent_tool" | "generated_prompt_id">;

export interface VerificationInput {
  kind: VerificationKind;
  /** Required except for kind=simulation (taken from the referenced run). */
  status?: VerificationRunStatus;
  summary?: string;
  command?: string | null;
  evidence_url?: string | null;
  evidence?: Record<string, unknown>;
  fix_attempt_id?: string | null;
  simulation_run_id?: string | null;
}

/** Reasons the server gives (`error.details.reason`) when a workflow gate refuses a change (HTTP 409). */
export type WorkflowConflictReason =
  | "wip_limit_exceeded"
  | "verification_required"
  | "column_not_empty"
  | "dependency_cycle"
  | "parent_cycle";

export interface WorkflowConflict {
  reason: WorkflowConflictReason | string | null;
  message: string;
  details: Record<string, unknown>;
}
