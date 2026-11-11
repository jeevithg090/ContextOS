/**
 * Incident types. Mirrors backend/app/schemas/incidents.py — every value is computed by the server
 * from persisted rows; free text was redacted before it was stored.
 */
import type { IncidentStatus, Severity } from "@/lib/domain";

export interface AgentRef {
  id: string;
  name: string;
}

export interface SessionRef {
  id: string;
  external_session_id: string;
}

export interface UserRef {
  id: string;
  name: string;
}

export interface Actor {
  type: "user" | "system";
  id: string | null;
  name: string;
}

export interface IncidentSummary {
  id: string;
  number: number;
  key: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  assignee: UserRef | null;
  primary_agent: AgentRef | null;
  primary_session: SessionRef | null;
  finding_count: number;
  open_finding_count: number;
  max_finding_severity: Severity | null;
  opened_at: string;
  updated_at: string;
  resolved_at: string | null;
  created_by: Actor;
  is_simulation: boolean;
}

export interface IncidentFinding {
  id: string;
  title: string;
  category: string;
  rule_id: string;
  severity: Severity;
  status: string;
  confidence: number;
  explanation: string;
  agent: AgentRef | null;
  session: SessionRef | null;
  source_id: string | null;
  context_item_id: string | null;
  tool_invocation_id: string | null;
  policy_decision_id: string | null;
  destination_id: string | null;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
}

export interface InvolvedAgent {
  id: string;
  name: string;
  framework: string;
  environment: string;
  status: string;
  finding_count: number;
  is_primary: boolean;
}

export interface InvolvedSession {
  id: string;
  external_session_id: string;
  agent_id: string;
  agent_name: string;
  status: string;
  started_at: string;
  ended_at: string | null;
  event_count: number;
  risk_score: number;
  risk_level: string;
  trifecta: boolean;
  finding_count: number;
  is_primary: boolean;
}

export interface InvolvedSource {
  id: string;
  source_type: string;
  identifier: string;
  display_name: string | null;
  trust_level: string;
  trust_reasons: Array<string | null>;
  finding_count: number;
}

export interface InvolvedDestination {
  id: string;
  kind: string;
  identifier: string;
  display_name: string | null;
  classification: string;
  transfer_count: number;
  blocked_count: number;
  finding_count: number;
}

export interface Involved {
  agents: InvolvedAgent[];
  sessions: InvolvedSession[];
  sources: InvolvedSource[];
  destinations: InvolvedDestination[];
  note: string;
}

export interface Activity {
  id: string;
  kind: string;
  actor: Actor;
  body: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface LinkedTask {
  id: string;
  key: string;
  title: string;
  priority: string;
  column: string | null;
  done: boolean;
  archived: boolean;
  related_finding_id: string | null;
  parent_task_id: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  summary: string;
  resolution: string | null;
  tags: unknown[];
  allowed_transitions: IncidentStatus[];
  findings: IncidentFinding[];
  involved: Involved;
  activity: Activity[];
  tasks: LinkedTask[];
}

export interface IncidentFilters {
  status?: IncidentStatus[];
  severity?: Severity[];
  include_simulated?: boolean;
  q?: string;
  assignee_user_id?: string;
  unassigned?: boolean;
  sort?: IncidentSort;
}

export type IncidentSort = "priority" | "recent" | "updated";

export interface IncidentCreate {
  title: string;
  summary?: string;
  severity: Severity;
  finding_ids?: string[];
}

export interface IncidentUpdate {
  status?: IncidentStatus;
  severity?: Severity;
  /** null unassigns. */
  assignee_user_id?: string | null;
  resolution?: string;
}

export interface LinkFindingsResult {
  linked: string[];
  already_linked: string[];
  incident: IncidentDetail;
}

export const TIMELINE_ENTRY_TYPES = ["event", "finding", "policy_decision", "approval", "activity"] as const;
export type TimelineEntryType = (typeof TIMELINE_ENTRY_TYPES)[number];

export interface TimelineRefs {
  event_id: string | null;
  session_id: string | null;
  context_item_id: string | null;
  tool_invocation_id: string | null;
  policy_decision_id: string | null;
  approval_id: string | null;
  source_id: string | null;
  destination_id: string | null;
  finding_id: string | null;
  finding_ids: string[];
}

export interface TimelineEntry {
  id: string;
  type: TimelineEntryType;
  occurred_at: string;
  title: string;
  summary: string | null;
  severity: string | null;
  status: string | null;
  decision: string | null;
  enforcement: string | null;
  trust_level: string | null;
  event_type: string | null;
  sequence: number | null;
  session_id: string | null;
  agent_id: string | null;
  actor: Actor | null;
  tool_name: string | null;
  from_other_session: boolean;
  refs: TimelineRefs;
}

export interface IncidentTimeline {
  incident_id: string;
  items: TimelineEntry[];
  total: number;
  truncated: boolean;
  counts: Record<TimelineEntryType, number>;
  session_ids: string[];
  recorded_event_count: number;
  note: string;
}

/** GET /org/members (subset used for the assignee picker). */
export interface Member {
  id: string;
  user_id: string;
  name: string;
  email: string;
  role: string;
  is_active: boolean;
}

/** GET /findings (subset used when choosing findings to group into an incident). */
export interface FindingOption {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  status: string;
  agent: AgentRef | null;
  session: SessionRef | null;
  incident: { id: string; number: number } | null;
  last_seen_at: string;
  is_simulation: boolean;
}

/** POST /workspace/tasks/from-incident (fields used here). */
export interface RemediationTasksResult {
  incident_id: string;
  mode: "per_finding" | "parent_with_subtasks";
  parent_task_id: string | null;
  created_count: number;
  existing_count: number;
  tasks: Array<{ finding_id: string | null; created: boolean; task: { id: string; key?: string; title: string } }>;
}

export interface ExportResult {
  filename: string;
  sha256: string | null;
}
