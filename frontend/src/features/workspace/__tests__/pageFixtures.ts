/**
 * API fixtures for the Engineering Workspace pages, typed against ../types and ../analytics/types
 * (mirrors backend/app/schemas/workspace*.py). Task, column and board builders are shared with the
 * board component tests.
 */
import type { Member } from "@/features/settings/api";
import type { EngineeringAnalytics, RemediationFinding, RemediationPage } from "../analytics/types";
import type { BoardSummary, LabelWithUsage, TaskCard } from "../types";
import { makeCard } from "../boards/__tests__/fixtures";

export { makeBoard, makeCard, makeColumn, makeTaskDetail } from "../boards/__tests__/fixtures";

const NOW = "2026-11-10T12:00:00Z";
const DAY = 86_400_000;

/** An ISO time `days` from the moment the test runs (due dates are compared with the real clock). */
export const fromNow = (days: number) => new Date(Date.now() + days * DAY).toISOString();

export const LABEL: LabelWithUsage = { id: "lbl_sec", name: "security", color: "high", task_count: 2, created_at: NOW };

export const MEMBERS: Member[] = [
  { id: "mem_me", user_id: "usr_me", name: "Ada Analyst", email: "me@acme.test", role: "owner", is_active: true, created_at: NOW, last_login_at: NOW },
  { id: "mem_dev", user_id: "usr_dev", name: "Dev Person", email: "dev@acme.test", role: "developer", is_active: true, created_at: NOW, last_login_at: null },
];

export const ME_ASSIGNEE = { user_id: "usr_me", name: "Ada Analyst", email: "me@acme.test", role: "assignee" as const };

export function boardSummary(overrides: Partial<BoardSummary> = {}): BoardSummary {
  return {
    id: "brd_1",
    name: "Security remediation",
    description: "Fixes for findings raised by ContextOS.",
    template: "security_remediation",
    is_default: true,
    config: {},
    created_by: null,
    created_at: NOW,
    updated_at: NOW,
    archived_at: null,
    column_count: 5,
    task_count: 8,
    open_task_count: 6,
    ...overrides,
  };
}

export const ROTATE_TASK: TaskCard = makeCard({
  id: "tsk_rotate",
  key: "CTX-7",
  number: 7,
  title: "Rotate the leaked deploy key",
  task_type: "security_vulnerability",
  priority: "urgent",
  severity: "critical",
  column_id: "col_progress",
  column_name: "In progress",
  status_key: "in_progress",
  labels: [{ id: LABEL.id, name: LABEL.name, color: LABEL.color }],
  assignees: [ME_ASSIGNEE],
  due_date: fromNow(-1),
  is_overdue: true,
  blocked_by_open: 1,
  subtasks_total: 3,
  subtasks_done: 1,
  related_finding_id: "fnd_exfil",
});

export const DOCS_TASK: TaskCard = makeCard({
  id: "tsk_docs",
  key: "CTX-9",
  number: 9,
  title: "Treat fetched vendor docs as data",
  task_type: "prompt_injection",
  priority: "medium",
  severity: null,
  column_id: "col_todo",
  column_name: "To do",
  status_key: "todo",
  assignees: [ME_ASSIGNEE],
  due_date: fromNow(3),
  verification_status: "failed",
});

export const DONE_TASK: TaskCard = makeCard({
  id: "tsk_done",
  key: "CTX-3",
  number: 3,
  title: "Restrict Bash uploads",
  task_type: "agent_misconfiguration",
  priority: "low",
  severity: "medium",
  column_id: "col_done",
  column_name: "Done",
  status_key: "done",
  is_done: true,
  assignees: [ME_ASSIGNEE],
  verification_status: "passed",
  completed_at: NOW,
});

function finding(overrides: Partial<RemediationFinding>): RemediationFinding {
  return {
    finding_id: "fnd_exfil",
    title: "Credential sent to an unclassified host",
    category: "exfiltration",
    severity: "critical",
    status: "open",
    confidence: 0.95,
    occurrence_count: 2,
    first_seen_at: "2026-11-09T09:00:00Z",
    last_seen_at: "2026-11-10T09:20:00Z",
    is_simulation: false,
    agent_id: "agt_payments",
    agent_name: "payments-coder",
    session_id: "ses_main",
    incident_id: "inc_3",
    state: "task_open",
    state_reason: "CTX-7 is in progress.",
    linked_task_count: 1,
    task: ROTATE_TASK,
    ...overrides,
  };
}

export const REMEDIATION: RemediationPage = {
  items: [
    finding({}),
    finding({
      finding_id: "fnd_inj",
      title: "Instruction override in fetched page",
      category: "prompt_injection",
      severity: "high",
      occurrence_count: 1,
      incident_id: null,
      state: "no_task",
      state_reason: "No remediation task tracks this finding yet.",
      linked_task_count: 0,
      task: null,
    }),
  ],
  total: 2,
  limit: 50,
  offset: 0,
  counts: { no_task: 1, task_open: 1, task_done_unverified: 0, verified: 0 },
};

export const ANALYTICS: EngineeringAnalytics = {
  generated_at: NOW,
  window_days: 30,
  window_start: "2026-10-11T12:00:00Z",
  board_id: null,
  include_simulated: false,
  open_tasks: 6,
  overdue: 1,
  by_priority: [
    { key: "urgent", count: 1 },
    { key: "high", count: 2 },
    { key: "medium", count: 3 },
  ],
  by_type: [{ key: "security_vulnerability", count: 4 }],
  by_status_key: [{ key: "in_progress", count: 2 }],
  completed_in_window: 4,
  avg_resolution_hours: 30,
  median_resolution_hours: 7.25,
  p90_resolution_hours: 72,
  findings_awaiting_remediation: { total: 3, no_task: 1, task_open: 2, open_findings: 5 },
  remediation_completion_rate: { numerator: 2, denominator: 4, rate: 0.5 },
  reopened_issues: { reopen_events: 2, tasks_reopened: 1 },
  failed_verification_runs: { numerator: 1, denominator: 5, rate: 0.2 },
  outstanding_critical: {
    total: 1,
    findings: 1,
    tasks: 0,
    items: [
      {
        kind: "finding",
        id: "fnd_exfil",
        title: "Credential sent to an unclassified host",
        severity: "critical",
        since: "2026-11-09T09:00:00Z",
        state: "task_open",
        is_simulation: false,
        agent_id: "agt_payments",
        agent_name: "payments-coder",
        task: ROTATE_TASK,
      },
    ],
  },
  series_granularity: "day",
  created_vs_completed: [
    { start: "2026-11-08T00:00:00Z", created: 2, completed: 1 },
    { start: "2026-11-09T00:00:00Z", created: 1, completed: 2 },
  ],
  throughput: [{ start: "2026-11-03T00:00:00Z", created: 3, completed: 4 }],
  cycle_time: [
    { key: "lt_1d", label: "< 1 day", min_hours: 0, max_hours: 24, count: 3 },
    { key: "1_7d", label: "1–7 days", min_hours: 24, max_hours: 168, count: 1 },
  ],
};

/** No tasks, findings or runs in the window: what a brand-new workspace returns. */
export const EMPTY_ANALYTICS: EngineeringAnalytics = {
  ...ANALYTICS,
  open_tasks: 0,
  overdue: 0,
  by_priority: [],
  by_type: [],
  by_status_key: [],
  completed_in_window: 0,
  avg_resolution_hours: null,
  median_resolution_hours: null,
  p90_resolution_hours: null,
  findings_awaiting_remediation: { total: 0, no_task: 0, task_open: 0, open_findings: 0 },
  remediation_completion_rate: { numerator: 0, denominator: 0, rate: null },
  reopened_issues: { reopen_events: 0, tasks_reopened: 0 },
  failed_verification_runs: { numerator: 0, denominator: 0, rate: null },
  outstanding_critical: { total: 0, findings: 0, tasks: 0, items: [] },
  created_vs_completed: [],
  throughput: [],
  cycle_time: [],
};

/** jsdom has no ResizeObserver; recharts' ResponsiveContainer needs one. */
export function stubResizeObserver() {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
}
