/** Test fixtures shaped exactly like the workspace API responses. */
import type { BoardDetail, ColumnWithTasks, TaskCard, TaskDetail } from "../../types";

const NOW = "2026-11-10T12:00:00Z";

export function makeCard(overrides: Partial<TaskCard> = {}): TaskCard {
  return {
    id: "tsk_1",
    key: "CTX-1",
    number: 1,
    board_id: "brd_1",
    column_id: "col_todo",
    column_name: "To do",
    status_key: "todo",
    is_done: false,
    position: 0,
    title: "Treat fetched web content as data",
    task_type: "prompt_injection",
    priority: "high",
    severity: "high",
    labels: [],
    assignees: [],
    due_date: null,
    is_overdue: false,
    parent_task_id: null,
    subtasks_total: 0,
    subtasks_done: 0,
    blocked_by_open: 0,
    verification_status: "unverified",
    related_finding_id: null,
    related_incident_id: null,
    related_agent_id: null,
    created_at: NOW,
    updated_at: NOW,
    completed_at: null,
    archived_at: null,
    ...overrides,
  };
}

export function makeColumn(overrides: Partial<ColumnWithTasks> = {}): ColumnWithTasks {
  const tasks = overrides.tasks ?? [];
  return {
    id: "col_todo",
    board_id: "brd_1",
    name: "To do",
    description: null,
    color: "slate",
    position: 0,
    wip_limit: null,
    status_key: "todo",
    is_done_column: false,
    requires_verification: false,
    automation: [],
    task_count: tasks.length,
    wip_exceeded: false,
    ...overrides,
    tasks,
  };
}

export function makeBoard(columns: ColumnWithTasks[], overrides: Partial<BoardDetail> = {}): BoardDetail {
  const all = columns.flatMap((c) => c.tasks);
  return {
    id: "brd_1",
    name: "Security remediation",
    description: null,
    template: "security_remediation",
    is_default: true,
    config: {},
    created_by: null,
    created_at: NOW,
    updated_at: NOW,
    archived_at: null,
    column_count: columns.length,
    task_count: all.length,
    open_task_count: all.filter((t) => !t.is_done).length,
    columns,
    ...overrides,
  };
}

export function makeTaskDetail(overrides: Partial<TaskDetail> = {}): TaskDetail {
  const card = makeCard();
  return {
    ...card,
    board_name: "Security remediation",
    column: makeColumn(),
    description: "Agents follow instructions embedded in fetched pages.",
    reporter: { id: "usr_1", name: "Ada Analyst", email: "ada@example.com" },
    related_files: ["backend/app/engines/detection/injection.py"],
    reproduction_steps: "1. Fetch the page\n2. Observe the tool call",
    expected_behaviour: "The instruction is ignored.",
    actual_behaviour: "The agent sends the file.",
    acceptance_criteria: [
      { text: "Injected instructions are treated as data", done: true },
      { text: "Regression scenario passes", done: false },
    ],
    resolution: null,
    verified_at: null,
    reopened_count: 0,
    parent: null,
    subtasks: [],
    blocked_by: [],
    blocking: [],
    comments: [],
    refs: [],
    attachments: [],
    links: { branch: [], commit: [], pull_request: [], deployment: [] },
    fix_attempts: [],
    verification_runs: [],
    activity: [],
    generated_prompt_ids: [],
    ...overrides,
  };
}
