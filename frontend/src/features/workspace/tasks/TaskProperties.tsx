/**
 * Task properties panel: stage (column), type, priority, severity, people, labels, due date, parent,
 * verification and the security records the task was raised for. Every edit is saved immediately.
 */
import { useMemo, type ReactNode } from "react";
import { format } from "date-fns";
import { ChevronDown, X } from "lucide-react";
import { EntityLink } from "@/components/data";
import { Select, useToast } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { useMembers } from "@/features/settings/api";
import { SEVERITIES, SEVERITY_META, type Severity } from "@/lib/domain";
import { formatDateTime, timeAgo } from "@/lib/format";
import { initials, LabelChip, PRIORITY_META, TASK_TYPE_LABELS, TaskKeyLink } from "../analytics/taskMeta";
import { useBoard, useCreateLabel, useLabels, useMoveTask, useSetAssignees } from "../api";
import { TASK_PRIORITIES, TASK_TYPES, type AssigneeRole, type TaskDetail, type TaskPriority, type TaskType } from "../types";
import { describeError, useSaveTask } from "./hooks";
import { OptionPicker } from "./pickers/OptionPicker";
import { TaskSearchPicker } from "./pickers/TaskSearchPicker";
import { VerificationStatusBadge } from "./taskBits";
import type { ConflictContext } from "./useWorkflowConflicts";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[96px_1fr] items-start gap-2 py-1.5">
      <dt className="pt-1 text-xs text-fg-faint">{label}</dt>
      <dd className="min-w-0 text-[13px] text-fg">{children}</dd>
    </div>
  );
}

const PICKER_TRIGGER =
  "inline-flex min-h-[28px] w-full flex-wrap items-center gap-1 rounded px-1.5 py-0.5 text-left text-[13px] text-fg hover:bg-surface-2 disabled:cursor-not-allowed disabled:hover:bg-transparent";

/** Local end of day, so a due date means "by the end of that day" wherever the user is. */
const dueIso = (date: string) => new Date(`${date}T23:59:59`).toISOString();

export function TaskProperties({ task, canWrite, report }: { task: TaskDetail; canWrite: boolean; report: (error: unknown, ctx: ConflictContext) => void }) {
  const toast = useToast();
  const { me } = useAuth();
  const { save } = useSaveTask(task.id);
  const board = useBoard(task.board_id);
  const members = useMembers();
  const labels = useLabels();
  const createLabel = useCreateLabel();
  const setAssignees = useSetAssignees();
  const move = useMoveTask();

  const columns = useMemo(() => [...(board.data?.columns ?? [])].sort((a, b) => a.position - b.position), [board.data]);
  const memberOptions = useMemo(
    () => (members.data?.items ?? []).filter((m) => m.is_active).map((m) => ({ value: m.user_id, label: m.user_id === me?.user.id ? `${m.name} (you)` : m.name, hint: m.email })),
    [members.data, me],
  );
  const people = (role: AssigneeRole) => task.assignees.filter((a) => a.role === role);

  const toggleAssignee = (userId: string, role: AssigneeRole) => {
    const current = task.assignees.map((a) => ({ user_id: a.user_id, role: a.role }));
    const existing = current.find((a) => a.user_id === userId);
    const next =
      existing?.role === role ? current.filter((a) => a.user_id !== userId) : [...current.filter((a) => a.user_id !== userId), { user_id: userId, role }];
    setAssignees.mutate({ taskId: task.id, assignees: next }, { onError: (e) => toast.error("People not updated", describeError(e)) });
  };

  const toggleLabel = (labelId: string) => {
    const ids = task.labels.map((l) => l.id);
    void save({ label_ids: ids.includes(labelId) ? ids.filter((id) => id !== labelId) : [...ids, labelId] }, "Labels").catch(() => undefined);
  };

  const moveTo = (columnId: string, overrideWip = false): Promise<unknown> => {
    const target = columns.find((c) => c.id === columnId);
    const vars = { taskId: task.id, boardId: task.board_id, column_id: columnId, override_wip: overrideWip };
    return move.mutateAsync(vars).then(
      () => toast.success(`${task.key} moved to “${target?.name ?? "column"}”`),
      (error: unknown) => {
        if (overrideWip) throw error;
        report(error, { title: `${task.key} was not moved to “${target?.name ?? "that column"}”`, override: () => moveTo(columnId, true) });
      },
    );
  };

  const personList = (role: AssigneeRole, empty: string) => {
    const list = people(role);
    const trigger = (
      <button type="button" className={PICKER_TRIGGER} disabled={!canWrite} aria-label={role === "assignee" ? "Change assignees" : "Change reviewers"}>
        {list.length === 0 ? (
          <span className="text-fg-faint">{empty}</span>
        ) : (
          list.map((a) => (
            <span key={a.user_id} className="inline-flex items-center gap-1 rounded bg-surface-2 px-1 py-0.5 text-xs" title={a.email}>
              <span className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-surface-3 text-[8px] font-semibold text-fg-muted" aria-hidden>
                {initials(a.name)}
              </span>
              {a.name}
            </span>
          ))
        )}
      </button>
    );
    return (
      <OptionPicker
        trigger={trigger}
        ariaLabel={role === "assignee" ? "Search people to assign" : "Search reviewers"}
        multiple
        options={memberOptions}
        selected={list.map((a) => a.user_id)}
        onSelect={(userId) => toggleAssignee(userId, role)}
        loading={members.isLoading}
        emptyLabel={members.error ? "Could not load members." : "No matching members."}
        disabled={!canWrite}
      />
    );
  };

  const dueValue = task.due_date ? format(new Date(task.due_date), "yyyy-MM-dd") : "";

  return (
    <dl className="divide-y divide-border/60">
      <Row label="Stage">
        {canWrite && columns.length > 0 ? (
          <Select aria-label="Move to column" value={task.column_id} onChange={(e) => void moveTo(e.target.value)} disabled={move.isPending} className="!h-7 !text-xs">
            {columns.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
                {c.wip_limit !== null ? ` (${c.task_count}/${c.wip_limit})` : ""}
                {c.requires_verification ? " · verification gate" : ""}
              </option>
            ))}
          </Select>
        ) : (
          <span>{task.column_name}</span>
        )}
        <div className="mt-1 text-2xs text-fg-faint">on {task.board_name}</div>
      </Row>
      <Row label="Verification">
        <VerificationStatusBadge status={task.verification_status} />
        {task.verified_at && <div className="mt-1 text-2xs text-fg-faint">Passed {timeAgo(task.verified_at)}</div>}
      </Row>
      <Row label="Type">
        <Select aria-label="Task type" value={task.task_type} disabled={!canWrite} onChange={(e) => void save({ task_type: e.target.value as TaskType }, "Type").catch(() => undefined)} className="!h-7 !text-xs">
          {TASK_TYPES.map((t) => (
            <option key={t} value={t}>
              {TASK_TYPE_LABELS[t]}
            </option>
          ))}
        </Select>
      </Row>
      <Row label="Priority">
        <Select aria-label="Priority" value={task.priority} disabled={!canWrite} onChange={(e) => void save({ priority: e.target.value as TaskPriority }, "Priority").catch(() => undefined)} className="!h-7 !text-xs">
          {TASK_PRIORITIES.map((p) => (
            <option key={p} value={p}>
              {PRIORITY_META[p].label}
            </option>
          ))}
        </Select>
      </Row>
      <Row label="Severity">
        <Select
          aria-label="Severity"
          value={task.severity ?? ""}
          disabled={!canWrite}
          onChange={(e) => void save({ severity: (e.target.value || null) as Severity | null }, "Severity").catch(() => undefined)}
          className="!h-7 !text-xs"
        >
          <option value="">Not set</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_META[s].label}
            </option>
          ))}
        </Select>
      </Row>
      <Row label="Assignees">{personList("assignee", "Unassigned")}</Row>
      <Row label="Reviewers">{personList("reviewer", "No reviewer")}</Row>
      <Row label="Labels">
        <OptionPicker
          trigger={
            <button type="button" className={PICKER_TRIGGER} disabled={!canWrite} aria-label="Change labels">
              {task.labels.length === 0 ? <span className="text-fg-faint">No labels</span> : task.labels.map((l) => <LabelChip key={l.id} label={l} />)}
            </button>
          }
          ariaLabel="Search or create labels"
          multiple
          options={(labels.data ?? []).map((l) => ({ value: l.id, label: l.name, hint: `${l.task_count}` }))}
          selected={task.labels.map((l) => l.id)}
          onSelect={toggleLabel}
          loading={labels.isLoading}
          createNoun="label"
          onCreate={async (name) => {
            try {
              const label = await createLabel.mutateAsync({ name });
              await save({ label_ids: [...task.labels.map((l) => l.id), label.id] }, "Labels");
            } catch (error) {
              toast.error("Label not created", describeError(error));
            }
          }}
          disabled={!canWrite}
        />
      </Row>
      <Row label="Due date">
        <span className="flex items-center gap-1">
          <input
            type="date"
            aria-label="Due date"
            value={dueValue}
            disabled={!canWrite}
            onChange={(e) => void save({ due_date: e.target.value ? dueIso(e.target.value) : null }, "Due date").catch(() => undefined)}
            className={`h-7 rounded border border-border-strong bg-surface-2 px-2 text-xs focus:border-accent/60 focus:outline-none [color-scheme:dark] ${task.is_overdue ? "text-danger" : "text-fg"}`}
          />
          {task.due_date && canWrite && (
            <button type="button" onClick={() => void save({ due_date: null }, "Due date").catch(() => undefined)} className="rounded p-1 text-fg-faint hover:bg-surface-2 hover:text-fg" aria-label="Clear due date">
              <X className="h-3.5 w-3.5" aria-hidden />
            </button>
          )}
        </span>
        {task.is_overdue && <div className="mt-1 text-2xs text-danger">Overdue</div>}
      </Row>
      <Row label="Parent">
        <span className="flex items-center gap-1">
          {task.parent ? <TaskKeyLink task={task.parent} /> : <span className="text-fg-faint">None</span>}
          {task.parent && <span className="min-w-0 truncate text-xs text-fg-muted">{task.parent.title}</span>}
          {canWrite && (
            <TaskSearchPicker
              trigger={
                <button type="button" className="ml-auto rounded p-1 text-fg-faint hover:bg-surface-2 hover:text-fg" aria-label="Choose parent task" title="Choose parent task">
                  <ChevronDown className="h-3.5 w-3.5" aria-hidden />
                </button>
              }
              ariaLabel="Search for a parent task"
              exclude={[task.id, ...task.subtasks.map((s) => s.id)]}
              onSelect={(id) => void save({ parent_task_id: id }, "Parent").catch(() => undefined)}
            />
          )}
          {canWrite && task.parent && (
            <button type="button" onClick={() => void save({ parent_task_id: null }, "Parent").catch(() => undefined)} className="rounded p-1 text-fg-faint hover:bg-surface-2 hover:text-fg" aria-label="Remove parent task">
              <X className="h-3.5 w-3.5" aria-hidden />
            </button>
          )}
        </span>
      </Row>
      {(task.related_finding_id || task.related_incident_id || task.related_agent_id) && (
        <Row label="Raised for">
          <div className="flex flex-col gap-1">
            {task.related_finding_id && <EntityLink type="finding" id={task.related_finding_id} />}
            {task.related_incident_id && <EntityLink type="incident" id={task.related_incident_id} />}
            {task.related_agent_id && <EntityLink type="agent" id={task.related_agent_id} />}
          </div>
        </Row>
      )}
      <Row label="Reporter">{task.reporter?.name ?? <span className="text-fg-muted">ContextOS (system)</span>}</Row>
      <Row label="Created">
        <time dateTime={task.created_at} title={formatDateTime(task.created_at)} className="text-xs text-fg-muted">
          {timeAgo(task.created_at)}
        </time>
      </Row>
      <Row label="Updated">
        <time dateTime={task.updated_at} title={formatDateTime(task.updated_at)} className="text-xs text-fg-muted">
          {timeAgo(task.updated_at)}
        </time>
      </Row>
      {(task.completed_at || task.reopened_count > 0) && (
        <Row label="Completed">
          <span className="text-xs text-fg-muted">
            {task.completed_at ? timeAgo(task.completed_at) : "Not completed"}
            {task.reopened_count > 0 && ` · reopened ${task.reopened_count}×`}
          </span>
        </Row>
      )}
    </dl>
  );
}
