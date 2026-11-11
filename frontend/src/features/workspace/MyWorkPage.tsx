import { useMemo } from "react";
import { Link } from "react-router-dom";
import { addDays, isBefore } from "date-fns";
import { CalendarClock, History, ListChecks } from "lucide-react";
import { InlineStat, Section } from "@/components/data";
import { EmptyState, ErrorState, LoadingRows, PageHeader } from "@/components/ui";
import { useTasks } from "./api";
import { STATUS_KEY_LABELS } from "./analytics/taskMeta";
import { TaskRowList } from "./analytics/TaskRowList";
import { STATUS_KEYS, type StatusKey, type TaskCard } from "./types";

const OPEN_LIMIT = 200;
const DUE_WINDOW_DAYS = 7;

/** "What am I working on?" — tasks assigned to me by stage, what is due, and what changed. */
export function MyWorkPage() {
  const open = useTasks({ assignee: "me", sort: "priority", limit: OPEN_LIMIT });
  const due = useTasks({ assignee: "me", sort: "due_date", limit: 50 });
  const recent = useTasks({ assignee: "me", include_done: true, sort: "updated", limit: 8 });

  const groups = useMemo(() => {
    const byKey = new Map<StatusKey, TaskCard[]>();
    for (const task of open.data?.items ?? []) byKey.set(task.status_key, [...(byKey.get(task.status_key) ?? []), task]);
    return STATUS_KEYS.filter((k) => byKey.has(k)).map((k) => ({ key: k, tasks: byKey.get(k)! }));
  }, [open.data]);

  const horizon = addDays(new Date(), DUE_WINDOW_DAYS);
  const dueSoon = (due.data?.items ?? []).filter((t) => t.due_date && isBefore(new Date(t.due_date), horizon));
  const overdue = dueSoon.filter((t) => t.is_overdue).length;
  const blocked = (open.data?.items ?? []).filter((t) => t.blocked_by_open > 0).length;
  const total = open.data?.total ?? 0;

  return (
    <>
      <PageHeader
        eyebrow="Engineering Workspace"
        title="My Work"
        description="Open tasks assigned to you, grouped by stage, with what is due this week and what changed most recently."
        actions={
          <Link to="/work/tasks?assignee=me" className="text-xs text-accent hover:text-accent-strong">
            Open in All Tasks
          </Link>
        }
      />
      {open.error && !open.data ? (
        <div className="panel">
          <ErrorState error={open.error} onRetry={() => void open.refetch()} />
        </div>
      ) : (
        <>
          <div className="panel mb-4 flex flex-wrap gap-x-8 gap-y-2 px-4 py-3" aria-busy={open.isLoading || undefined}>
            <InlineStat label="Assigned, open" value={open.isLoading ? "…" : total} hint="Tasks assigned to you that are not in a done column" />
            <InlineStat label="Overdue" value={due.isLoading ? "…" : overdue} tone={overdue ? "danger" : undefined} hint="Open tasks whose due date has passed" />
            <InlineStat label={`Due in ${DUE_WINDOW_DAYS} days`} value={due.isLoading ? "…" : dueSoon.length - overdue} hint="Open tasks due in the next week" />
            <InlineStat label="Blocked" value={open.isLoading ? "…" : blocked} tone={blocked ? "warn" : undefined} hint="Open tasks waiting on another open task" />
          </div>
          <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <div className="min-w-0 space-y-4">
              {open.isLoading ? (
                <div className="panel">
                  <LoadingRows rows={6} />
                </div>
              ) : groups.length === 0 ? (
                <div className="panel">
                  <EmptyState
                    icon={<ListChecks className="h-4 w-4" />}
                    title="Nothing open is assigned to you"
                    description="Pick up work from a board, or turn an untracked security finding into a task."
                    action={
                      <div className="flex gap-3 text-xs">
                        <Link to="/work/boards" className="text-accent hover:text-accent-strong">
                          Kanban boards
                        </Link>
                        <Link to="/work/remediation?state=no_task" className="text-accent hover:text-accent-strong">
                          Untracked findings
                        </Link>
                      </div>
                    }
                  />
                </div>
              ) : (
                groups.map((g) => (
                  <Section key={g.key} title={`${STATUS_KEY_LABELS[g.key]} · ${g.tasks.length}`} flush>
                    <TaskRowList tasks={g.tasks} aria-label={`${STATUS_KEY_LABELS[g.key]} tasks`} />
                  </Section>
                ))
              )}
              {total > OPEN_LIMIT && (
                <p className="text-xs text-fg-muted">
                  Showing the {OPEN_LIMIT} highest-priority of {total} tasks.{" "}
                  <Link to="/work/tasks?assignee=me&sort=priority" className="text-accent hover:text-accent-strong">
                    See all
                  </Link>
                </p>
              )}
            </div>
            <div className="min-w-0 space-y-4">
              <Section title="Due soon and overdue" description={`Due within ${DUE_WINDOW_DAYS} days, soonest first.`} flush>
                {due.isLoading ? (
                  <LoadingRows rows={3} />
                ) : due.error ? (
                  <ErrorState error={due.error} onRetry={() => void due.refetch()} />
                ) : dueSoon.length === 0 ? (
                  <EmptyState icon={<CalendarClock className="h-4 w-4" />} title="Nothing due this week" />
                ) : (
                  <TaskRowList tasks={dueSoon} compact aria-label="Tasks due soon" />
                )}
              </Section>
              <Section title="Recently updated" description="Your tasks, including done ones, by last change." flush>
                {recent.isLoading ? (
                  <LoadingRows rows={3} />
                ) : recent.error ? (
                  <ErrorState error={recent.error} onRetry={() => void recent.refetch()} />
                ) : (recent.data?.items ?? []).length === 0 ? (
                  <EmptyState icon={<History className="h-4 w-4" />} title="No recent activity on your tasks" />
                ) : (
                  <TaskRowList tasks={recent.data!.items} compact aria-label="Recently updated tasks" />
                )}
              </Section>
            </div>
          </div>
        </>
      )}
    </>
  );
}
