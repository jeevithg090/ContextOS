import { useState } from "react";
import { Check, ClipboardList } from "lucide-react";
import { SearchInput } from "@/components/data";
import { Checkbox, EmptyState, ErrorState, LoadingRows, SeverityBadge } from "@/components/ui";
import { cn, timeAgo } from "@/lib/format";
import { useTasks } from "../api";
import { PriorityBadge, taskTypeLabel } from "../analytics/taskMeta";
import type { TaskCard } from "../types";

const PAGE = 25;

/**
 * Search tasks (GET /workspace/tasks?q=…) and pick one. Shows open tasks by default, most recently
 * updated first; "Include done" widens the search.
 */
export function TaskPicker({
  onSelect,
  selectedId,
  autoFocus = false,
  className,
  listClassName,
}: {
  onSelect: (task: TaskCard) => void;
  selectedId?: string | null;
  autoFocus?: boolean;
  className?: string;
  listClassName?: string;
}) {
  const [q, setQ] = useState("");
  const [includeDone, setIncludeDone] = useState(false);
  const query = useTasks({ q: q || undefined, include_done: includeDone, sort: "updated", limit: PAGE });
  const items = query.data?.items ?? [];
  const total = query.data?.total ?? 0;

  return (
    <div className={cn("flex min-h-0 flex-col", className)}>
      <div className="flex flex-wrap items-center gap-3 pb-3">
        <SearchInput value={q} onChange={setQ} placeholder="Search by title, description or key (CTX-12)…" label="Search tasks" className="max-w-md flex-1" autoFocus={autoFocus} shortcut={false} />
        <Checkbox label="Include done" checked={includeDone} onChange={setIncludeDone} />
        {query.data && (
          <span className="num ml-auto text-2xs text-fg-faint" aria-live="polite">
            {total > items.length ? `Showing ${items.length} of ${total}` : `${total} ${total === 1 ? "task" : "tasks"}`}
          </span>
        )}
      </div>
      {query.isLoading ? (
        <LoadingRows rows={5} />
      ) : query.error ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState
          icon={<ClipboardList className="h-4 w-4" />}
          title={q ? "No tasks match this search" : "No open tasks"}
          description={q ? "Try a different word or a task key such as CTX-12." : "Create a task on a board, or turn a finding into a remediation task first."}
        />
      ) : (
        <ul className={cn("min-h-0 divide-y divide-border/70 overflow-y-auto rounded-md border border-border", query.isPlaceholderData && "opacity-60", listClassName)} aria-label="Tasks">
          {items.map((task) => {
            const selected = task.id === selectedId;
            return (
              <li key={task.id}>
                <button
                  type="button"
                  onClick={() => onSelect(task)}
                  aria-pressed={selectedId !== undefined ? selected : undefined}
                  className={cn("flex w-full items-start gap-3 px-3 py-2.5 text-left transition-colors hover:bg-surface-2", selected && "bg-accent/[0.06]")}
                >
                  <span className="mt-0.5 w-16 shrink-0 font-mono text-xs text-fg-muted">{task.key}</span>
                  <span className="min-w-0 flex-1">
                    <span className="flex min-w-0 items-center gap-2">
                      <span className={cn("truncate text-[13px]", task.is_done ? "text-fg-muted" : "text-fg")}>{task.title}</span>
                      {task.severity && <SeverityBadge severity={task.severity} />}
                    </span>
                    <span className="mt-0.5 flex flex-wrap items-center gap-x-2 text-2xs text-fg-faint">
                      <span>{taskTypeLabel(task.task_type)}</span>
                      <span aria-hidden>·</span>
                      <span>{task.column_name}</span>
                      <span aria-hidden>·</span>
                      <span>updated {timeAgo(task.updated_at)}</span>
                    </span>
                  </span>
                  <PriorityBadge priority={task.priority} className="shrink-0" />
                  {selected && <Check className="mt-0.5 h-4 w-4 shrink-0 text-accent" aria-label="Selected" />}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
