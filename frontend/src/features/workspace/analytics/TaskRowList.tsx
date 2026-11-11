import { Link } from "react-router-dom";
import { Ban } from "lucide-react";
import { SeverityBadge } from "@/components/ui";
import { cn, timeAgo } from "@/lib/format";
import { DueDate, PriorityBadge, VerificationBadge } from "./taskMeta";
import type { TaskCard } from "../types";

export interface TaskRowListProps {
  tasks: TaskCard[];
  /** Narrow layout for side panels: key, title and due date only. */
  compact?: boolean;
  "aria-label": string;
}

/** Compact, keyboard-navigable task rows; each row opens the task page. */
export function TaskRowList({ tasks, compact = false, "aria-label": ariaLabel }: TaskRowListProps) {
  return (
    <ul className="divide-y divide-border/70" aria-label={ariaLabel}>
      {tasks.map((task) => (
        <li key={task.id}>
          <Link
            to={`/work/tasks/${encodeURIComponent(task.id)}`}
            className="flex items-center gap-3 px-4 py-2 transition-colors hover:bg-surface-2/70 focus-visible:outline-offset-[-2px]"
          >
            <span className={cn("shrink-0 font-mono text-xs text-fg-muted", compact ? "w-[56px]" : "w-[68px]")}>{task.key}</span>
            <span className="min-w-0 flex-1">
              <span className={cn("flex min-w-0 items-center gap-2 text-[13px]", task.is_done ? "text-fg-muted" : "text-fg")}>
                <span className="truncate">{task.title}</span>
                {task.severity && !compact && <SeverityBadge severity={task.severity} />}
                {task.blocked_by_open > 0 && !compact && (
                  <span className="inline-flex shrink-0 items-center gap-1 text-2xs text-warn" title={`Blocked by ${task.blocked_by_open} open task(s)`}>
                    <Ban className="h-3 w-3" aria-hidden />
                    Blocked
                  </span>
                )}
              </span>
              <span className="mt-0.5 block truncate text-2xs text-fg-muted">
                {task.column_name} · updated {timeAgo(task.updated_at)}
              </span>
            </span>
            {!compact && (
              <span className="hidden shrink-0 sm:inline-flex">
                <PriorityBadge priority={task.priority} />
              </span>
            )}
            {!compact && task.verification_status !== "unverified" && (
              <span className="hidden shrink-0 md:inline-flex">
                <VerificationBadge status={task.verification_status} />
              </span>
            )}
            <span className="w-[72px] shrink-0 text-right">
              <DueDate due={task.due_date} done={task.is_done} overdue={task.is_overdue} />
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}
