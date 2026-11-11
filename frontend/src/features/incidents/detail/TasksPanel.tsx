/** Engineering Workspace tasks linked to the incident directly, by reference or through its findings. */
import { Link } from "react-router-dom";
import { CheckCircle2, Circle } from "lucide-react";
import { Badge, Mono } from "@/components/ui";
import type { LinkedTask } from "../types";

export function TasksPanel({ tasks }: { tasks: LinkedTask[] }) {
  if (tasks.length === 0) {
    return <p className="text-xs text-fg-muted">No remediation task yet. Create tasks to hand the open findings to engineering with their evidence attached.</p>;
  }
  const done = tasks.filter((t) => t.done).length;
  return (
    <div className="space-y-2">
      <p className="text-2xs text-fg-faint">
        {done} of {tasks.length} done
      </p>
      <ul className="space-y-1.5">
        {tasks.map((t) => (
          <li key={t.id} className="flex items-start gap-2">
            {t.done ? <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ok" aria-label="Done" /> : <Circle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint" aria-label="Not done" />}
            <div className="min-w-0 flex-1">
              <Link to={`/work/tasks/${encodeURIComponent(t.id)}`} className="text-[13px] text-fg hover:text-accent hover:underline">
                <Mono className="mr-1.5 text-2xs text-fg-faint">{t.key}</Mono>
                <span className={t.done ? "text-fg-muted line-through decoration-fg-faint" : undefined}>{t.title}</span>
              </Link>
              <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-2xs text-fg-faint">
                {t.column && <span>{t.column}</span>}
                <span>· {t.priority} priority</span>
                {t.parent_task_id === null && !t.related_finding_id && <Badge tone="neutral">Incident task</Badge>}
                {t.archived && <Badge tone="neutral">Archived</Badge>}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
