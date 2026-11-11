/**
 * Remediation work for a finding: tasks in the Engineering Workspace that reference it, and the
 * "Create remediation task" action (POST /workspace/tasks/from-finding). The workspace returns the
 * existing open task instead of creating a duplicate; either way we navigate to it.
 */
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ClipboardList } from "lucide-react";
import { Badge, Button, useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { humanize } from "@/lib/domain";
import { useCreateRemediationTask } from "../api";
import type { FindingDetail } from "../types";

function createError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 404) return "The task could not be created: this finding or the Engineering Workspace was not found. Reload the page and try again.";
    if (err.status === 409) return err.message || "A conflicting task already exists for this finding.";
    if (err.status === 403) return "You do not have permission to create tasks.";
    return err.message;
  }
  return "The task could not be created. Try again.";
}

export function TasksPanel({ finding, canWrite }: { finding: FindingDetail; canWrite: boolean }) {
  const navigate = useNavigate();
  const toast = useToast();
  const create = useCreateRemediationTask();
  const [error, setError] = useState<string | null>(null);
  const tasks = finding.related.tasks;
  const openTask = tasks.find((t) => !t.done && !t.archived);

  const onCreate = () => {
    setError(null);
    create.mutate(finding.id, {
      onSuccess: (result) => {
        if (!result.created) toast.success(`${result.task.key} already tracks this finding`, "Opening the existing task.");
        else toast.success(`Created ${result.task.key}`, result.task.title);
        navigate(`/work/tasks/${encodeURIComponent(result.task.id)}`);
      },
      onError: (err) => setError(createError(err)),
    });
  };

  return (
    <div className="space-y-3">
      {tasks.length === 0 ? (
        <p className="text-xs text-fg-muted">No remediation task yet. A task carries this finding's evidence and acceptance criteria to whoever fixes it.</p>
      ) : (
        <ul className="divide-y divide-border rounded-md border border-border">
          {tasks.map((t) => (
            <li key={t.id}>
              <Link to={`/work/tasks/${encodeURIComponent(t.id)}`} className="flex items-center gap-2 px-3 py-2 transition-colors hover:bg-surface-2">
                <span className="num shrink-0 font-mono text-2xs text-fg-muted">{t.key}</span>
                <span className="min-w-0 flex-1 truncate text-xs text-fg" title={t.title}>
                  {t.title}
                </span>
                {t.archived ? <Badge tone="neutral">Archived</Badge> : t.done ? <Badge tone="ok">Done</Badge> : <Badge tone="accent">{t.column ?? "Open"}</Badge>}
                <span className="sr-only">priority {humanize(t.priority)}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      {canWrite &&
        (openTask ? (
          <Link
            to={`/work/tasks/${encodeURIComponent(openTask.id)}`}
            className="inline-flex h-7 items-center gap-1.5 rounded border border-border-strong px-2.5 text-xs text-fg transition-colors hover:bg-surface-2"
          >
            <ClipboardList className="h-3.5 w-3.5" aria-hidden /> Go to {openTask.key}
          </Link>
        ) : (
          <Button size="sm" variant="outline" icon={<ClipboardList className="h-3.5 w-3.5" aria-hidden />} onClick={onCreate} loading={create.isPending}>
            Create remediation task
          </Button>
        ))}
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
