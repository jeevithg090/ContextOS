/** Task header: key, inline-editable title, status line and the primary actions. */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Archive, ArchiveRestore, Ban, ListTree, Sparkles } from "lucide-react";
import { ConfirmDialog, CopyButton } from "@/components/data";
import { Badge, Button, SeverityBadge, useToast } from "@/components/ui";
import { pluralize } from "@/lib/format";
import { taskTypeLabel } from "../analytics/taskMeta";
import { useArchiveTask } from "../api";
import type { TaskDetail } from "../types";
import { BreakdownDialog } from "./BreakdownDialog";
import { InlineTitle } from "./fields/InlineEditors";
import { describeError, useSaveTask } from "./hooks";
import { PriorityIcon, VerificationStatusBadge } from "./taskBits";

export function TaskHeader({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const navigate = useNavigate();
  const toast = useToast();
  const { save, pending } = useSaveTask(task.id);
  const archive = useArchiveTask();
  const [breakingDown, setBreakingDown] = useState(false);
  const [confirmArchive, setConfirmArchive] = useState(false);
  const archived = task.archived_at !== null;
  const editable = canWrite && !archived;
  const taskUrl = `${window.location.origin}/work/tasks/${encodeURIComponent(task.id)}`;

  return (
    <header className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-fg-muted">
        <span className="inline-flex items-center gap-1 font-mono text-fg">
          {task.key}
          <CopyButton value={taskUrl} label="Copy link to task" />
        </span>
        <span aria-hidden>·</span>
        <span>{task.board_name}</span>
        <span aria-hidden>/</span>
        <span className="text-fg">{task.column_name}</span>
        <span aria-hidden>·</span>
        <PriorityIcon priority={task.priority} />
        <span>{taskTypeLabel(task.task_type)}</span>
        {task.severity && <SeverityBadge severity={task.severity} />}
        <VerificationStatusBadge status={task.verification_status} />
        {task.is_done && <Badge tone="ok">Done</Badge>}
        {archived && <Badge tone="warn">Archived</Badge>}
      </div>

      <InlineTitle value={task.title} canEdit={editable} onSave={(title) => save({ title }, "Title")} />

      {task.blocked_by_open > 0 && (
        <p className="flex items-center gap-1.5 text-xs text-danger">
          <Ban className="h-3.5 w-3.5" aria-hidden />
          Blocked by {pluralize(task.blocked_by_open, "open task")}.
        </p>
      )}
      {archived && <p className="text-xs text-warn">This task is archived: it is hidden from boards and cannot take new evidence until restored.</p>}

      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="primary" icon={<Sparkles className="h-3.5 w-3.5" aria-hidden />} onClick={() => navigate(`/work/fix-context/${encodeURIComponent(task.id)}`)}>
          Generate Fix Context
        </Button>
        {editable && (
          <Button size="sm" variant="secondary" icon={<ListTree className="h-3.5 w-3.5" aria-hidden />} onClick={() => setBreakingDown(true)}>
            Break down
          </Button>
        )}
        {canWrite &&
          (archived ? (
            <Button size="sm" variant="ghost" icon={<ArchiveRestore className="h-3.5 w-3.5" aria-hidden />} loading={pending} onClick={() => void save({ archived: false }, "Restore").then(() => toast.success(`${task.key} restored`), () => undefined)}>
              Restore
            </Button>
          ) : (
            <Button size="sm" variant="ghost" icon={<Archive className="h-3.5 w-3.5" aria-hidden />} onClick={() => setConfirmArchive(true)}>
              Archive
            </Button>
          ))}
      </div>

      <BreakdownDialog task={task} open={breakingDown} onOpenChange={setBreakingDown} />
      <ConfirmDialog
        open={confirmArchive}
        onOpenChange={setConfirmArchive}
        title={`Archive ${task.key}?`}
        description="Archived tasks leave the board but keep their history, evidence and links. You can restore them later."
        confirmLabel="Archive task"
        onConfirm={async () => {
          try {
            await archive.mutateAsync(task.id);
            toast.success(`${task.key} archived`);
          } catch (error) {
            throw new Error(describeError(error));
          }
        }}
      />
    </header>
  );
}
