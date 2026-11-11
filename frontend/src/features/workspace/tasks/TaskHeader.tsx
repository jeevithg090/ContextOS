/** Task header: key, inline-editable title, status line and the primary actions. */
import { useState } from "react";
import { Link } from "react-router-dom";
import { Archive, ArchiveRestore, Ban, FileText, ListTree, Sparkles } from "lucide-react";
import { ConfirmDialog, CopyButton } from "@/components/data";
import { Badge, Button, SeverityBadge, useToast } from "@/components/ui";
import { pluralize, shortId } from "@/lib/format";
import { taskTypeLabel } from "../analytics/taskMeta";
import { useArchiveTask } from "../api";
import type { TaskDetail } from "../types";
import { BreakdownDialog } from "./BreakdownDialog";
import { InlineTitle } from "./fields/InlineEditors";
import { describeError, useSaveTask } from "./hooks";
import { PriorityIcon, VerificationStatusBadge } from "./taskBits";

/** Same look as the primary small Button, for actions that navigate (real links: middle-click works). */
const PRIMARY_LINK =
  "inline-flex h-7 select-none items-center justify-center gap-1.5 whitespace-nowrap rounded bg-accent px-2.5 text-xs font-medium text-accent-fg transition-colors hover:bg-accent-strong";

/** Saved-prompt detail in the Prompt Library (opens the prompt drawer on the "Saved prompts" tab). */
export const savedPromptHref = (promptId: string) => `/work/prompts?tab=prompts&prompt=${encodeURIComponent(promptId)}`;
export const fixContextHref = (taskId: string) => `/work/fix-context/${encodeURIComponent(taskId)}`;
const PROMPTS_SHOWN = 5;

function GeneratedPrompts({ task }: { task: TaskDetail }) {
  const ids = task.generated_prompt_ids;
  if (ids.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-muted">
      <span className="inline-flex items-center gap-1">
        <FileText className="h-3.5 w-3.5 text-fg-faint" aria-hidden />
        {pluralize(ids.length, "saved fix prompt")}:
      </span>
      {ids.slice(0, PROMPTS_SHOWN).map((id) => (
        <Link key={id} to={savedPromptHref(id)} className="font-mono text-accent hover:underline" aria-label={`Open saved prompt ${id}`}>
          {shortId(id)}
        </Link>
      ))}
      {ids.length > PROMPTS_SHOWN && (
        <Link to={`/work/prompts?tab=prompts&task=${encodeURIComponent(task.id)}`} className="text-accent hover:underline">
          all {ids.length}
        </Link>
      )}
    </div>
  );
}

export function TaskHeader({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
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
        <Link to={fixContextHref(task.id)} className={PRIMARY_LINK}>
          <Sparkles className="h-3.5 w-3.5" aria-hidden />
          Generate Fix Context
        </Link>
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

      <GeneratedPrompts task={task} />

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
