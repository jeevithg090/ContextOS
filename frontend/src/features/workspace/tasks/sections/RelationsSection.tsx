/** Subtasks and dependencies (blocked by / blocking / related), with the blocked state explained. */
import { useState, type FormEvent, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Ban, CheckCircle2, Circle, Link2, Plus, Unlink } from "lucide-react";
import { Section } from "@/components/data";
import { Badge, Button, IconButton, Input, useToast } from "@/components/ui";
import { pluralize } from "@/lib/format";
import { statusKeyLabel, TaskKeyLink } from "../../analytics/taskMeta";
import { useAddDependency, useCreateTask, useRemoveDependency, workspaceKeys } from "../../api";
import type { DependencyKind, TaskBrief, TaskDependency, TaskDetail } from "../../types";
import { describeError, useSaveTask } from "../hooks";
import { TaskSearchPicker } from "../pickers/TaskSearchPicker";

function BriefRow({ brief, trailing }: { brief: TaskBrief; trailing?: ReactNode }) {
  return (
    <li className="group flex items-center gap-2 rounded px-1 py-1 hover:bg-surface-2">
      {brief.is_done ? <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-ok" aria-label="Done" /> : <Circle className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-label="Open" />}
      <TaskKeyLink task={brief} />
      <span className={`min-w-0 flex-1 truncate text-[13px] ${brief.is_done ? "text-fg-muted" : "text-fg"}`}>{brief.title}</span>
      {brief.archived ? <Badge>Archived</Badge> : <span className="shrink-0 text-2xs text-fg-faint">{brief.is_done ? "Done" : statusKeyLabel(brief.status_key)}</span>}
      {trailing}
    </li>
  );
}

function Subtasks({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const toast = useToast();
  const qc = useQueryClient();
  const create = useCreateTask();
  const [title, setTitle] = useState("");
  const done = task.subtasks.filter((s) => s.is_done).length;

  const add = (e: FormEvent) => {
    e.preventDefault();
    const text = title.trim();
    if (!text) return;
    create.mutate(
      { title: text, board_id: task.board_id, parent_task_id: task.id, task_type: task.task_type, priority: task.priority },
      {
        onSuccess: (sub) => {
          setTitle("");
          toast.success(`${sub.key} added as a subtask`, `In “${sub.column_name}”.`);
          void qc.invalidateQueries({ queryKey: workspaceKeys.task(task.id) });
        },
        onError: (err) => toast.error("Subtask not created", describeError(err)),
      },
    );
  };

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="text-xs font-medium text-fg-muted">Subtasks</div>
        {task.subtasks.length > 0 && <span className="num text-2xs text-fg-faint">{done}/{task.subtasks.length} done</span>}
      </div>
      {task.subtasks.length === 0 && <p className="text-xs text-fg-faint">No subtasks. Use “Break down” to draft them from the task, or add one here.</p>}
      <ul>
        {task.subtasks.map((s) => (
          <SubtaskRow key={s.id} parentId={task.id} brief={s} canWrite={canWrite} />
        ))}
      </ul>
      {canWrite && (
        <form onSubmit={add} className="flex gap-1.5">
          <Input value={title} maxLength={300} onChange={(e) => setTitle(e.target.value)} placeholder="New subtask title" aria-label="New subtask title" className="!h-7 !text-xs" />
          <Button size="sm" type="submit" icon={<Plus className="h-3 w-3" aria-hidden />} disabled={!title.trim()} loading={create.isPending}>
            Add
          </Button>
        </form>
      )}
    </div>
  );
}

function SubtaskRow({ parentId, brief, canWrite }: { parentId: string; brief: TaskBrief; canWrite: boolean }) {
  const qc = useQueryClient();
  const { save, pending } = useSaveTask(brief.id);
  const detach = () =>
    void save({ parent_task_id: null }, "Subtask").then(() => qc.invalidateQueries({ queryKey: workspaceKeys.task(parentId) }), () => undefined);
  return (
    <BriefRow
      brief={brief}
      trailing={
        canWrite && (
          <IconButton label={`Detach ${brief.key} from this task`} className="h-6 w-6 opacity-0 group-hover:opacity-100 focus:opacity-100" onClick={detach} disabled={pending}>
            <Unlink className="h-3 w-3" aria-hidden />
          </IconButton>
        )
      }
    />
  );
}

function DependencyList({ title, deps, empty, canWrite, onRemove }: { title: string; deps: TaskDependency[]; empty: string; canWrite: boolean; onRemove: (d: TaskDependency) => void }) {
  return (
    <div className="space-y-1">
      <div className="text-xs font-medium text-fg-muted">{title}</div>
      {deps.length === 0 ? (
        <p className="text-xs text-fg-faint">{empty}</p>
      ) : (
        <ul>
          {deps.map((d) => (
            <BriefRow
              key={d.id}
              brief={d.task}
              trailing={
                <>
                  {d.kind === "relates_to" && <Badge>Related</Badge>}
                  {canWrite && (
                    <IconButton label={`Remove dependency on ${d.task.key}`} className="h-6 w-6 opacity-0 group-hover:opacity-100 focus:opacity-100" onClick={() => onRemove(d)}>
                      <Unlink className="h-3 w-3" aria-hidden />
                    </IconButton>
                  )}
                </>
              }
            />
          ))}
        </ul>
      )}
    </div>
  );
}

export function RelationsSection({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const toast = useToast();
  const qc = useQueryClient();
  const addDep = useAddDependency();
  const removeDep = useRemoveDependency();
  const openBlockers = task.blocked_by.filter((d) => d.kind === "blocks" && !d.task.is_done && !d.task.archived);
  const related = [...task.blocked_by, ...task.blocking].filter((d) => d.kind === "relates_to");
  const exclude = [task.id, ...task.blocked_by.map((d) => d.task.id), ...task.blocking.map((d) => d.task.id)];

  const refresh = () => void qc.invalidateQueries({ queryKey: workspaceKeys.task(task.id) });
  const link = (taskId: string, dependsOnTaskId: string, kind: DependencyKind, success: string) =>
    addDep.mutate(
      { taskId, dependsOnTaskId, kind },
      {
        onSuccess: () => {
          toast.success(success);
          refresh();
        },
        onError: (e) => toast.error("Dependency not added", describeError(e)),
      },
    );
  const unlink = (d: TaskDependency) =>
    removeDep.mutate(
      { taskId: d.task_id, dependencyId: d.id },
      {
        onSuccess: () => {
          toast.success(`Dependency on ${d.task.key} removed`);
          refresh();
        },
        onError: (e) => toast.error("Dependency not removed", describeError(e)),
      },
    );

  const addButton = (label: string) => (
    <Button size="xs" variant="outline" icon={<Link2 className="h-3 w-3" aria-hidden />}>
      {label}
    </Button>
  );

  return (
    <Section
      title="Subtasks & dependencies"
      description="“Blocked by” tasks should be finished first. The blocked state is shown on the card and here; it does not stop the task from being moved."
      bodyClassName="space-y-4"
    >
      {openBlockers.length > 0 && (
        <div role="status" className="flex items-start gap-2 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-fg">
          <Ban className="mt-0.5 h-3.5 w-3.5 shrink-0 text-danger" aria-hidden />
          <span>
            Blocked by {pluralize(openBlockers.length, "open task")}: {openBlockers.map((d) => d.task.key).join(", ")}. Finish {openBlockers.length === 1 ? "it" : "them"} before starting this work.
          </span>
        </div>
      )}
      <Subtasks task={task} canWrite={canWrite} />
      <div className="grid gap-4 md:grid-cols-2">
        <DependencyList title="Blocked by" deps={task.blocked_by.filter((d) => d.kind === "blocks")} empty="Nothing blocks this task." canWrite={canWrite} onRemove={unlink} />
        <DependencyList title="Blocking" deps={task.blocking.filter((d) => d.kind === "blocks")} empty="No task waits on this one." canWrite={canWrite} onRemove={unlink} />
      </div>
      {related.length > 0 && <DependencyList title="Related" deps={related} empty="" canWrite={canWrite} onRemove={unlink} />}
      {canWrite && (
        <div className="flex flex-wrap gap-2 border-t border-border pt-3">
          <TaskSearchPicker trigger={addButton("Blocked by…")} ariaLabel="Search for a task that blocks this one" exclude={exclude} onSelect={(id) => link(task.id, id, "blocks", "Blocker added")} />
          <TaskSearchPicker trigger={addButton("Blocks…")} ariaLabel="Search for a task this one blocks" exclude={exclude} onSelect={(id) => link(id, task.id, "blocks", "Blocked task added")} />
          <TaskSearchPicker trigger={addButton("Related to…")} ariaLabel="Search for a related task" exclude={exclude} onSelect={(id) => link(task.id, id, "relates_to", "Related task linked")} />
        </div>
      )}
    </Section>
  );
}
