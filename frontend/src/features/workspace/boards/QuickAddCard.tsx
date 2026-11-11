/** Inline "Add task" at the bottom of a column. Enter creates and keeps the box open for the next one. */
import { useRef, useState } from "react";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui";
import { useCreateTask } from "../api";
import type { TaskType } from "../types";
import type { ConflictContext } from "../tasks/useWorkflowConflicts";

export interface QuickAddCardProps {
  boardId: string;
  columnId: string;
  columnName: string;
  defaultType: TaskType;
  onCreated: (taskKey: string) => void;
  onError: (error: unknown, ctx: ConflictContext) => void;
}

export function QuickAddCard({ boardId, columnId, columnName, defaultType, onCreated, onError }: QuickAddCardProps) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const create = useCreateTask();

  const submit = (overrideWip = false) => {
    const text = title.trim();
    if (!text || create.isPending) return Promise.resolve();
    const body = { title: text, board_id: boardId, column_id: columnId, task_type: defaultType, override_wip: overrideWip };
    return create.mutateAsync(body).then(
      (task) => {
        setTitle("");
        onCreated(task.key);
        inputRef.current?.focus();
      },
      (error: unknown) => {
        // A failed override retry is shown inside the override dialog itself.
        if (overrideWip) throw error;
        onError(error, { title: "Task not created", override: () => submit(true) });
      },
    );
  };

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="flex h-7 w-full items-center gap-1.5 rounded px-2 text-xs text-fg-faint transition-colors hover:bg-surface-2 hover:text-fg"
      >
        <Plus className="h-3.5 w-3.5" aria-hidden />
        Add task
      </button>
    );
  }

  return (
    <form
      className="rounded-md border border-accent/40 bg-surface-2 p-2"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <textarea
        ref={inputRef}
        autoFocus
        rows={2}
        value={title}
        maxLength={300}
        disabled={create.isPending}
        aria-label={`New task title in ${columnName}`}
        placeholder="Task title — Enter to add, Esc to close"
        onChange={(e) => setTitle(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            void submit();
          } else if (e.key === "Escape") {
            e.preventDefault();
            setOpen(false);
            setTitle("");
          }
        }}
        className="w-full resize-none bg-transparent text-[13px] text-fg placeholder:text-fg-faint focus:outline-none"
      />
      <div className="mt-1.5 flex items-center justify-end gap-1.5">
        <Button size="xs" variant="ghost" onClick={() => {
            setOpen(false);
            setTitle("");
          }} disabled={create.isPending}>
          Cancel
        </Button>
        <Button size="xs" variant="primary" type="submit" loading={create.isPending} disabled={!title.trim()}>
          Add
        </Button>
      </div>
    </form>
  );
}
