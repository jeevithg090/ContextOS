import { useId, useMemo, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { Button, Checkbox, Dialog, Field, Input, Select, useToast } from "@/components/ui";
import { useBoard, useBoards, useCreateTask, validationErrors, workflowConflict } from "../api";
import { TASK_PRIORITIES, TASK_TYPES, type TaskPriority, type TaskType } from "../types";
import { PRIORITY_META, TASK_TYPE_LABELS } from "./taskMeta";

export interface CreateTaskDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Pre-selected board (e.g. the list's board filter); defaults to the organisation's default board. */
  boardId?: string;
  /**
   * Called with the new task's id after it is created (e.g. a board opens it in its drawer). When
   * omitted, the dialog navigates to the task page.
   */
  onCreated?: (taskId: string) => void;
}

/** Create a task with the essentials, then continue on the task page (or the caller's view) to add detail. */
export function CreateTaskDialog(props: CreateTaskDialogProps) {
  // Mounted only while open, so every opening starts from a clean form and mutation state.
  return props.open ? <CreateTaskDialogBody {...props} /> : null;
}

function CreateTaskDialogBody({ open, onOpenChange, boardId, onCreated }: CreateTaskDialogProps) {
  const ids = { board: useId(), column: useId(), title: useId(), type: useId(), priority: useId() };
  const navigate = useNavigate();
  const toast = useToast();
  const boards = useBoards();
  const create = useCreateTask();
  const [board, setBoard] = useState("");
  const [column, setColumn] = useState("");
  const [title, setTitle] = useState("");
  const [taskType, setTaskType] = useState<TaskType | "">("");
  const [priority, setPriority] = useState<TaskPriority>("medium");
  const [overrideWip, setOverrideWip] = useState(false);

  const fallbackBoard = useMemo(() => {
    const items = boards.data?.items ?? [];
    return (boardId && items.find((b) => b.id === boardId)?.id) || items.find((b) => b.is_default)?.id || items[0]?.id || "";
  }, [boards.data, boardId]);
  const selectedBoard = board || fallbackBoard;
  const detail = useBoard(selectedBoard || null);
  const columns = useMemo(() => [...(detail.data?.columns ?? [])].sort((a, b) => a.position - b.position), [detail.data]);
  const selectedColumn = columns.some((c) => c.id === column) ? column : (columns[0]?.id ?? "");
  const defaultType = (detail.data?.config.default_task_type ?? "task") as TaskType;

  const conflict = workflowConflict(create.error);
  const errors = validationErrors(create.error);
  const otherError = create.error && !conflict && errors.length === 0 ? (create.error as Error).message : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !selectedBoard || !selectedColumn) return;
    create.mutate(
      {
        title: title.trim(),
        board_id: selectedBoard,
        column_id: selectedColumn,
        task_type: taskType || defaultType,
        priority,
        override_wip: overrideWip,
      },
      {
        onSuccess: (task) => {
          toast.success(`${task.key} created`, `${task.board_name} · ${task.column_name}`);
          onOpenChange(false);
          if (onCreated) onCreated(task.id);
          else navigate(`/work/tasks/${encodeURIComponent(task.id)}`);
        },
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !create.isPending && onOpenChange(next)}
      title="Create task"
      description="Add the essentials now; description, acceptance criteria and evidence are added on the task page."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="create-task-form" loading={create.isPending} disabled={!title.trim() || !selectedColumn}>
            Create task
          </Button>
        </>
      }
    >
      <form id="create-task-form" onSubmit={submit} className="space-y-4">
        <Field label="Title" htmlFor={ids.title}>
          <Input id={ids.title} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={400} required autoFocus placeholder="What needs to be done?" />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Board" htmlFor={ids.board}>
            <Select
              id={ids.board}
              value={selectedBoard}
              disabled={boards.isLoading}
              onChange={(e) => {
                setBoard(e.target.value);
                setColumn("");
              }}
            >
              {(boards.data?.items ?? []).map((b) => (
                <option key={b.id} value={b.id}>
                  {b.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Column" htmlFor={ids.column} hint={detail.isLoading ? "Loading columns…" : undefined}>
            <Select id={ids.column} value={selectedColumn} disabled={!columns.length} onChange={(e) => setColumn(e.target.value)}>
              {columns.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                  {c.wip_limit !== null ? ` (${c.task_count}/${c.wip_limit})` : ""}
                  {c.requires_verification ? " — needs verification" : ""}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Type" htmlFor={ids.type}>
            <Select id={ids.type} value={taskType || defaultType} onChange={(e) => setTaskType(e.target.value as TaskType)}>
              {TASK_TYPES.map((t) => (
                <option key={t} value={t}>
                  {TASK_TYPE_LABELS[t]}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Priority" htmlFor={ids.priority}>
            <Select id={ids.priority} value={priority} onChange={(e) => setPriority(e.target.value as TaskPriority)}>
              {TASK_PRIORITIES.map((p) => (
                <option key={p} value={p}>
                  {PRIORITY_META[p].label}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        {(conflict || errors.length > 0 || otherError) && (
          <div role="alert" className="flex gap-2 rounded border border-danger/30 bg-danger/10 p-3 text-xs text-fg">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-danger" aria-hidden />
            <div className="space-y-2">
              {conflict && <p>{conflict.message}</p>}
              {errors.map((msg) => (
                <p key={msg}>{msg}</p>
              ))}
              {otherError && <p>{otherError}</p>}
              {conflict?.reason === "wip_limit_exceeded" && (
                <Checkbox label="Create it anyway and record the WIP override on the task" checked={overrideWip} onChange={setOverrideWip} />
              )}
            </div>
          </div>
        )}
      </form>
    </Dialog>
  );
}
