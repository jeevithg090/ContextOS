/** Delete a column. A non-empty column needs a target column for its tasks (the server enforces it). */
import { useId, useMemo, useState } from "react";
import { ConfirmDialog } from "@/components/data";
import { Checkbox, Field, Select, useToast } from "@/components/ui";
import { pluralize } from "@/lib/format";
import { useDeleteColumn } from "../api";
import type { Column } from "../types";

export interface DeleteColumnDialogProps {
  boardId: string;
  column: Column;
  columns: Column[];
  onClose: () => void;
}

export function DeleteColumnDialog({ boardId, column, columns, onClose }: DeleteColumnDialogProps) {
  const selectId = useId();
  const toast = useToast();
  const remove = useDeleteColumn();
  const others = useMemo(() => columns.filter((c) => c.id !== column.id).sort((a, b) => a.position - b.position), [columns, column.id]);
  const [target, setTarget] = useState(others[0]?.id ?? "");
  const [overrideWip, setOverrideWip] = useState(false);
  const nonEmpty = column.task_count > 0;
  const targetColumn = others.find((c) => c.id === target);

  return (
    <ConfirmDialog
      open
      onOpenChange={(open) => !open && onClose()}
      destructive
      title={`Delete column “${column.name}”?`}
      description={nonEmpty ? `It holds ${pluralize(column.task_count, "task")}. Choose where they go.` : "The column is empty."}
      confirmLabel={nonEmpty ? "Move tasks and delete" : "Delete column"}
      onConfirm={async () => {
        const result = await remove.mutateAsync({ boardId, columnId: column.id, moveTo: nonEmpty ? target : undefined, overrideWip: nonEmpty && overrideWip });
        const moved = result.moved_task_count > 0 ? ` ${pluralize(result.moved_task_count, "task")} moved to “${targetColumn?.name ?? "another column"}”.` : "";
        const rules = result.removed_automation_rules > 0 ? ` ${pluralize(result.removed_automation_rules, "automation rule")} that targeted it ${result.removed_automation_rules === 1 ? "was" : "were"} removed.` : "";
        toast.success(`Column “${column.name}” deleted`, `${moved}${rules}`.trim() || undefined);
      }}
    >
      {nonEmpty && (
        <div className="space-y-3">
          <Field label="Move its tasks to" htmlFor={selectId}>
            <Select id={selectId} value={target} onChange={(e) => setTarget(e.target.value)}>
              {others.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                  {c.wip_limit !== null ? ` (${c.task_count}/${c.wip_limit})` : ""}
                  {c.requires_verification ? " — requires verification" : ""}
                </option>
              ))}
            </Select>
          </Field>
          {targetColumn?.wip_limit != null && (
            <Checkbox label={`Allow “${targetColumn.name}” to go over its WIP limit of ${targetColumn.wip_limit}`} checked={overrideWip} onChange={setOverrideWip} />
          )}
          <p className="text-xs">Tasks keep their history; each move is recorded in its activity. Verification gates on the target column still apply.</p>
        </div>
      )}
      <p className="text-xs">Automation rules in other columns that move tasks here are removed. This cannot be undone.</p>
    </ConfirmDialog>
  );
}
