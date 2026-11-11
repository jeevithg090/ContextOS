/** Board settings: name, description, default task type, the fields shown on cards and the default board. */
import { useId, useState, type FormEvent } from "react";
import { Button, Checkbox, Dialog, Field, Input, Select, Textarea, useToast } from "@/components/ui";
import { TASK_TYPE_LABELS } from "../analytics/taskMeta";
import { useUpdateBoard, validationErrors } from "../api";
import { CARD_FIELDS, TASK_TYPES, type BoardDetail, type CardField, type TaskType } from "../types";
import { CARD_FIELD_LABELS, cardFields } from "./boardMeta";
import { errorMessage } from "../tasks/useWorkflowConflicts";

export function BoardSettingsDialog({ board, onClose }: { board: BoardDetail; onClose: () => void }) {
  const ids = { name: useId(), description: useId(), type: useId() };
  const toast = useToast();
  const update = useUpdateBoard();
  const [name, setName] = useState(board.name);
  const [description, setDescription] = useState(board.description ?? "");
  const [defaultType, setDefaultType] = useState<TaskType>(board.config.default_task_type ?? "task");
  const [fields, setFields] = useState<Set<CardField>>(() => cardFields(board.config));
  const [isDefault, setIsDefault] = useState(board.is_default);
  const errors = validationErrors(update.error);

  const toggleField = (field: CardField, on: boolean) =>
    setFields((prev) => {
      const next = new Set(prev);
      if (on) next.add(field);
      else next.delete(field);
      return next;
    });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    update.mutate(
      {
        boardId: board.id,
        patch: {
          name: name.trim(),
          description: description.trim() || null,
          ...(isDefault !== board.is_default && isDefault ? { is_default: true } : {}),
          config: { ...board.config, default_task_type: defaultType, card_fields: CARD_FIELDS.filter((f) => fields.has(f)) },
        },
      },
      {
        onSuccess: () => {
          toast.success("Board settings saved");
          onClose();
        },
      },
    );
  };

  return (
    <Dialog
      open
      onOpenChange={(open) => !open && !update.isPending && onClose()}
      title="Board settings"
      className="w-[min(600px,calc(100vw-32px))]"
      footer={
        <>
          <Button size="sm" variant="ghost" onClick={onClose} disabled={update.isPending}>
            Cancel
          </Button>
          <Button size="sm" variant="primary" type="submit" form="board-settings" loading={update.isPending} disabled={!name.trim()}>
            Save settings
          </Button>
        </>
      }
    >
      <form id="board-settings" onSubmit={submit} className="space-y-4">
        <Field label="Name" htmlFor={ids.name}>
          <Input id={ids.name} value={name} maxLength={200} onChange={(e) => setName(e.target.value)} required />
        </Field>
        <Field label="Description" htmlFor={ids.description}>
          <Textarea id={ids.description} value={description} rows={3} maxLength={2000} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Field label="Default type for new tasks" htmlFor={ids.type} hint="Used by quick-add on this board.">
          <Select id={ids.type} value={defaultType} onChange={(e) => setDefaultType(e.target.value as TaskType)}>
            {TASK_TYPES.map((t) => (
              <option key={t} value={t}>
                {TASK_TYPE_LABELS[t]}
              </option>
            ))}
          </Select>
        </Field>
        <fieldset className="space-y-2">
          <legend className="text-xs font-medium text-fg-muted">Shown on cards</legend>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
            {CARD_FIELDS.map((f) => (
              <Checkbox key={f} label={CARD_FIELD_LABELS[f]} checked={fields.has(f)} onChange={(on) => toggleField(f, on)} />
            ))}
          </div>
          <p className="text-2xs text-fg-faint">The title is always shown. Blocked markers always show, because hiding them would hide a real constraint.</p>
        </fieldset>
        <div className="space-y-1">
          <Checkbox label="Default board for new tasks" checked={isDefault} disabled={board.is_default} onChange={setIsDefault} />
          <p className="text-2xs text-fg-faint">
            {board.is_default ? "This is the default board. Make another board the default to change it." : "Tasks created without a board (for example from findings) land here."}
          </p>
        </div>
        {update.error && (
          <div role="alert" className="space-y-1 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {(errors.length > 0 ? errors : [errorMessage(update.error)]).map((m) => (
              <p key={m}>{m}</p>
            ))}
          </div>
        )}
      </form>
    </Dialog>
  );
}
