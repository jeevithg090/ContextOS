/**
 * Add or edit a column: name, description, colour, status key, WIP limit, verification gate, done
 * flag and automation rules. The server validates the whole layout and its messages are shown as-is.
 */
import { useId, useMemo, useState, type FormEvent } from "react";
import { Plus, Trash2 } from "lucide-react";
import { Button, Checkbox, Dialog, Field, IconButton, Input, Select, Textarea } from "@/components/ui";
import { cn } from "@/lib/format";
import { useAddColumn, useUpdateColumn, validationErrors } from "../api";
import { COLUMN_COLORS, type AutomationRule, type AutomationTrigger, type Column, type StatusKey } from "../types";
import { COLUMN_COLOR_LABELS, columnAccent, isColumnColor } from "./boardMeta";
import { AUTOMATION_TRIGGERS, AUTOMATION_TRIGGER_META, STATUS_KEY_OPTIONS } from "./columnOptions";
import { errorMessage } from "../tasks/useWorkflowConflicts";

export interface ColumnSettingsDialogProps {
  boardId: string;
  /** Column being edited; null adds a new column at the end. */
  column: Column | null;
  columns: Column[];
  onClose: () => void;
  onSaved: (name: string, created: boolean) => void;
}

const HEX = /^#[0-9a-f]{6}$/i;

export function ColumnSettingsDialog({ boardId, column, columns, onClose, onSaved }: ColumnSettingsDialogProps) {
  const ids = { name: useId(), description: useId(), status: useId(), wip: useId(), hex: useId() };
  const add = useAddColumn();
  const update = useUpdateColumn();
  const mutation = column ? update : add;

  const [name, setName] = useState(column?.name ?? "");
  const [description, setDescription] = useState(column?.description ?? "");
  const [color, setColor] = useState(column?.color ?? "slate");
  const [statusKey, setStatusKey] = useState<StatusKey>(column?.status_key ?? "todo");
  const [wip, setWip] = useState(column?.wip_limit != null ? String(column.wip_limit) : "");
  const [requiresVerification, setRequiresVerification] = useState(column?.requires_verification ?? false);
  const [isDone, setIsDone] = useState(column?.is_done_column ?? false);
  const [rules, setRules] = useState<AutomationRule[]>(column?.automation ?? []);
  const [localError, setLocalError] = useState<string | null>(null);

  const otherColumns = useMemo(() => columns.filter((c) => c.id !== column?.id).sort((a, b) => a.position - b.position), [columns, column]);
  const unusedTriggers = AUTOMATION_TRIGGERS.filter((t) => !rules.some((r) => r.trigger === t));
  const serverErrors = validationErrors(mutation.error);
  const otherError = mutation.error && serverErrors.length === 0 ? errorMessage(mutation.error) : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    const wipLimit = wip.trim() === "" ? null : Number(wip);
    if (wipLimit !== null && (!Number.isInteger(wipLimit) || wipLimit < 1)) {
      setLocalError("The WIP limit must be a whole number of at least 1, or empty for no limit.");
      return;
    }
    if (!isColumnColor(color) && !HEX.test(color)) {
      setLocalError("Pick a colour swatch or enter a hex colour such as #3b82f6.");
      return;
    }
    if (rules.some((r) => !r.move_to_column_id)) {
      setLocalError("Every automation rule needs a target column.");
      return;
    }
    const body = {
      name: name.trim(),
      description: description.trim() || null,
      color,
      status_key: isDone ? ("done" as StatusKey) : statusKey,
      wip_limit: wipLimit,
      requires_verification: requiresVerification,
      is_done_column: isDone,
      automation: rules,
    };
    const done = () => {
      onSaved(body.name, !column);
      onClose();
    };
    if (column) update.mutate({ boardId, columnId: column.id, patch: body }, { onSuccess: done });
    else add.mutate({ boardId, column: body }, { onSuccess: done });
  };

  return (
    <Dialog
      open
      onOpenChange={(open) => !open && !mutation.isPending && onClose()}
      title={column ? `Edit column “${column.name}”` : "Add column"}
      description="Columns are workflow stages. The status key tells analytics what the stage means, whatever you call it."
      className="w-[min(620px,calc(100vw-32px))]"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose} disabled={mutation.isPending}>
            Cancel
          </Button>
          <Button variant="primary" size="sm" type="submit" form="column-settings" loading={mutation.isPending} disabled={!name.trim()}>
            {column ? "Save column" : "Add column"}
          </Button>
        </>
      }
    >
      <form id="column-settings" onSubmit={submit} className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-[1fr_180px]">
          <Field label="Name" htmlFor={ids.name}>
            <Input id={ids.name} value={name} maxLength={100} onChange={(e) => setName(e.target.value)} autoFocus required />
          </Field>
          <Field label="Status key" htmlFor={ids.status} hint={isDone ? "Done columns always use “Done”." : undefined}>
            <Select id={ids.status} value={isDone ? "done" : statusKey} disabled={isDone} onChange={(e) => setStatusKey(e.target.value as StatusKey)}>
              {STATUS_KEY_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </Field>
        </div>

        <Field label="Description" htmlFor={ids.description} hint="Shown under the column name: what belongs here and when work leaves.">
          <Textarea id={ids.description} value={description} maxLength={1000} rows={2} className="min-h-[56px]" onChange={(e) => setDescription(e.target.value)} />
        </Field>

        <fieldset className="space-y-1.5">
          <legend className="text-xs font-medium text-fg-muted">Colour</legend>
          <div className="flex flex-wrap items-center gap-1.5" role="radiogroup" aria-label="Column colour">
            {COLUMN_COLORS.map((token) => {
              const accent = columnAccent(token);
              const selected = color === token;
              return (
                <button
                  key={token}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  aria-label={COLUMN_COLOR_LABELS[token]}
                  title={COLUMN_COLOR_LABELS[token]}
                  onClick={() => setColor(token)}
                  className={cn("flex h-7 w-7 items-center justify-center rounded border", selected ? "border-accent bg-surface-3" : "border-border hover:border-border-strong")}
                >
                  <span className={cn("h-3 w-3 rounded-full", accent.dot)} aria-hidden />
                </button>
              );
            })}
            <label htmlFor={ids.hex} className="ml-2 text-2xs text-fg-faint">
              or hex
            </label>
            <Input id={ids.hex} value={isColumnColor(color) ? "" : color} placeholder="#3b82f6" maxLength={7} className="!h-7 !w-24 font-mono !text-xs" onChange={(e) => setColor(e.target.value.trim() || "slate")} />
          </div>
        </fieldset>

        <div className="grid gap-3 sm:grid-cols-[180px_1fr]">
          <Field label="WIP limit" htmlFor={ids.wip} hint="Empty means no limit.">
            <Input id={ids.wip} type="number" min={1} step={1} inputMode="numeric" value={wip} onChange={(e) => setWip(e.target.value)} />
          </Field>
          <div className="space-y-2 pt-5">
            <Checkbox label="Requires passed verification to enter" checked={requiresVerification} onChange={setRequiresVerification} />
            <Checkbox label="Done column (tasks here count as completed)" checked={isDone} onChange={setIsDone} />
          </div>
        </div>
        {requiresVerification && (
          <p className="rounded border border-border bg-surface-2 px-3 py-2 text-2xs text-fg-muted">
            Tasks can enter only after a verification run (test run, review, simulation, replay, deployment or manual check) has passed. Done columns to the right of this one inherit
            the gate. A fix attempt marked “claimed complete” does not count.
          </p>
        )}

        <fieldset className="space-y-2">
          <legend className="text-xs font-medium text-fg-muted">Automation rules</legend>
          <p className="text-2xs text-fg-faint">Move tasks out of this column automatically. Automation never bypasses WIP limits or verification gates; a blocked rule is recorded on the task instead.</p>
          {rules.length === 0 && <p className="text-xs text-fg-muted">No rules.</p>}
          {rules.map((rule, i) => (
            <div key={rule.trigger} className="flex flex-wrap items-center gap-2">
              <Select
                aria-label={`Rule ${i + 1} trigger`}
                value={rule.trigger}
                className="!w-auto min-w-[200px]"
                onChange={(e) => setRules((all) => all.map((r, j) => (j === i ? { ...r, trigger: e.target.value as AutomationTrigger } : r)))}
                title={AUTOMATION_TRIGGER_META[rule.trigger]?.description}
              >
                {[rule.trigger, ...unusedTriggers].map((t) => (
                  <option key={t} value={t}>
                    When {AUTOMATION_TRIGGER_META[t].label.toLowerCase()}
                  </option>
                ))}
              </Select>
              <span className="text-xs text-fg-faint">move to</span>
              <Select
                aria-label={`Rule ${i + 1} target column`}
                value={rule.move_to_column_id}
                className="!w-auto min-w-[160px] flex-1"
                onChange={(e) => setRules((all) => all.map((r, j) => (j === i ? { ...r, move_to_column_id: e.target.value } : r)))}
              >
                <option value="">Choose a column…</option>
                {otherColumns.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </Select>
              <IconButton label={`Remove rule ${i + 1}`} onClick={() => setRules((all) => all.filter((_, j) => j !== i))}>
                <Trash2 className="h-3.5 w-3.5" aria-hidden />
              </IconButton>
            </div>
          ))}
          {unusedTriggers.length > 0 && otherColumns.length > 0 && (
            <Button size="xs" variant="ghost" icon={<Plus className="h-3 w-3" aria-hidden />} onClick={() => setRules((all) => [...all, { trigger: unusedTriggers[0], move_to_column_id: "" }])}>
              Add rule
            </Button>
          )}
        </fieldset>

        {(localError || serverErrors.length > 0 || otherError) && (
          <div role="alert" className="space-y-1 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {localError && <p>{localError}</p>}
            {serverErrors.map((m) => (
              <p key={m}>{m}</p>
            ))}
            {otherError && <p>{otherError}</p>}
          </div>
        )}
      </form>
    </Dialog>
  );
}
