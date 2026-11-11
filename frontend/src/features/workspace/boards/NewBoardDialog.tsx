/** Create a board from one of the server's templates, previewing the columns each one creates. */
import { useId, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Lock } from "lucide-react";
import { Button, Dialog, ErrorState, Field, Input, LoadingRows, Textarea, useToast } from "@/components/ui";
import { cn } from "@/lib/format";
import { useBoardTemplates, useCreateBoard, validationErrors } from "../api";
import type { BoardTemplateKey } from "../types";
import { errorMessage } from "../tasks/useWorkflowConflicts";

export function NewBoardDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return open ? <NewBoardDialogBody onOpenChange={onOpenChange} /> : null;
}

function NewBoardDialogBody({ onOpenChange }: { onOpenChange: (open: boolean) => void }) {
  const ids = { name: useId(), description: useId() };
  const navigate = useNavigate();
  const toast = useToast();
  const templates = useBoardTemplates();
  const create = useCreateBoard();
  const [template, setTemplate] = useState<BoardTemplateKey>("software_development");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const errors = validationErrors(create.error);
  const selected = templates.data?.find((t) => t.key === template) ?? templates.data?.[0];

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const finalName = name.trim() || selected?.name || "New board";
    create.mutate(
      { name: finalName, template: selected?.key ?? template, description: description.trim() || null },
      {
        onSuccess: (board) => {
          toast.success(`Board “${board.name}” created`, `${board.columns.length} columns from the ${selected?.name ?? "selected"} template.`);
          onOpenChange(false);
          navigate(`/work/boards/${encodeURIComponent(board.id)}`);
        },
      },
    );
  };

  return (
    <Dialog
      open
      onOpenChange={(next) => !create.isPending && onOpenChange(next)}
      title="New board"
      description="Pick the workflow closest to how this work moves. Columns, WIP limits and gates can be changed afterwards."
      className="w-[min(760px,calc(100vw-32px))]"
      footer={
        <>
          <Button size="sm" variant="ghost" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            Cancel
          </Button>
          <Button size="sm" variant="primary" type="submit" form="new-board" loading={create.isPending} disabled={!selected}>
            Create board
          </Button>
        </>
      }
    >
      <form id="new-board" onSubmit={submit} className="space-y-4">
        {templates.isLoading ? (
          <LoadingRows rows={4} />
        ) : templates.error ? (
          <ErrorState error={templates.error} onRetry={() => void templates.refetch()} />
        ) : (
          <fieldset>
            <legend className="mb-2 text-xs font-medium text-fg-muted">Template</legend>
            <div role="radiogroup" aria-label="Board template" className="grid gap-2 sm:grid-cols-2">
              {(templates.data ?? []).map((t) => {
                const active = t.key === selected?.key;
                return (
                  <button
                    key={t.key}
                    type="button"
                    role="radio"
                    aria-checked={active}
                    onClick={() => setTemplate(t.key)}
                    className={cn(
                      "rounded-md border p-3 text-left transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent",
                      active ? "border-accent/60 bg-accent/[0.06]" : "border-border hover:border-border-strong hover:bg-surface-2",
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-[13px] font-medium text-fg">{t.name}</span>
                      {t.requires_verification && (
                        <span className="inline-flex items-center gap-1 text-2xs text-fg-muted" title="Includes a column that requires passed verification">
                          <Lock className="h-3 w-3" aria-hidden />
                          Verification gate
                        </span>
                      )}
                    </div>
                    <p className="mt-1 line-clamp-2 text-2xs text-fg-muted">{t.description}</p>
                    <ol className="mt-2 flex flex-wrap items-center gap-1" aria-label={`${t.name} columns`}>
                      {t.columns.map((c, i) => (
                        <li key={`${c}-${i}`} className="inline-flex items-center gap-1 text-2xs text-fg-faint">
                          {i > 0 && <span aria-hidden>→</span>}
                          <span className="rounded border border-border bg-surface-2 px-1 text-fg-muted">{c}</span>
                        </li>
                      ))}
                    </ol>
                  </button>
                );
              })}
            </div>
          </fieldset>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name" htmlFor={ids.name} hint={selected ? `Leave empty to use “${selected.name}”.` : undefined}>
            <Input id={ids.name} value={name} maxLength={200} onChange={(e) => setName(e.target.value)} placeholder={selected?.name} />
          </Field>
          <Field label="Description (optional)" htmlFor={ids.description}>
            <Textarea id={ids.description} value={description} rows={2} className="min-h-[32px]" maxLength={2000} onChange={(e) => setDescription(e.target.value)} />
          </Field>
        </div>
        {create.error && (
          <div role="alert" className="space-y-1 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {(errors.length > 0 ? errors : [errorMessage(create.error)]).map((m) => (
              <p key={m}>{m}</p>
            ))}
          </div>
        )}
      </form>
    </Dialog>
  );
}
