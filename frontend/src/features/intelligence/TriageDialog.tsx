/** Note-taking confirmation for triage actions that change what a finding means (resolve, false
 * positive, reopen). Acknowledging needs no dialog — see `useTriage`. */
import { useEffect, useId, useState } from "react";
import { Button, Dialog, Field, Textarea, useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { useUpdateFinding } from "./api";
import { ACTION_META, type TriageAction } from "./meta";
import type { FindingDetail } from "./types";

const MIN_REASON = 3;

export function TriageDialog({
  finding,
  action,
  onOpenChange,
  onDone,
}: {
  finding: { id: string; title: string } | null;
  action: TriageAction | null;
  onOpenChange: (open: boolean) => void;
  onDone?: (detail: FindingDetail) => void;
}) {
  const open = finding !== null && action !== null;
  const meta = action ? ACTION_META[action] : null;
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const noteId = useId();
  const update = useUpdateFinding();
  const toast = useToast();

  useEffect(() => {
    if (open) {
      setNote("");
      setError(null);
    }
  }, [open, finding?.id, action]);

  if (!meta || !finding || !action) return null;
  const trimmed = note.trim();
  const tooShort = meta.noteRequired && trimmed.length < MIN_REASON;

  const submit = () => {
    if (tooShort) {
      setError("Add a short reason so the next person understands the decision.");
      return;
    }
    setError(null);
    update.mutate(
      { id: finding.id, body: { status: action, ...(trimmed ? { resolution_note: trimmed } : {}) } },
      {
        onSuccess: (detail) => {
          toast.success(meta.done, finding.title);
          onOpenChange(false);
          onDone?.(detail);
        },
        onError: (err) => setError(err instanceof ApiError ? err.message : "The change could not be saved. Try again."),
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !update.isPending && onOpenChange(next)}
      title={meta.verb}
      description={finding.title}
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={update.isPending}>
            Cancel
          </Button>
          <Button variant={action === "false_positive" ? "secondary" : "primary"} onClick={submit} loading={update.isPending} disabled={tooShort}>
            {meta.verb}
          </Button>
        </>
      }
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <p className="text-xs leading-relaxed text-fg-muted">{meta.description}</p>
        <Field
          label={meta.noteLabel}
          htmlFor={noteId}
          error={error}
          hint={meta.noteRequired ? "Required. Credentials pasted here are redacted before they are stored." : "Credentials pasted here are redacted before they are stored."}
        >
          <Textarea
            id={noteId}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            maxLength={4000}
            autoFocus
            placeholder={action === "false_positive" ? "e.g. The README documents an attack example for the security training." : "e.g. Rotated the token and blocked the collector domain."}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                submit();
              }
            }}
          />
        </Field>
      </form>
    </Dialog>
  );
}
