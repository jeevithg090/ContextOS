/**
 * Triage on the detail page: the action buttons the current status allows (server-provided
 * `allowed_transitions`), the current resolution and its note (editable once closed), and the
 * audited triage history.
 */
import { useEffect, useId, useState } from "react";
import { Check, CheckCheck, RotateCcw, ShieldOff } from "lucide-react";
import { Timeline } from "@/components/data";
import { Button, Dialog, Field, StatusBadge, Textarea, useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useUpdateFinding } from "../api";
import { ACTION_META, STATUS_OPTIONS, historyLabel, historyTone, type TriageAction } from "../meta";
import type { FindingDetail } from "../types";

const ICONS: Record<TriageAction, React.ReactNode> = {
  acknowledged: <Check className="h-3.5 w-3.5" aria-hidden />,
  resolved: <CheckCheck className="h-3.5 w-3.5" aria-hidden />,
  false_positive: <ShieldOff className="h-3.5 w-3.5" aria-hidden />,
  open: <RotateCcw className="h-3.5 w-3.5" aria-hidden />,
};
const ORDER: TriageAction[] = ["acknowledged", "resolved", "false_positive", "open"];

export function TriageActions({ finding, busy, onAction }: { finding: FindingDetail; busy: boolean; onAction: (action: TriageAction) => void }) {
  const allowed = ORDER.filter((a) => finding.allowed_transitions.includes(a));
  if (allowed.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Triage">
      {allowed.map((action) => (
        <Button
          key={action}
          size="sm"
          variant={action === "acknowledged" || (action === "resolved" && finding.status === "acknowledged") ? "primary" : "outline"}
          icon={ICONS[action]}
          onClick={() => onAction(action)}
          loading={busy && action === "acknowledged"}
          disabled={busy}
          title={ACTION_META[action].description}
        >
          {ACTION_META[action].label}
        </Button>
      ))}
    </div>
  );
}

function NoteDialog({ finding, open, onOpenChange }: { finding: FindingDetail; open: boolean; onOpenChange: (open: boolean) => void }) {
  const [note, setNote] = useState(finding.resolution_note ?? "");
  const [error, setError] = useState<string | null>(null);
  const noteId = useId();
  const update = useUpdateFinding();
  const toast = useToast();
  const required = finding.status === "false_positive";

  useEffect(() => {
    if (open) {
      setNote(finding.resolution_note ?? "");
      setError(null);
    }
  }, [open, finding.resolution_note]);

  const submit = () => {
    if (required && note.trim().length < 3) {
      setError("A false positive needs a reason.");
      return;
    }
    update.mutate(
      { id: finding.id, body: { resolution_note: note.trim() } },
      {
        onSuccess: () => {
          toast.success("Resolution note saved");
          onOpenChange(false);
        },
        onError: (err) => setError(err instanceof ApiError ? err.message : "The note could not be saved. Try again."),
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !update.isPending && onOpenChange(next)}
      title="Edit resolution note"
      description={finding.title}
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={update.isPending}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} loading={update.isPending}>
            Save note
          </Button>
        </>
      }
    >
      <Field label={required ? "Why is this not suspicious?" : "What was done"} htmlFor={noteId} error={error} hint="Credentials pasted here are redacted before they are stored. The previous note stays in the history.">
        <Textarea id={noteId} value={note} maxLength={4000} autoFocus onChange={(e) => setNote(e.target.value)} />
      </Field>
    </Dialog>
  );
}

export function TriageStatus({ finding, canWrite }: { finding: FindingDetail; canWrite: boolean }) {
  const [editing, setEditing] = useState(false);
  const closed = finding.status === "resolved" || finding.status === "false_positive";
  const statusMeta = STATUS_OPTIONS.find((s) => s.value === finding.status);
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <StatusBadge status={finding.status} />
        {statusMeta && <span className="text-xs text-fg-muted">{statusMeta.description}</span>}
      </div>
      {closed && (
        <div className="rounded-md border border-border bg-surface-2/40 p-3">
          <div className="flex items-center justify-between gap-2 text-2xs text-fg-faint">
            <span>{finding.resolved_by ? `By ${finding.resolved_by.name}` : "Closed by an API key or automation"}</span>
            {canWrite && (
              <Button size="xs" variant="ghost" onClick={() => setEditing(true)}>
                Edit note
              </Button>
            )}
          </div>
          <p className="mt-1 whitespace-pre-wrap break-words text-xs text-fg">{finding.resolution_note || <span className="text-fg-faint">No note was recorded.</span>}</p>
        </div>
      )}
      {editing && <NoteDialog finding={finding} open={editing} onOpenChange={setEditing} />}
    </div>
  );
}

export function TriageHistory({ finding }: { finding: FindingDetail }) {
  const items = finding.history.map((h, i) => ({
    id: `${h.action}-${h.occurred_at}-${i}`,
    time: h.occurred_at,
    tone: historyTone(h.action),
    title: historyLabel(h.action),
    description: (
      <span className="block">
        <span title={formatDateTime(h.occurred_at)}>
          {h.actor} · {timeAgo(h.occurred_at)}
        </span>
        {h.note && <span className="mt-0.5 block whitespace-pre-wrap break-words text-fg">{h.note}</span>}
      </span>
    ),
  }));
  return (
    <Timeline
      items={items}
      dense
      timeFormat="relative"
      showTime={false}
      aria-label="Triage history"
      emptyLabel="No one has triaged this finding yet. Acknowledge it to let your team know it is being looked at."
    />
  );
}
