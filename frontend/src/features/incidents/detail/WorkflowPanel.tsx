/**
 * Status workflow: open → investigating → contained → resolved, with false positive as an alternative
 * end state. Only the transitions the server allows are offered; closing asks for a resolution.
 */
import { useId, useState } from "react";
import { Check, CircleSlash } from "lucide-react";
import { Button, Dialog, Field, Textarea, useToast } from "@/components/ui";
import type { IncidentStatus } from "@/lib/domain";
import { cn, formatDateTime, timeAgo } from "@/lib/format";
import { errorMessage, useUpdateIncident } from "../api";
import { STATUS_DESCRIPTIONS, STATUS_LABELS, WORKFLOW, isClosed, transitionLabel } from "../meta";
import type { IncidentDetail } from "../types";

function Stepper({ status }: { status: IncidentStatus }) {
  const falsePositive = status === "false_positive";
  const current = WORKFLOW.indexOf(status);
  return (
    <ol className="flex flex-wrap items-center gap-y-2" aria-label="Incident workflow">
      {WORKFLOW.map((step, i) => {
        const done = !falsePositive && i < current;
        const active = !falsePositive && i === current;
        return (
          <li key={step} className="flex items-center" aria-current={active ? "step" : undefined}>
            {i > 0 && <span className={cn("mx-2 h-px w-6 sm:w-10", done || active ? "bg-accent/60" : "bg-border")} aria-hidden />}
            <span
              className={cn(
                "inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-xs",
                active ? "border-accent/50 bg-accent/10 font-medium text-fg" : done ? "border-border text-fg-muted" : "border-dashed border-border text-fg-faint",
              )}
              title={STATUS_DESCRIPTIONS[step]}
            >
              {done && <Check className="h-3 w-3 text-ok" aria-hidden />}
              {STATUS_LABELS[step]}
            </span>
          </li>
        );
      })}
      <li className="ml-3 flex items-center" aria-current={falsePositive ? "step" : undefined}>
        <span
          className={cn(
            "inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-xs",
            falsePositive ? "border-border-strong bg-surface-3 font-medium text-fg" : "border-dashed border-border text-fg-faint",
          )}
          title={STATUS_DESCRIPTIONS.false_positive}
        >
          <CircleSlash className="h-3 w-3" aria-hidden />
          {STATUS_LABELS.false_positive}
        </span>
      </li>
    </ol>
  );
}

function ResolutionDialog({
  incident,
  target,
  onClose,
}: {
  incident: IncidentDetail;
  target: { status?: IncidentStatus; edit?: boolean } | null;
  onClose: () => void;
}) {
  const id = useId();
  const toast = useToast();
  const update = useUpdateIncident(incident.id);
  const [text, setText] = useState(target?.edit ? (incident.resolution ?? "") : "");
  const fp = target?.status === "false_positive";

  const submit = () => {
    const resolution = text.trim();
    if (!resolution || !target) return;
    update.mutate(target.edit ? { resolution } : { status: target.status, resolution }, {
      onSuccess: (detail) => {
        toast.success(target.edit ? "Resolution updated" : `${detail.key} marked ${STATUS_LABELS[detail.status].toLowerCase()}`);
        onClose();
      },
    });
  };

  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => !open && !update.isPending && onClose()}
      title={target?.edit ? "Edit resolution" : fp ? "Mark as false positive" : "Resolve incident"}
      description={
        fp
          ? "Explain why this is not a real problem. Linked findings keep their own status; triage them separately if needed."
          : "Record what was done (credentials rotated, destination blocked, policy added). Linked findings keep their own status."
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={update.isPending}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} loading={update.isPending} disabled={!text.trim()}>
            {target?.edit ? "Save resolution" : fp ? "Mark false positive" : "Resolve"}
          </Button>
        </>
      }
    >
      <Field label="Resolution" htmlFor={id} hint="Secrets are redacted before the text is stored.">
        <Textarea
          id={id}
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={5}
          maxLength={8000}
          autoFocus
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submit();
          }}
        />
      </Field>
      {update.error && (
        <p role="alert" className="mt-3 text-xs text-danger">
          {errorMessage(update.error)}
        </p>
      )}
    </Dialog>
  );
}

export function WorkflowPanel({ incident, canWrite }: { incident: IncidentDetail; canWrite: boolean }) {
  const toast = useToast();
  const update = useUpdateIncident(incident.id);
  const [dialog, setDialog] = useState<{ status?: IncidentStatus; edit?: boolean } | null>(null);
  const [pending, setPending] = useState<IncidentStatus | null>(null);

  const move = (to: IncidentStatus) => {
    if (isClosed(to)) return setDialog({ status: to });
    setPending(to);
    update.mutate(
      { status: to },
      {
        onSuccess: (detail) => toast.success(`${detail.key} is now ${STATUS_LABELS[detail.status].toLowerCase()}`),
        onError: (err) => toast.error("Could not change the status", errorMessage(err)),
        onSettled: () => setPending(null),
      },
    );
  };

  const closed = isClosed(incident.status);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Stepper status={incident.status} />
        {canWrite && incident.allowed_transitions.length > 0 && (
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Change status">
            {incident.allowed_transitions.map((to) => (
              <Button
                key={to}
                size="sm"
                variant={!closed && WORKFLOW.indexOf(to) === WORKFLOW.indexOf(incident.status) + 1 ? "primary" : "outline"}
                loading={pending === to}
                disabled={update.isPending}
                onClick={() => move(to)}
                title={STATUS_DESCRIPTIONS[to]}
              >
                {transitionLabel(incident.status, to)}
              </Button>
            ))}
          </div>
        )}
      </div>
      <p className="text-xs text-fg-muted">{STATUS_DESCRIPTIONS[incident.status]}</p>
      {closed && (
        <div className="rounded border border-border bg-surface-2/60 px-3 py-2.5">
          <div className="flex items-center justify-between gap-2">
            <span className="label-caps">Resolution</span>
            <span className="flex items-center gap-2 text-2xs text-fg-faint">
              {incident.resolved_at && (
                <time dateTime={incident.resolved_at} title={formatDateTime(incident.resolved_at)}>
                  Closed {timeAgo(incident.resolved_at)}
                </time>
              )}
              {canWrite && (
                <Button size="xs" variant="ghost" onClick={() => setDialog({ edit: true })}>
                  Edit
                </Button>
              )}
            </span>
          </div>
          <p className="mt-1 whitespace-pre-wrap break-words text-[13px] text-fg">{incident.resolution || "No resolution recorded."}</p>
        </div>
      )}
      {dialog && <ResolutionDialog key={`${dialog.status ?? "edit"}`} incident={incident} target={dialog} onClose={() => setDialog(null)} />}
    </div>
  );
}
