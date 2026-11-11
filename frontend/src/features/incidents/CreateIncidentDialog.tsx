/** Open an incident by hand, optionally grouping open findings that are not yet part of one. */
import { useId, useState, type FormEvent } from "react";
import { Button, Dialog, Field, Input, Select, Textarea, useToast } from "@/components/ui";
import { SEVERITY_META, type Severity } from "@/lib/domain";
import { errorMessage, useCreateIncident } from "./api";
import { FindingPicker } from "./FindingPicker";
import { SEVERITY_OPTIONS } from "./meta";
import type { IncidentDetail } from "./types";

export interface CreateIncidentDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (incident: IncidentDetail) => void;
}

export function CreateIncidentDialog({ open, onOpenChange, onCreated }: CreateIncidentDialogProps) {
  const formId = useId();
  const toast = useToast();
  const create = useCreateIncident();
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [severity, setSeverity] = useState<Severity>("high");
  const [findingIds, setFindingIds] = useState<string[]>([]);

  /** Close and start from an empty form next time. Never closes while the request is in flight. */
  const close = (afterSuccess = false) => {
    if (create.isPending && !afterSuccess) return;
    setTitle("");
    setSummary("");
    setSeverity("high");
    setFindingIds([]);
    create.reset();
    onOpenChange(false);
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    create.mutate(
      { title: title.trim(), summary: summary.trim(), severity, finding_ids: findingIds },
      {
        onSuccess: (incident) => {
          const raised = incident.severity !== severity ? ` Severity raised to ${SEVERITY_META[incident.severity].label.toLowerCase()} to match its findings.` : "";
          toast.success(`${incident.key} opened`, `${findingIds.length ? `${findingIds.length} finding(s) linked.` : "No findings linked yet."}${raised}`);
          close(true);
          onCreated(incident);
        },
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => (next ? onOpenChange(true) : close())}
      title="New incident"
      description="Group related findings into one investigation. Secrets in the title and summary are redacted before they are stored."
      className="w-[min(680px,calc(100vw-32px))]"
      footer={
        <>
          <Button variant="ghost" onClick={() => close()} disabled={create.isPending}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form={formId} loading={create.isPending} disabled={!title.trim()}>
            Open incident
          </Button>
        </>
      }
    >
      <form id={formId} onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-[1fr_160px]">
          <Field label="Title" htmlFor={`${formId}-title`}>
            <Input id={`${formId}-title`} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={400} required autoFocus placeholder="e.g. Token sent to an unknown host from the billing agent" />
          </Field>
          <Field label="Severity" htmlFor={`${formId}-severity`} hint="Raised automatically if a linked finding is more severe.">
            <Select id={`${formId}-severity`} value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_META[s].label}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <Field label="Summary" htmlFor={`${formId}-summary`} hint="What is known so far and why this needs investigating.">
          <Textarea id={`${formId}-summary`} value={summary} onChange={(e) => setSummary(e.target.value)} maxLength={8000} rows={3} />
        </Field>
        <Field label="Findings" hint="Optional. Only open findings that are not part of another incident are listed.">
          <FindingPicker selected={findingIds} onChange={setFindingIds} enabled={open} />
        </Field>
        {create.error && (
          <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {errorMessage(create.error)}
          </p>
        )}
      </form>
    </Dialog>
  );
}
