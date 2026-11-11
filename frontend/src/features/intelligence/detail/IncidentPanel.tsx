/**
 * The finding's incident: the one it belongs to, or (for writers) suggested open incidents to attach
 * it to and a dialog to open a new one. The server refuses closed incidents and mixing simulated
 * with real records (409); those messages are shown as returned.
 */
import { useEffect, useId, useState } from "react";
import { Link } from "react-router-dom";
import { Siren } from "lucide-react";
import { Button, Dialog, Field, Input, SeverityBadge, StatusBadge, useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { useLinkIncident } from "../api";
import type { FindingDetail, LinkIncidentResult } from "../types";

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

export function NewIncidentDialog({ finding, open, onOpenChange }: { finding: FindingDetail; open: boolean; onOpenChange: (open: boolean) => void }) {
  const [title, setTitle] = useState(finding.title);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const link = useLinkIncident();
  const toast = useToast();

  useEffect(() => {
    if (open) {
      setTitle(finding.title);
      setError(null);
    }
  }, [open, finding.title]);

  const submit = () => {
    const trimmed = title.trim();
    link.mutate(
      { id: finding.id, body: trimmed && trimmed !== finding.title ? { title: trimmed } : {} },
      {
        onSuccess: (result: LinkIncidentResult) => {
          toast.success(`Opened INC-${result.incident.number}`, result.incident.title);
          onOpenChange(false);
        },
        onError: (err) => setError(errorMessage(err, "The incident could not be opened. Try again.")),
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !link.isPending && onOpenChange(next)}
      title="Open an incident"
      description="Start an investigation with this finding as its first piece of evidence."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={link.isPending}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} loading={link.isPending} disabled={!title.trim()}>
            Open incident
          </Button>
        </>
      }
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (title.trim()) submit();
        }}
      >
        <Field label="Title" htmlFor={titleId} error={error} hint={`Starts at ${finding.severity} severity, the finding's severity.`}>
          <Input id={titleId} value={title} maxLength={400} autoFocus onChange={(e) => setTitle(e.target.value)} />
        </Field>
        {finding.is_simulation && <p className="text-xs text-fg-muted">This finding is simulated, so the incident will be flagged as a simulation too.</p>}
      </form>
    </Dialog>
  );
}

export function IncidentPanel({ finding, canWrite }: { finding: FindingDetail; canWrite: boolean }) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const link = useLinkIncident();
  const toast = useToast();
  const incident = finding.related.incident ?? finding.incident;

  if (incident) {
    return (
      <div className="space-y-2">
        <Link
          to={`/incidents/${encodeURIComponent(incident.id)}`}
          className="group block rounded-md border border-border bg-surface-2/40 p-3 transition-colors hover:border-border-strong hover:bg-surface-2"
        >
          <div className="flex items-center gap-2 text-xs">
            <Siren className="h-3.5 w-3.5 text-fg-muted" aria-hidden />
            <span className="num font-mono text-fg-muted">INC-{incident.number}</span>
            <StatusBadge status={incident.status} />
            <SeverityBadge severity={incident.severity} />
          </div>
          <div className="mt-1.5 text-[13px] font-medium text-fg group-hover:text-accent">{incident.title}</div>
        </Link>
        <p className="text-2xs text-fg-faint">Triage on this finding is added to the incident's timeline.</p>
      </div>
    );
  }

  const attach = (incidentId: string) =>
    link.mutate(
      { id: finding.id, body: { incident_id: incidentId } },
      {
        onSuccess: (result) => toast.success(`Attached to INC-${result.incident.number}`, result.incident.title),
        onError: (err) => toast.error("Could not attach the finding", errorMessage(err, "Try again.")),
      },
    );

  return (
    <div className="space-y-3">
      <p className="text-xs text-fg-muted">
        Not part of an incident. Critical findings (and some high-severity ones) open an incident automatically; others are linked by an analyst.
      </p>
      {finding.incident_candidates.length > 0 && (
        <div>
          <div className="label-caps mb-1.5">Open incidents</div>
          <ul className="divide-y divide-border rounded-md border border-border">
            {finding.incident_candidates.map((c) => (
              <li key={c.id} className="flex items-center gap-2 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <Link to={`/incidents/${encodeURIComponent(c.id)}`} className="block truncate text-xs font-medium text-fg hover:text-accent" title={c.title}>
                    <span className="num font-mono text-fg-muted">INC-{c.number}</span> {c.title}
                  </Link>
                  <div className="mt-0.5 flex items-center gap-1.5 text-2xs text-fg-faint">
                    <span>{c.reason}</span>
                    <span aria-hidden>·</span>
                    <span>{c.severity}</span>
                    <span aria-hidden>·</span>
                    <span>{c.status}</span>
                  </div>
                </div>
                {canWrite && (
                  <Button
                    size="xs"
                    variant="outline"
                    onClick={() => attach(c.id)}
                    loading={link.isPending && link.variables?.body.incident_id === c.id}
                    disabled={link.isPending}
                    aria-label={`Attach to INC-${c.number} ${c.title}`}
                  >
                    Attach
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {canWrite ? (
        <Button size="sm" variant="outline" icon={<Siren className="h-3.5 w-3.5" aria-hidden />} onClick={() => setDialogOpen(true)} disabled={link.isPending}>
          Open new incident
        </Button>
      ) : (
        finding.incident_candidates.length === 0 && <p className="text-2xs text-fg-faint">No open incidents to attach it to.</p>
      )}
      <NewIncidentDialog finding={finding} open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  );
}
