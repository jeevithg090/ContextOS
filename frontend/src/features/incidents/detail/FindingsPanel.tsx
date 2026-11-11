/** The incident's findings (most severe first) and linking more open findings into it. */
import { useState } from "react";
import { Link } from "react-router-dom";
import { Plus, Radar } from "lucide-react";
import { Button, Dialog, EmptyState, Mono, SeverityBadge, StatusBadge, useToast } from "@/components/ui";
import { FINDING_CATEGORY_LABELS } from "@/lib/domain";
import { formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { errorMessage, useLinkFindings } from "../api";
import { FindingPicker } from "../FindingPicker";
import { isClosed } from "../meta";
import type { IncidentDetail } from "../types";

function LinkDialog({ incident, open, onOpenChange }: { incident: IncidentDetail; open: boolean; onOpenChange: (open: boolean) => void }) {
  const toast = useToast();
  const link = useLinkFindings(incident.id);
  const [selected, setSelected] = useState<string[]>([]);

  const close = (afterSuccess = false) => {
    if (link.isPending && !afterSuccess) return;
    setSelected([]);
    link.reset();
    onOpenChange(false);
  };

  const submit = () =>
    link.mutate(selected, {
      onSuccess: (result) => {
        toast.success(`${result.linked.length} finding${result.linked.length === 1 ? "" : "s"} linked to ${result.incident.key}`);
        close(true);
      },
    });

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => (next ? onOpenChange(true) : close())}
      title={`Link findings to ${incident.key}`}
      description="Their sessions' events join the investigation timeline. The incident becomes at least as severe as the worst linked finding."
      className="w-[min(680px,calc(100vw-32px))]"
      footer={
        <>
          <Button variant="ghost" onClick={() => close()} disabled={link.isPending}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} loading={link.isPending} disabled={selected.length === 0}>
            Link {selected.length > 0 ? selected.length : ""} finding{selected.length === 1 ? "" : "s"}
          </Button>
        </>
      }
    >
      <FindingPicker selected={selected} onChange={setSelected} enabled={open} simulation={incident.is_simulation} />
      {link.error && (
        <p role="alert" className="mt-3 text-xs text-danger">
          {errorMessage(link.error)}
        </p>
      )}
    </Dialog>
  );
}

export function FindingsActions({ incident, canWrite }: { incident: IncidentDetail; canWrite: boolean }) {
  const [open, setOpen] = useState(false);
  if (!canWrite) return null;
  const closed = isClosed(incident.status);
  return (
    <>
      <Button size="sm" variant="outline" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setOpen(true)} disabled={closed} title={closed ? "Reopen the incident to link more findings" : undefined}>
        Link findings
      </Button>
      <LinkDialog incident={incident} open={open} onOpenChange={setOpen} />
    </>
  );
}

export function FindingsPanel({ incident }: { incident: IncidentDetail }) {
  if (incident.findings.length === 0) {
    return (
      <EmptyState
        icon={<Radar className="h-5 w-5" aria-hidden />}
        title="No findings linked"
        description="Link the findings this investigation is about; their sessions, sources and destinations then appear here and in the timeline."
        className="py-8"
      />
    );
  }
  return (
    <ul className="divide-y divide-border" aria-label="Linked findings">
      {incident.findings.map((f) => (
        <li key={f.id} className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={f.severity} />
              <Link to={`/intelligence/${encodeURIComponent(f.id)}`} className="min-w-0 break-words text-[13px] font-medium text-fg hover:text-accent hover:underline">
                {f.title}
              </Link>
              {f.status !== "open" && <StatusBadge status={f.status} />}
            </div>
            <p className="line-clamp-2 text-xs text-fg-muted">{f.explanation}</p>
            <div className="flex flex-wrap items-center gap-x-3 text-2xs text-fg-faint">
              <span>{FINDING_CATEGORY_LABELS[f.category] ?? f.category}</span>
              <Mono className="text-2xs text-fg-faint">{f.rule_id}</Mono>
              {f.agent && <span>{f.agent.name}</span>}
              {f.session && <span className="font-mono">{f.session.external_session_id}</span>}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-3 text-2xs text-fg-faint sm:flex-col sm:items-end sm:gap-0.5">
            <span className="num" title="Repeats of the same problem in the same session are merged">
              ×{formatNumber(f.occurrence_count)}
            </span>
            <time dateTime={f.last_seen_at} title={`First seen ${formatDateTime(f.first_seen_at)}, last seen ${formatDateTime(f.last_seen_at)}`}>
              {timeAgo(f.last_seen_at)}
            </time>
          </div>
        </li>
      ))}
    </ul>
  );
}
