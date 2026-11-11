/**
 * Exactly what the retention purge deletes and keeps — mirrors backend/app/services/retention.py
 * (`purge_expired`, run by `contextos-server purge`). Keep the two in sync.
 */
import { Archive, Trash2 } from "lucide-react";

const DELETED: string[] = [
  "Ingested events, context items, tool calls, policy decisions and provenance edges recorded before the cutoff",
  "Approvals that are no longer pending and were requested (and decided) before the cutoff",
  "Findings marked resolved or false positive whose last activity is before the cutoff — open and acknowledged findings are never purged",
  "Ended sessions with nothing newer recorded in them",
];

const KEPT: string[] = [
  "The audit log: it is a hash chain, so removing entries would break verification. Each purge adds an audit entry with the counts it deleted",
  "Evidence of open, investigating or contained incidents, until the incident is resolved or marked a false positive",
  "Agents, sources, destinations, policies, trust rules, incidents, integrations, simulation runs, and Engineering Workspace boards, tasks and prompts",
];

export function RetentionScope({ days }: { days: number | null }) {
  return (
    <div className="space-y-3 text-xs text-fg-muted">
      <p>
        Data is deleted only when an operator runs <code className="font-mono text-fg">contextos-server purge</code> on the server (schedule it, for example
        daily from cron). Until then, data past the retention period is kept and stays visible. Age is measured from when the server recorded the data
        {days !== null ? `: each run deletes what was recorded more than ${days} ${days === 1 ? "day" : "days"} earlier.` : "."}
      </p>
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <div className="mb-1.5 flex items-center gap-1.5 font-medium text-fg">
            <Trash2 className="h-3.5 w-3.5 text-fg-faint" aria-hidden />
            Deleted by the purge
          </div>
          <ul className="list-disc space-y-1 pl-4">
            {DELETED.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
        <div>
          <div className="mb-1.5 flex items-center gap-1.5 font-medium text-fg">
            <Archive className="h-3.5 w-3.5 text-fg-faint" aria-hidden />
            Always kept
          </div>
          <ul className="list-disc space-y-1 pl-4">
            {KEPT.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
