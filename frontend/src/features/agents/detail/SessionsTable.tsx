import { useNavigate } from "react-router-dom";
import { SimulationBadge, StatusBadge } from "@/components/ui";
import { DataTable, RiskMeter, type DataTableColumn } from "@/components/data";
import { cn, formatDateTime, timeAgo } from "@/lib/format";
import { durationLabel } from "../meta";
import type { SessionSummary } from "../types";

const LEGS: Array<{ key: "sensitive_access" | "untrusted_exposure" | "outbound_channel"; short: string; label: string }> = [
  { key: "sensitive_access", short: "S", label: "Sensitive data access" },
  { key: "untrusted_exposure", short: "U", label: "Untrusted content" },
  { key: "outbound_channel", short: "O", label: "Outbound channel" },
];

/** The three lethal-trifecta conditions as compact indicators (a condition, not proof of an attack). */
export function TrifectaIndicator({ session }: { session: Pick<SessionSummary, "sensitive_access" | "untrusted_exposure" | "outbound_channel" | "trifecta"> }) {
  const active = LEGS.filter((l) => session[l.key]);
  const text = active.length ? `Conditions present: ${active.map((l) => l.label.toLowerCase()).join(", ")}` : "No trifecta condition present";
  return (
    <span className="inline-flex items-center gap-0.5" role="img" aria-label={text} title={`${text}${session.trifecta ? " — all three together are a risk condition, not proof of an attack" : ""}`}>
      {LEGS.map((l) => (
        <span
          key={l.key}
          className={cn(
            "inline-flex h-4 w-4 items-center justify-center rounded-sm border font-mono text-[9px] font-semibold",
            session[l.key] ? (session.trifecta ? "border-sev-critical/40 bg-sev-critical/15 text-sev-critical" : "border-sev-medium/40 bg-sev-medium/10 text-sev-medium") : "border-border text-fg-faint",
          )}
          aria-hidden
        >
          {l.short}
        </span>
      ))}
    </span>
  );
}

const columns: Array<DataTableColumn<SessionSummary>> = [
  {
    key: "session",
    header: "Session",
    render: (s) => (
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="truncate font-mono text-xs text-fg" title={s.external_session_id}>
            {s.external_session_id}
          </span>
          {s.is_simulation && <SimulationBadge />}
        </div>
        <div className="mt-0.5 text-2xs text-fg-faint">
          Started <time dateTime={s.started_at} title={formatDateTime(s.started_at)}>{timeAgo(s.started_at)}</time>
          {s.parent_session_id ? " · delegated" : ""}
          {s.child_count > 0 ? ` · ${s.child_count} sub-session${s.child_count === 1 ? "" : "s"}` : ""}
        </div>
      </div>
    ),
  },
  { key: "status", header: "Status", render: (s) => <StatusBadge status={s.status} /> },
  { key: "risk", header: "Risk", render: (s) => <RiskMeter score={s.risk_score} level={s.risk_level} size="sm" label={`Risk of session ${s.external_session_id}`} /> },
  { key: "trifecta", header: "Trifecta", render: (s) => <TrifectaIndicator session={s} /> },
  {
    key: "findings",
    header: "Open findings",
    align: "right",
    render: (s) => (s.open_findings ? <span className="num text-sev-high">{s.open_findings}</span> : <span className="num text-fg-faint">0</span>),
  },
  { key: "events", header: "Events", align: "right", hideBelow: "md", render: (s) => <span className="num text-fg-muted">{s.event_count}</span> },
  { key: "duration", header: "Duration", align: "right", hideBelow: "lg", render: (s) => <span className="num text-fg-muted">{durationLabel(s.started_at, s.ended_at ?? s.last_event_at)}</span> },
  {
    key: "last",
    header: "Last activity",
    align: "right",
    hideBelow: "sm",
    render: (s) => {
      const at = s.last_event_at ?? s.started_at;
      return (
        <time dateTime={at} title={formatDateTime(at)} className="text-fg-muted">
          {timeAgo(at)}
        </time>
      );
    },
  },
];

export function SessionsTable({ rows, loading, error, onRetry, emptyTitle, emptyDescription }: { rows?: SessionSummary[]; loading: boolean; error: unknown; onRetry: () => void; emptyTitle: string; emptyDescription?: string }) {
  const navigate = useNavigate();
  return (
    <DataTable
      aria-label="Sessions"
      columns={columns}
      rows={rows}
      rowKey={(s) => s.id}
      loading={loading}
      error={error}
      onRetry={onRetry}
      manualSort
      dense
      onRowClick={(s) => navigate(`/sessions/${encodeURIComponent(s.id)}`)}
      empty={{ title: emptyTitle, description: emptyDescription }}
    />
  );
}
