import type { ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { Badge, SeverityBadge, SimulationBadge, StatusBadge } from "@/components/ui";
import { DataTable, RiskMeter, type DataTableColumn } from "@/components/data";
import { formatDateTime, timeAgo, truncate } from "@/lib/format";
import { ENVIRONMENT_LABELS, environmentTone, frameworkLabel } from "./meta";
import type { AgentSummary } from "./types";

const columns: Array<DataTableColumn<AgentSummary>> = [
  {
    key: "name",
    header: "Agent",
    render: (a) => (
      <div className="min-w-0 max-w-[280px]">
        <div className="flex items-center gap-2">
          <span className="truncate font-medium text-fg">{a.name}</span>
          {a.is_simulation && <SimulationBadge />}
        </div>
        <div className="mt-0.5 truncate text-xs text-fg-muted" title={a.description ?? undefined}>
          {a.owner ? `Owner ${a.owner}` : <span className="text-fg-faint">No owner</span>}
          {a.description ? ` · ${truncate(a.description, 70)}` : ""}
        </div>
      </div>
    ),
  },
  { key: "framework", header: "Framework", hideBelow: "lg", render: (a) => <span className="whitespace-nowrap text-fg-muted">{frameworkLabel(a.framework)}</span> },
  {
    key: "environment",
    header: "Environment",
    hideBelow: "sm",
    render: (a) => <Badge tone={environmentTone(a.environment)}>{ENVIRONMENT_LABELS[a.environment] ?? a.environment}</Badge>,
  },
  { key: "status", header: "Status", render: (a) => <StatusBadge status={a.status} /> },
  {
    key: "risk",
    header: "Session risk",
    render: (a) => (a.active_session_count > 0 ? <RiskMeter score={a.risk_score} level={a.risk_level} size="sm" label={`Risk of ${a.name}`} /> : <Muted>No active session</Muted>),
    className: "whitespace-nowrap",
  },
  {
    key: "findings",
    header: "Open findings",
    align: "right",
    render: (a) =>
      a.open_findings > 0 ? (
        <span className="inline-flex items-center justify-end gap-2">
          {a.max_open_severity && <SeverityBadge severity={a.max_open_severity} />}
          <span className="num text-fg">{a.open_findings}</span>
        </span>
      ) : (
        <Muted>0</Muted>
      ),
  },
  {
    key: "sessions",
    header: "Sessions",
    align: "right",
    hideBelow: "md",
    render: (a) => (
      <span className="num whitespace-nowrap" title={`${a.active_session_count} active of ${a.session_count}`}>
        {a.active_session_count > 0 && <span className="text-ok">{a.active_session_count} active · </span>}
        <span className="text-fg-muted">{a.session_count}</span>
      </span>
    ),
  },
  {
    key: "tools",
    header: "Tools",
    align: "right",
    hideBelow: "lg",
    render: (a) => (
      <span className="num whitespace-nowrap text-fg-muted" title={`${a.observed_tool_count} observed, ${a.declared_tool_count} declared`}>
        {a.observed_tool_count} <span className="text-fg-faint">obs</span> / {a.declared_tool_count} <span className="text-fg-faint">decl</span>
      </span>
    ),
  },
  {
    key: "last_seen",
    header: "Last seen",
    align: "right",
    hideBelow: "sm",
    render: (a) =>
      a.last_seen_at ? (
        <time dateTime={a.last_seen_at} title={formatDateTime(a.last_seen_at)} className="whitespace-nowrap text-fg-muted">
          {timeAgo(a.last_seen_at)}
        </time>
      ) : (
        <Muted>Never reported</Muted>
      ),
  },
];

function Muted({ children }: { children: ReactNode }) {
  return <span className="text-xs text-fg-faint">{children}</span>;
}

export function AgentsTable({ rows, loading, error, onRetry, empty }: { rows?: AgentSummary[]; loading: boolean; error: unknown; onRetry: () => void; empty: { title: string; description?: ReactNode; action?: ReactNode } }) {
  const navigate = useNavigate();
  return (
    <DataTable
      aria-label="Agents"
      columns={columns}
      rows={rows}
      rowKey={(a) => a.id}
      loading={loading}
      error={error}
      onRetry={onRetry}
      onRowClick={(a) => navigate(`/agents/${encodeURIComponent(a.id)}`)}
      manualSort
      empty={empty}
    />
  );
}
