/** Decision history: approved, rejected and expired requests, latest decision first, with who and when. */
import { History } from "lucide-react";
import { DataTable, Pagination, type DataTableColumn } from "@/components/data";
import { SimulationBadge, StatusBadge } from "@/components/ui";
import { formatDateTime, timeAgo, truncate } from "@/lib/format";
import { decidedByLabel } from "./meta";
import type { Approval } from "./types";

function waited(a: Approval): string {
  if (!a.decided_at) return "—";
  const s = Math.max(0, Math.round((Date.parse(a.decided_at) - Date.parse(a.requested_at)) / 1000));
  if (s < 120) return `${s}s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  return `${Math.round(s / 3600)} h`;
}

const COLUMNS: Array<DataTableColumn<Approval>> = [
  { key: "status", header: "Outcome", width: 104, render: (a) => <StatusBadge status={a.status} /> },
  {
    key: "action",
    header: "Request",
    render: (a) => (
      <div className="min-w-0">
        <div className="truncate text-xs text-fg-muted">
          <span className="font-medium text-fg">{a.agent.name ?? "Unknown agent"}</span>
          {a.is_simulation && (
            <span className="ml-1.5 align-middle">
              <SimulationBadge />
            </span>
          )}
        </div>
        <div className="truncate text-[13px] text-fg" title={a.summary}>
          {a.action}
        </div>
      </div>
    ),
  },
  {
    key: "policy",
    header: "Paused by",
    hideBelow: "lg",
    render: (a) => <span className="line-clamp-2 text-xs text-fg-muted">{a.policy_decision?.deciding_policy?.name ?? "Default decision"}</span>,
  },
  {
    key: "decided_by",
    header: "Decided by",
    hideBelow: "md",
    render: (a) => (
      <div className="min-w-0 text-xs">
        <div className="truncate text-fg">{decidedByLabel(a)}</div>
        {a.decision_note && (
          <div className="truncate text-fg-faint" title={a.decision_note}>
            “{truncate(a.decision_note, 60)}”
          </div>
        )}
      </div>
    ),
  },
  {
    key: "decided_at",
    header: "When",
    width: 120,
    render: (a) => (
      <div className="text-xs" title={formatDateTime(a.decided_at)}>
        <div className="text-fg">{timeAgo(a.decided_at)}</div>
        <div className="num text-fg-faint">waited {waited(a)}</div>
      </div>
    ),
  },
];

export interface HistoryListProps {
  rows: Approval[] | undefined;
  total: number;
  limit: number;
  offset: number;
  onPage: (offset: number) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}

export function HistoryList({ rows, total, limit, offset, onPage, selectedId, onSelect, loading, error, onRetry }: HistoryListProps) {
  return (
    <div>
      <DataTable
        columns={COLUMNS}
        rows={rows}
        rowKey={(a) => a.id}
        onRowClick={(a) => onSelect(a.id)}
        selectedKey={selectedId}
        loading={loading}
        error={error}
        onRetry={onRetry}
        manualSort
        dense
        aria-label="Decided and expired approval requests"
        empty={{
          icon: <History className="h-5 w-5" />,
          title: "No decisions yet",
          description: "Approved, rejected and expired requests are listed here with who decided and when.",
        }}
      />
      <Pagination total={total} limit={limit} offset={offset} onChange={onPage} itemLabel="decisions" className="border-t border-border px-4" />
    </div>
  );
}
