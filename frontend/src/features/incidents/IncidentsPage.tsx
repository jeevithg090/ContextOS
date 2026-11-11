/**
 * Incidents — answers "what needs investigating?".
 *
 * Active incidents first (open / investigating before contained), most severe first. Filters live in
 * the URL so views are linkable; live `incident.*` events refresh the list (hooks/useLiveEvents).
 */
import { useCallback, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Plus, Siren } from "lucide-react";
import { DataTable, EntityLink, FilterBar, FilterSelect, Pagination, SearchInput, SegmentedControl, type DataTableColumn } from "@/components/data";
import { Button, Checkbox, Mono, PageHeader, SeverityBadge, SimulationBadge, StatusBadge } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { SEVERITY_META, type IncidentStatus, type Severity } from "@/lib/domain";
import { cn, formatDateTime, timeAgo } from "@/lib/format";
import { useIncidents } from "./api";
import { CreateIncidentDialog } from "./CreateIncidentDialog";
import { SEVERITY_OPTIONS } from "./meta";
import type { IncidentFilters, IncidentSort, IncidentSummary } from "./types";

type StatusView = "active" | "open" | "investigating" | "contained" | "closed" | "all";

const STATUS_VIEWS: Array<{ value: StatusView; label: string; statuses?: IncidentStatus[] }> = [
  { value: "active", label: "Active", statuses: ["open", "investigating", "contained"] },
  { value: "open", label: "Open", statuses: ["open"] },
  { value: "investigating", label: "Investigating", statuses: ["investigating"] },
  { value: "contained", label: "Contained", statuses: ["contained"] },
  { value: "closed", label: "Closed", statuses: ["resolved", "false_positive"] },
  { value: "all", label: "All" },
];

const SORTS: Array<{ value: IncidentSort; label: string }> = [
  { value: "priority", label: "Priority" },
  { value: "recent", label: "Newest" },
  { value: "updated", label: "Recently updated" },
];

const PAGE_SIZE = 50;

function viewFrom(params: URLSearchParams): StatusView {
  const v = params.get("view");
  return STATUS_VIEWS.some((s) => s.value === v) ? (v as StatusView) : "active";
}

function Findings({ row }: { row: IncidentSummary }) {
  if (row.finding_count === 0) return <span className="text-fg-faint">None</span>;
  return (
    <span className="num text-[13px]" title={`${row.open_finding_count} of ${row.finding_count} linked findings still open or acknowledged`}>
      <span className={cn(row.open_finding_count > 0 ? "text-fg" : "text-fg-muted")}>{row.open_finding_count}</span>
      <span className="text-fg-faint"> / {row.finding_count}</span>
    </span>
  );
}

const COLUMNS: Array<DataTableColumn<IncidentSummary>> = [
  { key: "severity", header: "Severity", width: 96, render: (r) => <SeverityBadge severity={r.severity} /> },
  {
    key: "title",
    header: "Incident",
    render: (r) => (
      <div className="flex min-w-0 items-center gap-2">
        <Mono className="shrink-0 text-2xs text-fg-faint">{r.key}</Mono>
        <span className="truncate font-medium text-fg">{r.title}</span>
        {r.is_simulation && <SimulationBadge />}
      </div>
    ),
  },
  { key: "status", header: "Status", width: 128, render: (r) => <StatusBadge status={r.status} /> },
  {
    key: "agent",
    header: "Agent",
    width: 160,
    hideBelow: "md",
    render: (r) => (r.primary_agent ? <EntityLink type="agent" id={r.primary_agent.id} label={r.primary_agent.name} /> : <span className="text-fg-faint">—</span>),
  },
  { key: "findings", header: <span title="Open / total linked findings">Findings</span>, width: 92, align: "right", render: (r) => <Findings row={r} /> },
  {
    key: "assignee",
    header: "Assignee",
    width: 140,
    hideBelow: "lg",
    render: (r) => (r.assignee ? <span className="truncate text-[13px]">{r.assignee.name}</span> : <span className="text-xs text-fg-faint">Unassigned</span>),
  },
  {
    key: "age",
    header: "Age",
    width: 112,
    align: "right",
    render: (r) => (
      <time dateTime={r.opened_at} title={`Opened ${formatDateTime(r.opened_at)}${r.resolved_at ? ` · closed ${formatDateTime(r.resolved_at)}` : ""}`} className="text-xs text-fg-muted">
        {timeAgo(r.opened_at)}
      </time>
    ),
  },
];

export function IncidentsPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const { me, can } = useAuth();
  const [creating, setCreating] = useState(false);

  const update = useCallback(
    (key: string, value: string | null) =>
      setParams(
        (current) => {
          const next = new URLSearchParams(current);
          if (key !== "offset") next.delete("offset"); // any filter change starts from the first page
          if (value === null || value === "") next.delete(key);
          else next.set(key, value);
          return next;
        },
        { replace: true },
      ),
    [setParams],
  );

  const view = viewFrom(params);
  const severity = params.get("severity") ?? "";
  const assignee = params.get("assignee") ?? "";
  const q = params.get("q") ?? "";
  const sort = (SORTS.find((s) => s.value === params.get("sort"))?.value ?? "priority") as IncidentSort;
  const includeSimulated = params.get("simulated") === "1";
  const offset = Math.max(0, Number(params.get("offset")) || 0);

  const filters: IncidentFilters = {
    status: STATUS_VIEWS.find((s) => s.value === view)?.statuses,
    severity: severity ? [severity as Severity] : undefined,
    q: q || undefined,
    assignee_user_id: assignee === "me" ? me?.user.id : undefined,
    unassigned: assignee === "unassigned" || undefined,
    include_simulated: includeSimulated || undefined,
    sort,
  };
  const query = useIncidents(filters, PAGE_SIZE, offset);
  const filtered = view !== "active" || !!severity || !!assignee || !!q || includeSimulated;

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Investigations that group related findings. Critical findings, and high-severity exfiltration or secret exposure, open one automatically; analysts can open more and group findings by hand."
        actions={
          can("write") ? (
            <Button variant="primary" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setCreating(true)}>
              New incident
            </Button>
          ) : undefined
        }
      />

      <FilterBar
        onClear={() => setParams(new URLSearchParams(), { replace: true })}
        canClear={filtered}
        actions={<FilterSelect label="Sort" value={sort} allLabel={null} onChange={(v) => update("sort", v === "priority" ? null : v)} options={SORTS} />}
      >
        <SegmentedControl<StatusView>
          aria-label="Status"
          value={view}
          onChange={(v) => update("view", v === "active" ? null : v)}
          options={STATUS_VIEWS.map((s) => ({ value: s.value, label: s.label }))}
        />
        <FilterSelect
          label="Severity"
          value={severity}
          onChange={(v) => update("severity", v)}
          options={SEVERITY_OPTIONS.map((s) => ({ value: s, label: SEVERITY_META[s].label }))}
        />
        <FilterSelect
          label="Assignee"
          value={assignee}
          allLabel="Anyone"
          onChange={(v) => update("assignee", v)}
          options={[
            ...(me ? [{ value: "me", label: "Assigned to me" }] : []),
            { value: "unassigned", label: "Unassigned" },
          ]}
        />
        <SearchInput value={q} onChange={(v) => update("q", v)} placeholder="Search title or INC-12" label="Search incidents" className="w-56" />
        <Checkbox label={<span className="text-xs text-fg-muted">Include simulations</span>} checked={includeSimulated} onChange={(v) => update("simulated", v ? "1" : null)} />
      </FilterBar>

      <div className="panel overflow-hidden">
        <DataTable
          aria-label="Incidents"
          columns={COLUMNS}
          rows={query.data?.items}
          rowKey={(r) => r.id}
          onRowClick={(r) => navigate(`/incidents/${encodeURIComponent(r.id)}`)}
          loading={query.isLoading}
          error={query.error}
          onRetry={() => void query.refetch()}
          manualSort
          empty={
            filtered
              ? { title: "No incidents match these filters", description: "Clear the filters or widen the status view.", icon: <Siren className="h-5 w-5" aria-hidden /> }
              : {
                  title: "No active incidents",
                  description: "Nothing needs investigating right now. Incidents open automatically from critical findings, or from Security Intelligence when an analyst groups findings.",
                  icon: <Siren className="h-5 w-5" aria-hidden />,
                }
          }
        />
        {query.data && query.data.total > PAGE_SIZE && (
          <Pagination
            total={query.data.total}
            limit={PAGE_SIZE}
            offset={offset}
            onChange={(next) => update("offset", next ? String(next) : null)}
            itemLabel="incidents"
            className="border-t border-border px-4 py-2"
          />
        )}
      </div>

      <CreateIncidentDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(detail) => navigate(`/incidents/${encodeURIComponent(detail.id)}`)}
      />
    </>
  );
}
