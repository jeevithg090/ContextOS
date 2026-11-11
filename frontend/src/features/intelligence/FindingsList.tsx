/** The findings list: filters (URL state), table and per-row quick triage. */
import { useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Check, CheckCheck, Radar, ShieldOff, X } from "lucide-react";
import { DataTable, EntityLink, FilterBar, FilterSelect, Pagination, SearchInput, entityTypeLabel, type DataTableColumn } from "@/components/data";
import { Button, Checkbox, IconButton, SeverityBadge, SimulationBadge, StatusBadge, TrustBadge } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { usePagination } from "@/hooks";
import { SEVERITIES, SEVERITY_META, TONE_CLASSES } from "@/lib/domain";
import { cn, formatDateTime, formatNumber, pluralize, shortId, timeAgo, truncate } from "@/lib/format";
import { useFindings } from "./api";
import { SCOPE_KEYS, clearedParams, findingFiltersFrom, hasActiveFilters, includeSimulated, selectedStatuses, setParam, toggleStatus, toggleValue } from "./filters";
import { SORT_OPTIONS, STATUS_OPTIONS, TRANSITIONS, categoryLabel, type TriageAction } from "./meta";
import type { FindingStats, FindingSummary } from "./types";
import { useTriage } from "./useTriage";

type Update = (fn: (params: URLSearchParams) => URLSearchParams) => void;

function Chip({ active, onClick, children, label }: { active: boolean; onClick: () => void; children: React.ReactNode; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      aria-label={label}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-xs transition-colors",
        active ? "border-accent/50 bg-accent/10 text-fg" : "border-border text-fg-muted hover:bg-surface-2 hover:text-fg",
      )}
    >
      {children}
    </button>
  );
}

function QuickActions({ row, busy, onAction }: { row: FindingSummary; busy: boolean; onAction: (action: TriageAction, row: FindingSummary) => void }) {
  const allowed = TRANSITIONS[row.status] ?? [];
  const actions: Array<{ action: TriageAction; label: string; icon: React.ReactNode }> = [
    { action: "acknowledged", label: "Acknowledge", icon: <Check className="h-3.5 w-3.5" aria-hidden /> },
    { action: "resolved", label: "Resolve…", icon: <CheckCheck className="h-3.5 w-3.5" aria-hidden /> },
    { action: "false_positive", label: "Mark false positive…", icon: <ShieldOff className="h-3.5 w-3.5" aria-hidden /> },
  ];
  const shown = actions.filter((a) => allowed.includes(a.action));
  if (shown.length === 0) return null;
  return (
    <div className="flex items-center justify-end gap-0.5" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
      {shown.map((a) => (
        <IconButton key={a.action} label={`${a.label} ${row.title}`} title={a.label} disabled={busy} onClick={() => onAction(a.action, row)} className="disabled:opacity-40">
          {a.icon}
        </IconButton>
      ))}
    </div>
  );
}

export function FindingsList({ params, update, stats }: { params: URLSearchParams; update: Update; stats: FindingStats | undefined }) {
  const navigate = useNavigate();
  const { can } = useAuth();
  const canWrite = can("write");
  const search = params.toString();
  const filters = useMemo(() => findingFiltersFrom(new URLSearchParams(search)), [search]);
  const { limit, offset, setOffset, setLimit, reset } = usePagination(50);
  const filterKey = JSON.stringify(filters);
  useEffect(() => reset(), [filterKey, reset]);

  const list = useFindings(filters, limit, offset);
  const triage = useTriage();
  const statuses = selectedStatuses(params);
  const severities = params.getAll("severity");
  const filtered = hasActiveFilters(params);
  const total = list.data?.total ?? 0;
  const set = (key: string, value: string | null) => update((p) => setParam(p, key, value));

  const columns: Array<DataTableColumn<FindingSummary>> = [
    { key: "severity", header: "Severity", width: 92, render: (r) => <SeverityBadge severity={r.severity} /> },
    {
      key: "title",
      header: "Finding",
      render: (r) => (
        <div className="min-w-0 max-w-[560px]">
          <div className="flex min-w-0 items-center gap-2">
            <span className="truncate font-medium text-fg" title={r.title}>
              {r.title}
            </span>
            {r.is_simulation && <SimulationBadge />}
          </div>
          <div className="mt-0.5 flex min-w-0 items-center gap-1.5 text-2xs text-fg-faint">
            <span>{categoryLabel(r.category)}</span>
            <span aria-hidden>·</span>
            <span className="truncate font-mono">{r.rule_id}</span>
          </div>
        </div>
      ),
    },
    {
      key: "agent",
      header: "Agent / session",
      hideBelow: "lg",
      render: (r) => (
        <div className="flex min-w-0 flex-col gap-0.5">
          <EntityLink type="agent" id={r.agent?.id} label={r.agent?.name} className="max-w-[170px]" />
          {r.session && <EntityLink type="session" id={r.session.id} label={r.session.external_session_id} showIcon={false} className="max-w-[170px] text-2xs" />}
        </div>
      ),
    },
    {
      key: "source",
      header: "Source",
      hideBelow: "lg",
      render: (r) =>
        r.source ? (
          <div className="flex min-w-0 items-center gap-1.5">
            <span className="truncate text-xs text-fg-muted" title={r.source.identifier}>
              {truncate(r.source.display_name || r.source.identifier, 44)}
            </span>
            <TrustBadge level={r.source.trust_level} />
          </div>
        ) : (
          <span className="text-xs text-fg-faint">—</span>
        ),
    },
    {
      key: "occurrences",
      header: "Seen",
      align: "right",
      hideBelow: "md",
      render: (r) => (
        <span className="num font-mono text-xs text-fg-muted" title={`Detected ${pluralize(r.occurrence_count, "time")} (repeats are merged into one finding)`}>
          ×{formatNumber(r.occurrence_count)}
        </span>
      ),
    },
    {
      key: "last_seen",
      header: "Last seen",
      align: "right",
      render: (r) => (
        <time dateTime={r.last_seen_at} title={`Last seen ${formatDateTime(r.last_seen_at)} · first seen ${formatDateTime(r.first_seen_at)}`} className="whitespace-nowrap text-xs text-fg-muted">
          {timeAgo(r.last_seen_at)}
        </time>
      ),
    },
    {
      key: "status",
      header: "Status",
      hideBelow: "sm",
      render: (r) => (
        <div className="flex flex-col items-start gap-0.5">
          <StatusBadge status={r.status} />
          {r.incident && <EntityLink type="incident" id={r.incident.id} label={`INC-${r.incident.number}`} showIcon={false} className="text-2xs" />}
        </div>
      ),
    },
    ...(canWrite
      ? [{ key: "actions", header: <span className="sr-only">Quick triage</span>, align: "right" as const, width: 100, render: (r: FindingSummary) => <QuickActions row={r} busy={triage.busyId === r.id} onAction={(a, row) => triage.start(a, row)} /> }]
      : []),
  ];

  const empty = filtered
    ? { title: "No findings match these filters", action: <Button size="sm" variant="outline" onClick={() => update(clearedParams)}>Clear filters</Button> }
    : !includeSimulated(params) && (stats?.simulated_open ?? 0) > 0
      ? {
          title: "Nothing open from real agent activity",
          description: `${pluralize(stats?.simulated_open ?? 0, "simulated finding")} from the Simulation Lab ${stats?.simulated_open === 1 ? "is" : "are"} hidden.`,
          action: <Button size="sm" variant="outline" onClick={() => set("sim", "1")}>Show simulated findings</Button>,
        }
      : {
          icon: <Radar className="h-5 w-5" aria-hidden />,
          title: "Nothing needs attention",
          description: "No open or acknowledged findings. ContextOS raises one when an agent reads manipulative content, touches credentials, or tries to send data somewhere risky.",
          action: <Button size="sm" variant="outline" onClick={() => update((p) => toggleStatus(p, "resolved"))}>Show resolved findings</Button>,
        };

  return (
    <section aria-label="Findings">
      <FilterBar onClear={() => update(clearedParams)} canClear={filtered} actions={list.data && <span className="num text-xs text-fg-muted">{pluralize(total, "finding")}</span>}>
        <SearchInput value={params.get("q") ?? ""} onChange={(v) => set("q", v.trim() || null)} placeholder="Search titles, rules, explanations…" label="Search findings" />
        <FilterSelect
          label="Category"
          value={params.get("category") ?? ""}
          onChange={(v) => set("category", v || null)}
          options={(stats?.categories ?? []).map((c) => ({ value: c.category, label: categoryLabel(c.category), count: c.count }))}
        />
        <FilterSelect label="Agent" value={params.get("agent") ?? ""} onChange={(v) => set("agent", v || null)} options={(stats?.agents ?? []).map((a) => ({ value: a.id, label: a.name, count: a.count }))} />
        <FilterSelect label="Sort" value={params.get("sort") ?? "severity"} onChange={(v) => set("sort", v === "severity" ? null : v)} allLabel={null} options={SORT_OPTIONS.map((o) => ({ value: o.value, label: o.label }))} />
        {SCOPE_KEYS.filter((k) => params.get(k)).map((key) => (
          <span key={key} className="inline-flex h-7 items-center gap-1 rounded-md border border-accent/40 bg-accent/10 pl-2 pr-1 text-xs text-fg">
            {entityTypeLabel(key)} <span className="font-mono text-2xs">{shortId(params.get(key))}</span>
            <button type="button" onClick={() => set(key, null)} aria-label={`Remove ${key} filter`} className="inline-flex h-5 w-5 items-center justify-center rounded text-fg-muted hover:bg-surface-3 hover:text-fg">
              <X className="h-3 w-3" aria-hidden />
            </button>
          </span>
        ))}
      </FilterBar>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 pb-3">
        <div role="group" aria-label="Status" className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-fg-faint">Status</span>
          {STATUS_OPTIONS.map((s) => (
            <Chip key={s.value} active={statuses.length === 0 || statuses.includes(s.value)} onClick={() => update((p) => toggleStatus(p, s.value))} label={`Status ${s.label}`}>
              <span title={s.description}>{s.label}</span>
            </Chip>
          ))}
        </div>
        <div role="group" aria-label="Severity" className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-fg-faint">Severity</span>
          {SEVERITIES.map((s) => (
            <Chip key={s} active={severities.includes(s)} onClick={() => update((p) => toggleValue(p, "severity", s))} label={`Severity ${SEVERITY_META[s].label}`}>
              <span className={cn("h-1.5 w-1.5 rounded-full", TONE_CLASSES[SEVERITY_META[s].tone].dot)} aria-hidden />
              {SEVERITY_META[s].label}
            </Chip>
          ))}
        </div>
        <div className="ml-auto">
          <Checkbox label={<span className="text-xs text-fg-muted">Include simulated</span>} checked={includeSimulated(params)} onChange={(v) => set("sim", v ? "1" : null)} />
        </div>
      </div>

      <div className="panel overflow-hidden">
        <DataTable
          aria-label="Findings"
          columns={columns}
          rows={list.data?.items}
          rowKey={(r) => r.id}
          onRowClick={(r) => navigate(`/intelligence/${encodeURIComponent(r.id)}`)}
          loading={list.isLoading}
          error={list.error}
          onRetry={() => void list.refetch()}
          manualSort
          dense
          rowClassName={(r) => (r.status === "resolved" || r.status === "false_positive" ? "opacity-70" : undefined)}
          empty={empty}
        />
      </div>
      <Pagination total={total} limit={limit} offset={offset} onChange={setOffset} onLimitChange={setLimit} itemLabel="findings" />
      {triage.dialog}
    </section>
  );
}
