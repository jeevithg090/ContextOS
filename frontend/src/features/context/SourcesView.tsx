/** Sources view of the Context Explorer: where context came from and what each source triggered. */
import { useEffect, useMemo } from "react";
import { Database } from "lucide-react";
import { Badge, Button, SeverityBadge, TrustBadge } from "@/components/ui";
import { DataTable, FilterBar, FilterSelect, Pagination, SearchInput, type DataTableColumn } from "@/components/data";
import { usePagination } from "@/hooks";
import { TRUST_LEVELS, TRUST_META } from "@/lib/domain";
import { formatDateTime, formatNumber, pluralize, timeAgo } from "@/lib/format";
import { useContextSources } from "./api";
import { clearedParams, hasActiveFilters, sourceFiltersFrom } from "./filters";
import { SOURCE_TYPES, sourceTypeMeta } from "./meta";
import { ButtonLink, SourceLabel } from "./parts";
import type { ContextSourceSummary } from "./types";

type Update = (fn: (params: URLSearchParams) => URLSearchParams) => void;

const COLUMNS: Array<DataTableColumn<ContextSourceSummary>> = [
  {
    key: "source",
    header: "Source",
    render: (r) => <SourceLabel type={r.source_type} identifier={r.identifier} displayName={r.display_name} className="max-w-[440px]" />,
  },
  {
    key: "trust",
    header: "Current trust",
    render: (r) => (
      <span className="inline-flex items-center gap-1.5">
        <TrustBadge level={r.trust_level} />
        {r.manually_classified && <Badge tone="accent" title="Classification set by a person">Manual</Badge>}
      </span>
    ),
  },
  { key: "items", header: "Items", align: "right", render: (r) => <span className="num">{formatNumber(r.item_count)}</span> },
  {
    key: "reach",
    header: "Reach",
    hideBelow: "md",
    render: (r) => (
      <span className="num text-xs text-fg-muted" title="Distinct agents and sessions that received content from this source">
        {pluralize(r.agent_count, "agent")} · {pluralize(r.session_count, "session")}
      </span>
    ),
  },
  {
    key: "detections",
    header: "Detections",
    align: "right",
    hideBelow: "md",
    render: (r) =>
      r.items_with_detections ? (
        <span className="num text-xs text-sev-high" title="Items from this source where a detection rule matched">
          {pluralize(r.items_with_detections, "item")}
        </span>
      ) : (
        <span className="text-xs text-fg-faint">None</span>
      ),
  },
  {
    key: "findings",
    header: "Findings",
    render: (r) =>
      r.finding_count ? (
        <span className="inline-flex items-center gap-1.5">
          {r.max_finding_severity && <SeverityBadge severity={r.max_finding_severity} />}
          <span className="num text-xs text-fg-muted">
            {formatNumber(r.open_finding_count)} open / {formatNumber(r.finding_count)}
          </span>
        </span>
      ) : (
        <span className="text-xs text-fg-faint">None</span>
      ),
  },
  {
    key: "last_seen",
    header: "Last seen",
    align: "right",
    render: (r) => (
      <time dateTime={r.last_seen_at} title={formatDateTime(r.last_seen_at)} className="whitespace-nowrap text-xs text-fg-muted">
        {timeAgo(r.last_seen_at)}
      </time>
    ),
  },
];

export function SourcesView({ params, update, selectedId, onOpen }: { params: URLSearchParams; update: Update; selectedId: string | null; onOpen: (id: string) => void }) {
  const search = params.toString();
  const filters = useMemo(() => sourceFiltersFrom(new URLSearchParams(search)), [search]);
  const { limit, offset, setOffset, setLimit, reset } = usePagination(50);
  const filterKey = JSON.stringify(filters);
  useEffect(() => reset(), [filterKey, reset]);
  const sources = useContextSources(filters, limit, offset);
  const filtered = hasActiveFilters(params, "sources");
  const set = (key: string, value: string | null) =>
    update((p) => {
      const next = new URLSearchParams(p);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    });
  const total = sources.data?.total ?? 0;

  const empty = filtered
    ? { title: "No sources match these filters", action: <Button size="sm" variant="outline" onClick={() => update(clearedParams)}>Clear filters</Button> }
    : {
        icon: <Database className="h-5 w-5" aria-hidden />,
        title: filters.include_simulated ? "No sources recorded yet" : "No sources from real agent activity yet",
        description: filters.include_simulated
          ? "A source is registered the first time an agent receives content from it."
          : "A source is registered the first time an agent receives content from it. Sources seen only by Simulation Lab runs are hidden unless you include simulations.",
        action: <ButtonLink to="/integrations">Connect an integration</ButtonLink>,
      };

  return (
    <div>
      <FilterBar
        onClear={() => update(clearedParams)}
        canClear={filtered}
        actions={sources.data && <span className="num text-xs text-fg-muted">{formatNumber(total)} sources</span>}
      >
        <SearchInput value={params.get("q") ?? ""} onChange={(v) => set("q", v.trim() || null)} placeholder="Search identifiers, names, domains…" label="Search sources" />
        <FilterSelect label="Type" value={params.get("type") ?? ""} onChange={(v) => set("type", v || null)} options={SOURCE_TYPES.map((t) => ({ value: t, label: sourceTypeMeta(t).label }))} />
        <FilterSelect label="Trust" value={params.get("strust") ?? ""} onChange={(v) => set("strust", v || null)} options={TRUST_LEVELS.map((t) => ({ value: t, label: TRUST_META[t].label }))} />
        <FilterSelect
          label="Findings"
          value={params.get("findings") ?? ""}
          onChange={(v) => set("findings", v || null)}
          allLabel="Any"
          options={[
            { value: "yes", label: "Raised findings" },
            { value: "no", label: "No findings" },
          ]}
        />
        <FilterSelect
          label="Sort"
          value={params.get("sort") ?? "last_seen"}
          onChange={(v) => set("sort", v === "last_seen" ? null : v)}
          allLabel={null}
          options={[
            { value: "last_seen", label: "Recently seen" },
            { value: "items", label: "Most items" },
            { value: "findings", label: "Most findings" },
          ]}
        />
      </FilterBar>

      <div className="panel overflow-hidden">
        <DataTable
          aria-label="Context sources"
          columns={COLUMNS}
          rows={sources.data?.items}
          rowKey={(r) => r.id}
          onRowClick={(r) => onOpen(r.id)}
          selectedKey={selectedId}
          loading={sources.isLoading}
          error={sources.error}
          onRetry={() => void sources.refetch()}
          manualSort
          dense
          empty={empty}
        />
      </div>
      <Pagination total={total} limit={limit} offset={offset} onChange={setOffset} onLimitChange={setLimit} itemLabel="sources" />
    </div>
  );
}
