/** Items view of the Context Explorer: every piece of context an agent received, newest first. */
import { useEffect, useMemo } from "react";
import { FileSearch, X } from "lucide-react";
import { Button, SimulationBadge, TrustBadge } from "@/components/ui";
import { DataTable, EntityLink, FilterBar, FilterSelect, Pagination, SearchInput, entityTypeLabel, type DataTableColumn } from "@/components/data";
import { usePagination } from "@/hooks";
import { formatDateTime, formatNumber, pluralize, shortId, timeAgo } from "@/lib/format";
import { useContextFacets, useContextItems } from "./api";
import { SINCE_PRESETS, clearedParams, hasActiveFilters, itemFiltersFrom, toggleValue } from "./filters";
import { SENSITIVITIES, SOURCE_TYPES, sensitivityMeta, sourceTypeMeta } from "./meta";
import { ButtonLink, DetectionCell, SensitivityBadge, SourceLabel } from "./parts";
import { TrustChips } from "./TrustChips";
import type { ContextItemSummary } from "./types";

type Update = (fn: (params: URLSearchParams) => URLSearchParams) => void;

const COLUMNS: Array<DataTableColumn<ContextItemSummary>> = [
  {
    key: "source",
    header: "Source",
    render: (r) => (
      <div className="flex min-w-0 items-center gap-2">
        <SourceLabel type={r.source.source_type} identifier={r.source.identifier} displayName={r.source.display_name} className="min-w-0 max-w-[420px]" />
        {r.is_simulation && <SimulationBadge />}
      </div>
    ),
  },
  { key: "trust", header: "Trust at ingest", render: (r) => <TrustBadge level={r.trust_level} /> },
  { key: "detection", header: "Detections", render: (r) => <DetectionCell detection={r.detection} /> },
  { key: "sensitivity", header: "Sensitivity", hideBelow: "md", render: (r) => <SensitivityBadge sensitivity={r.sensitivity} containsSecrets={r.contains_secrets} /> },
  { key: "agent", header: "Agent", hideBelow: "lg", render: (r) => <EntityLink type="agent" id={r.agent.id} label={r.agent.name} className="max-w-[160px]" /> },
  { key: "session", header: "Session", hideBelow: "lg", render: (r) => <EntityLink type="session" id={r.session.id} label={r.session.external_session_id} className="max-w-[160px]" /> },
  {
    key: "received",
    header: "Received",
    align: "right",
    render: (r) => (
      <time dateTime={r.received_at} title={`${formatDateTime(r.received_at)} (server time)`} className="whitespace-nowrap text-xs text-fg-muted">
        {timeAgo(r.received_at)}
      </time>
    ),
  },
];

export function ItemsView({ params, update, selectedId, onOpen }: { params: URLSearchParams; update: Update; selectedId: string | null; onOpen: (id: string) => void }) {
  const search = params.toString();
  const filters = useMemo(() => itemFiltersFrom(new URLSearchParams(search)), [search]);
  const { limit, offset, setOffset, setLimit, reset } = usePagination(50);
  const filterKey = JSON.stringify(filters);
  useEffect(() => reset(), [filterKey, reset]);

  const items = useContextItems(filters, limit, offset);
  const facets = useContextFacets(filters);
  const facetData = facets.data;
  const filtered = hasActiveFilters(params, "items");
  const set = (key: string, value: string | null) =>
    update((p) => {
      const next = new URLSearchParams(p);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    });

  const typeCounts = new Map((facetData?.by_source_type ?? []).map((f) => [f.value, f.count]));
  const sensitivityCounts = new Map((facetData?.by_sensitivity ?? []).map((f) => [f.value, f.count]));
  const scopes = (["agent", "session", "source"] as const).filter((k) => params.get(k));
  const total = items.data?.total ?? 0;
  const hiddenSimulated = !filters.include_simulated ? facetData?.simulated_total ?? 0 : 0;

  const empty = filtered
    ? { title: "No context matches these filters", action: <Button size="sm" variant="outline" onClick={() => update(clearedParams)}>Clear filters</Button> }
    : hiddenSimulated > 0
      ? {
          title: "No real agent activity recorded yet",
          description: `${pluralize(hiddenSimulated, "simulated item")} from the Simulation Lab ${hiddenSimulated === 1 ? "is" : "are"} hidden. Simulations run synthetic scenarios through the real pipeline.`,
          action: <Button size="sm" variant="outline" onClick={() => set("sim", "1")}>Show simulated items</Button>,
        }
      : {
          icon: <FileSearch className="h-5 w-5" aria-hidden />,
          title: "No context has been recorded yet",
          description: "Context appears here when an integration reports what an agent read — files, web pages, tool output, MCP responses and prompts.",
          action: <ButtonLink to="/integrations">Connect an integration</ButtonLink>,
        };

  return (
    <div>
      <FilterBar
        onClear={() => update(clearedParams)}
        canClear={filtered}
        actions={items.data && <span className="num text-xs text-fg-muted">{formatNumber(total)} items</span>}
      >
        <SearchInput value={params.get("q") ?? ""} onChange={(v) => set("q", v.trim() || null)} placeholder="Search previews, sources, hashes…" label="Search context" />
        <FilterSelect
          label="Type"
          value={params.get("type") ?? ""}
          onChange={(v) => set("type", v || null)}
          options={SOURCE_TYPES.map((t) => ({ value: t, label: sourceTypeMeta(t).label, count: typeCounts.get(t) ?? 0 })).filter((o) => o.count > 0 || o.value === params.get("type"))}
        />
        <FilterSelect
          label="Sensitivity"
          value={params.get("sensitivity") ?? ""}
          onChange={(v) => set("sensitivity", v || null)}
          options={SENSITIVITIES.map((s) => ({ value: s, label: sensitivityMeta(s).label, count: sensitivityCounts.get(s) ?? 0 }))}
        />
        <FilterSelect
          label="Received"
          value={params.get("since") ?? ""}
          onChange={(v) => set("since", v || null)}
          allLabel="Any time"
          options={Object.entries(SINCE_PRESETS).map(([value, p]) => ({ value, label: p.label }))}
        />
        {scopes.map((key) => (
          <span key={key} className="inline-flex h-7 items-center gap-1 rounded-md border border-accent/40 bg-accent/10 pl-2 pr-1 text-xs text-fg">
            {entityTypeLabel(key)} <span className="font-mono text-2xs">{shortId(params.get(key))}</span>
            <button type="button" onClick={() => set(key, null)} aria-label={`Remove ${key} filter`} className="inline-flex h-5 w-5 items-center justify-center rounded text-fg-muted hover:bg-surface-3 hover:text-fg">
              <X className="h-3 w-3" aria-hidden />
            </button>
          </span>
        ))}
      </FilterBar>

      <TrustChips
        facets={facetData}
        loading={facets.isLoading}
        selected={params.getAll("trust")}
        onToggle={(level) => update((p) => toggleValue(p, "trust", level))}
        onClear={() => set("trust", null)}
        detectionsOnly={params.get("detections") === "yes"}
        onToggleDetections={() => set("detections", params.get("detections") === "yes" ? null : "yes")}
        secretsOnly={params.get("secrets") === "yes"}
        onToggleSecrets={() => set("secrets", params.get("secrets") === "yes" ? null : "yes")}
      />

      <div className="panel overflow-hidden">
        <DataTable
          aria-label="Context items"
          columns={COLUMNS}
          rows={items.data?.items}
          rowKey={(r) => r.id}
          onRowClick={(r) => onOpen(r.id)}
          selectedKey={selectedId}
          loading={items.isLoading}
          error={items.error}
          onRetry={() => void items.refetch()}
          manualSort
          dense
          empty={empty}
        />
      </div>
      <Pagination total={total} limit={limit} offset={offset} onChange={setOffset} onLimitChange={setLimit} itemLabel="items" />
    </div>
  );
}
