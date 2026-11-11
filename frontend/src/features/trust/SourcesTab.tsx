/** Sources tab: every context source agents consumed, how it is classified and what it may do. */
import { useEffect, useMemo } from "react";
import { Database } from "lucide-react";
import { Badge, SeverityBadge, SimulationBadge, TrustBadge } from "@/components/ui";
import { DataTable, FilterBar, FilterSelect, Pagination, SearchInput, type DataTableColumn, type SortState } from "@/components/data";
import { usePagination } from "@/hooks";
import { TRUST_LEVELS, TRUST_META, type TrustLevel } from "@/lib/domain";
import { formatNumber, timeAgo } from "@/lib/format";
import { useTrustSources } from "./api";
import { CapabilityChips } from "./components";
import { CAPABILITY_META, SOURCE_TYPE_LABELS, displayIdentifier, sourceTypeLabel } from "./meta";
import { SOURCE_TYPES, type Capability, type SourceFilters, type SourceSort, type TrustSource } from "./types";
import { boolParam, includeSimulatedParam, type SetParams } from "./urlState";

const SORT_FIELDS: Record<string, string> = {
  source: "identifier",
  trust: "trust",
  observations: "observations",
  findings: "findings",
  last_seen: "last_seen",
};

function toSortState(sort: string): SortState | null {
  const desc = sort.startsWith("-");
  const field = sort.replace(/^-/, "");
  const key = Object.keys(SORT_FIELDS).find((k) => SORT_FIELDS[k] === field);
  return key ? { key, direction: desc ? "desc" : "asc" } : null;
}

function classifiedBy(s: TrustSource) {
  if (s.manually_classified) return <Badge tone="accent">Manual</Badge>;
  if (s.trust_rule_name) return <span className="truncate text-xs text-fg-muted" title={`Trust rule: ${s.trust_rule_name}`}>{s.trust_rule_name}</span>;
  return <span className="text-xs text-fg-faint">Default</span>;
}

const COLUMNS: Array<DataTableColumn<TrustSource>> = [
  {
    key: "source",
    header: "Source",
    sortable: true,
    render: (s) => (
      <div className="min-w-0 max-w-[420px]">
        <div className="flex min-w-0 items-center gap-1.5">
          <span className="truncate text-[13px] text-fg" title={s.identifier}>
            {s.display_name || displayIdentifier(s.identifier)}
          </span>
          {s.is_simulation && <SimulationBadge />}
        </div>
        <div className="flex min-w-0 items-center gap-1.5 text-2xs text-fg-faint">
          <span className="shrink-0">{sourceTypeLabel(s.source_type)}</span>
          {s.display_name && <span className="truncate font-mono">{s.identifier}</span>}
        </div>
      </div>
    ),
  },
  { key: "trust", header: "Trust", sortable: true, render: (s) => <TrustBadge level={s.trust_level} /> },
  { key: "capabilities", header: "May", render: (s) => <CapabilityChips capabilities={s.trust_capabilities} />, hideBelow: "md" },
  { key: "classified_by", header: "Classified by", render: classifiedBy, hideBelow: "lg", className: "max-w-[180px]" },
  { key: "observations", header: "Seen", align: "right", sortable: true, render: (s) => formatNumber(s.observation_count), hideBelow: "sm" },
  {
    key: "findings",
    header: "Findings",
    align: "right",
    sortable: true,
    render: (s) =>
      s.finding_count ? (
        <span className="inline-flex items-center justify-end gap-1.5">
          {s.max_finding_severity && <SeverityBadge severity={s.max_finding_severity} />}
          <span className="num">{s.finding_count}</span>
        </span>
      ) : (
        <span className="text-fg-faint">0</span>
      ),
  },
  { key: "last_seen", header: "Last seen", align: "right", sortable: true, render: (s) => <span title={s.last_seen_at}>{timeAgo(s.last_seen_at)}</span>, hideBelow: "sm" },
];

export function SourcesTab({ params, set, onOpen }: { params: URLSearchParams; set: SetParams; onOpen: (id: string) => void }) {
  const q = params.get("sq") ?? "";
  const level = params.get("slevel") ?? "";
  const type = params.get("stype") ?? "";
  const cap = params.get("scap") ?? "";
  const manual = params.get("smanual") ?? "";
  const findings = params.get("sfind") ?? "";
  const sort = (params.get("ssort") ?? "-last_seen") as SourceSort;
  const includeSimulated = includeSimulatedParam(params);
  const page = usePagination(50);
  const filterKey = [q, level, type, cap, manual, findings, sort, includeSimulated].join("|");
  const { reset } = page;
  useEffect(() => reset(), [filterKey, reset]);

  const filters: SourceFilters = useMemo(
    () => ({
      q: q || undefined,
      trust_level: level ? [level as TrustLevel] : undefined,
      source_type: type || undefined,
      capability: (cap || undefined) as Capability | undefined,
      manual: boolParam(manual),
      has_findings: boolParam(findings),
      include_simulated: includeSimulated || undefined,
      sort,
      limit: page.limit,
      offset: page.offset,
    }),
    [q, level, type, cap, manual, findings, includeSimulated, sort, page.limit, page.offset],
  );
  const sources = useTrustSources(filters);
  const filtered = !!(q || level || type || cap || manual || findings);
  const clear = () => set({ sq: null, slevel: null, stype: null, scap: null, smanual: null, sfind: null });
  const selected = params.get("source");

  return (
    <div>
      <FilterBar
        onClear={clear}
        canClear={filtered}
        actions={sources.data && <span className="num text-xs text-fg-muted">{formatNumber(sources.data.total)} sources</span>}
      >
        <SearchInput value={q} onChange={(v) => set({ sq: v.trim() || null })} placeholder="Search identifier, name or domain" label="Search sources" className="w-64" />
        <FilterSelect label="Trust" value={level} onChange={(v) => set({ slevel: v || null })} options={TRUST_LEVELS.map((l) => ({ value: l, label: TRUST_META[l].label }))} />
        <FilterSelect label="Type" value={type} onChange={(v) => set({ stype: v || null })} options={SOURCE_TYPES.map((t) => ({ value: t, label: SOURCE_TYPE_LABELS[t] }))} />
        <FilterSelect
          label="May"
          value={cap}
          onChange={(v) => set({ scap: v || null })}
          allLabel="Anything"
          options={(["instruct", "execute", "credential_access"] as Capability[]).map((c) => ({ value: c, label: CAPABILITY_META[c].label }))}
        />
        <FilterSelect label="Classified" value={manual} onChange={(v) => set({ smanual: v || null })} options={[{ value: "yes", label: "Manually" }, { value: "no", label: "By rules" }]} />
        <FilterSelect label="Findings" value={findings} onChange={(v) => set({ sfind: v || null })} options={[{ value: "yes", label: "Has findings" }, { value: "no", label: "None" }]} />
      </FilterBar>
      <div className="panel">
        <DataTable
          aria-label="Context sources"
          columns={COLUMNS}
          rows={sources.data?.items}
          rowKey={(s) => s.id}
          onRowClick={(s) => onOpen(s.id)}
          selectedKey={selected}
          loading={sources.isLoading}
          error={sources.error}
          onRetry={() => void sources.refetch()}
          manualSort
          sort={toSortState(sort)}
          onSortChange={(next) => set({ ssort: next ? `${next.direction === "desc" ? "-" : ""}${SORT_FIELDS[next.key]}` : null })}
          empty={
            filtered
              ? { title: "No sources match these filters", description: "Clear the filters to see every source." }
              : {
                  icon: <Database className="h-5 w-5" aria-hidden />,
                  title: "No context sources recorded yet",
                  description: "Sources appear when an integration reports content an agent consumed — a web page, file, repository, MCP server or prompt.",
                }
          }
        />
      </div>
      {sources.data && (
        <Pagination total={sources.data.total} limit={page.limit} offset={page.offset} onChange={page.setOffset} onLimitChange={page.setLimit} itemLabel="sources" />
      )}
    </div>
  );
}
