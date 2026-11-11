/** Destinations tab: everywhere agents tried to send data, its classification and what happened. */
import { useEffect, useMemo } from "react";
import { Globe, Pin } from "lucide-react";
import { TrustBadge } from "@/components/ui";
import { DataTable, FilterBar, FilterSelect, Pagination, SearchInput, type DataTableColumn, type SortState } from "@/components/data";
import { usePagination } from "@/hooks";
import { TRUST_LEVELS, TRUST_META, type TrustLevel } from "@/lib/domain";
import { cn, formatNumber, timeAgo } from "@/lib/format";
import { useTrustDestinations } from "./api";
import { CheckIcon } from "./components";
import { DESTINATION_KIND_LABELS } from "./meta";
import type { DestinationFilters, DestinationSort, TrustDestination } from "./types";
import { boolParam, type SetParams } from "./urlState";

const SORT_FIELDS: Record<string, string> = {
  destination: "identifier",
  transfers: "transfers",
  blocked: "blocked",
  sensitive: "sensitive",
  last_seen: "last_seen",
};

function toSortState(sort: string): SortState | null {
  const field = sort.replace(/^-/, "");
  const key = Object.keys(SORT_FIELDS).find((k) => SORT_FIELDS[k] === field);
  return key ? { key, direction: sort.startsWith("-") ? "desc" : "asc" } : null;
}

function ChecksSummary({ d }: { d: TrustDestination }) {
  const v = d.verification;
  const parts: Array<[string, number]> = [
    ["fail", v.failed],
    ["warn", v.warned],
    ["pass", v.passed],
  ];
  const label = `${v.failed} failed, ${v.warned} warnings, ${v.passed} passed, ${v.unknown} not checked`;
  return (
    <span className="inline-flex items-center gap-2" aria-label={label} title={label}>
      {parts.map(([result, n]) => (
        <span key={result} className={cn("inline-flex items-center gap-0.5 text-xs", n ? "text-fg" : "text-fg-faint opacity-60")}>
          <CheckIcon result={result} className="h-3.5 w-3.5" />
          <span className="num">{n}</span>
        </span>
      ))}
    </span>
  );
}

const COLUMNS: Array<DataTableColumn<TrustDestination>> = [
  {
    key: "destination",
    header: "Destination",
    sortable: true,
    render: (d) => (
      <div className="min-w-0 max-w-[380px]">
        <div className="truncate font-mono text-[12.5px] text-fg" title={d.identifier}>
          {d.identifier}
        </div>
        <div className="text-2xs text-fg-faint">{DESTINATION_KIND_LABELS[d.kind] ?? d.kind}</div>
      </div>
    ),
  },
  {
    key: "classification",
    header: "Classification",
    render: (d) => (
      <span className="inline-flex items-center gap-1.5">
        <TrustBadge level={d.classification} />
        {d.override_rule_id && <Pin className="h-3.5 w-3.5 text-fg-muted" aria-label="Pinned by an exact-match rule" />}
      </span>
    ),
  },
  { key: "checks", header: "Checks", render: (d) => <ChecksSummary d={d} />, hideBelow: "md" },
  {
    key: "transfers",
    header: <span title="Calls ContextOS did not stop: allowed, or denied where the integration only advises or observes">Not stopped</span>,
    align: "right",
    sortable: true,
    render: (d) => formatNumber(d.transfer_count),
  },
  {
    key: "blocked",
    header: "Blocked",
    align: "right",
    sortable: true,
    render: (d) => <span className={d.blocked_count ? "text-dec-deny" : "text-fg-faint"}>{formatNumber(d.blocked_count)}</span>,
  },
  {
    key: "sensitive",
    header: "Sensitive",
    align: "right",
    sortable: true,
    hideBelow: "sm",
    render: (d) => <span className={d.sensitive_transfer_count ? "text-sev-high" : "text-fg-faint"}>{formatNumber(d.sensitive_transfer_count)}</span>,
  },
  { key: "last_seen", header: "Last seen", align: "right", sortable: true, hideBelow: "sm", render: (d) => <span title={d.last_seen_at}>{timeAgo(d.last_seen_at)}</span> },
];

export function DestinationsTab({ params, set, onOpen }: { params: URLSearchParams; set: SetParams; onOpen: (id: string) => void }) {
  const q = params.get("dq") ?? "";
  const level = params.get("dlevel") ?? "";
  const kind = params.get("dkind") ?? "";
  const blocked = params.get("dblocked") ?? "";
  const sort = (params.get("dsort") ?? "-last_seen") as DestinationSort;
  const page = usePagination(50);
  const { reset } = page;
  const filterKey = [q, level, kind, blocked, sort].join("|");
  useEffect(() => reset(), [filterKey, reset]);

  const filters: DestinationFilters = useMemo(
    () => ({
      q: q || undefined,
      classification: level ? [level as TrustLevel] : undefined,
      kind: kind || undefined,
      has_blocked: boolParam(blocked),
      sort,
      limit: page.limit,
      offset: page.offset,
    }),
    [q, level, kind, blocked, sort, page.limit, page.offset],
  );
  const destinations = useTrustDestinations(filters);
  const filtered = !!(q || level || kind || blocked);

  return (
    <div>
      <FilterBar
        onClear={() => set({ dq: null, dlevel: null, dkind: null, dblocked: null })}
        canClear={filtered}
        actions={destinations.data && <span className="num text-xs text-fg-muted">{formatNumber(destinations.data.total)} destinations</span>}
      >
        <SearchInput value={q} onChange={(v) => set({ dq: v.trim() || null })} placeholder="Search host, address or name" label="Search destinations" className="w-64" />
        <FilterSelect label="Classification" value={level} onChange={(v) => set({ dlevel: v || null })} options={TRUST_LEVELS.map((l) => ({ value: l, label: TRUST_META[l].label }))} />
        <FilterSelect
          label="Kind"
          value={kind}
          onChange={(v) => set({ dkind: v || null })}
          options={["domain", "ip", "email", "service", "agent", "unknown"].map((k) => ({ value: k, label: k === "unknown" ? "Unknown" : DESTINATION_KIND_LABELS[k] }))}
        />
        <FilterSelect label="Blocked calls" value={blocked} onChange={(v) => set({ dblocked: v || null })} options={[{ value: "yes", label: "At least one" }, { value: "no", label: "None" }]} />
      </FilterBar>
      <div className="panel">
        <DataTable
          aria-label="Destinations"
          columns={COLUMNS}
          rows={destinations.data?.items}
          rowKey={(d) => d.id}
          onRowClick={(d) => onOpen(d.id)}
          selectedKey={params.get("destination")}
          loading={destinations.isLoading}
          error={destinations.error}
          onRetry={() => void destinations.refetch()}
          manualSort
          sort={toSortState(sort)}
          onSortChange={(next) => set({ dsort: next ? `${next.direction === "desc" ? "-" : ""}${SORT_FIELDS[next.key]}` : null })}
          empty={
            filtered
              ? { title: "No destinations match these filters", description: "Clear the filters to see every destination." }
              : {
                  icon: <Globe className="h-5 w-5" aria-hidden />,
                  title: "No destinations recorded yet",
                  description: "Destinations appear when an agent's tool call targets a host, address, mailbox or service — whether the call was allowed or blocked.",
                }
          }
        />
      </div>
      {destinations.data && (
        <Pagination total={destinations.data.total} limit={page.limit} offset={page.offset} onChange={page.setOffset} onLimitChange={page.setLimit} itemLabel="destinations" />
      )}
      <p className="pt-1 text-2xs text-fg-faint">
        “Not stopped” counts calls ContextOS did not stop: allowed, or denied where the integration only advises or observes. “Blocked” counts
        calls denied at an integration that enforces decisions. Calls paused for approval are in neither, unless the integration only observes.
        “Sensitive” counts not-stopped calls that carried secrets or sensitive resources. Whether a call then ran is shown on each call.
      </p>
    </div>
  );
}
