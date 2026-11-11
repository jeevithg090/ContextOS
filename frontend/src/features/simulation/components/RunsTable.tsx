import { useState } from "react";
import { History, X } from "lucide-react";
import { DataTable, EntityLink, FilterBar, FilterSelect, Pagination, Section, type DataTableColumn } from "@/components/data";
import { SimulationBadge } from "@/components/ui";
import { formatDateTime, shortId, timeAgo } from "@/lib/format";
import { useAgentOptions, useRuns } from "../api";
import type { RunFilters, Scenario, SimulationRun } from "../types";
import type { ParamUpdate } from "../urlState";
import { VerdictBadge } from "./VerdictBadge";

const PAGE_SIZE = 25;

const VERDICT_OPTIONS = [
  { value: "passed", label: "All checks passed" },
  { value: "failed", label: "Checks failed" },
];

export interface RunsTableProps {
  filters: RunFilters;
  scenarios: Scenario[] | undefined;
  selectedRunId: string | null;
  onOpenRun: (runId: string) => void;
  onFilterChange: (updates: ParamUpdate) => void;
}

/** Recent runs, newest first, with URL-backed filters (scenario, verdict, agent, suite). */
export function RunsTable({ filters, scenarios, selectedRunId, onOpenRun, onFilterChange }: RunsTableProps) {
  // Offset belongs to one filter combination: changing a filter goes back to the first page.
  const filterKey = JSON.stringify(filters);
  const [page, setPage] = useState<{ key: string; offset: number }>({ key: filterKey, offset: 0 });
  const offset = page.key === filterKey ? page.offset : 0;
  const runs = useRuns(filters, PAGE_SIZE, offset);
  const agents = useAgentOptions();

  const verdict = filters.passed === undefined ? "" : filters.passed ? "passed" : "failed";
  const hasFilters = Object.keys(filters).length > 0;

  const columns: Array<DataTableColumn<SimulationRun>> = [
    {
      key: "scenario",
      header: "Scenario",
      render: (r) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-fg">{r.scenario_name}</div>
          {r.suite_run_id && <div className="font-mono text-2xs text-fg-faint">suite {shortId(r.suite_run_id)}</div>}
        </div>
      ),
    },
    { key: "verdict", header: "Verdict", render: (r) => <VerdictBadge run={r} /> },
    {
      key: "checks",
      header: "Checks",
      align: "right",
      render: (r) => (
        <span title={`${r.checks_passed} of ${r.checks_total} checks passed`}>
          {r.checks_passed}/{r.checks_total}
        </span>
      ),
    },
    {
      key: "agent",
      header: "Agent / version",
      hideBelow: "md",
      render: (r) => (
        <div className="min-w-0 text-xs">
          {r.agent_id ? <EntityLink type="agent" id={r.agent_id} label={agents.data?.find((a) => a.id === r.agent_id)?.name} /> : <span className="text-fg-muted">Simulated agent</span>}
          <div className="text-2xs text-fg-faint">{r.agent_version ? `v${r.agent_version}` : "no version recorded"}</div>
        </div>
      ),
    },
    {
      key: "started_at",
      header: "Started",
      hideBelow: "sm",
      render: (r) => (
        <span className="whitespace-nowrap text-xs text-fg-muted" title={formatDateTime(r.started_at)}>
          {timeAgo(r.started_at)}
        </span>
      ),
    },
  ];

  return (
    <Section
      title={
        <span className="inline-flex items-center gap-2">
          Recent runs <SimulationBadge />
        </span>
      }
      description="Every run of a scenario, newest first. Open one to see its checks, steps and evidence."
      flush
    >
      <FilterBar className="px-4 pt-3" onClear={() => onFilterChange({ scenario: null, verdict: null, agent: null, suite: null })} canClear={hasFilters} aria-label="Run filters">
        <FilterSelect
          label="Scenario"
          value={filters.scenario_id ?? ""}
          onChange={(v) => onFilterChange({ scenario: v })}
          options={(scenarios ?? []).map((s) => ({ value: s.id, label: s.name }))}
        />
        <FilterSelect label="Verdict" value={verdict} onChange={(v) => onFilterChange({ verdict: v })} options={VERDICT_OPTIONS} />
        <FilterSelect
          label="Agent"
          value={filters.agent_id ?? ""}
          onChange={(v) => onFilterChange({ agent: v })}
          options={(agents.data ?? []).map((a) => ({ value: a.id, label: a.name }))}
          disabled={agents.isLoading}
        />
        {filters.suite_run_id && (
          <button
            type="button"
            onClick={() => onFilterChange({ suite: null })}
            className="inline-flex h-7 items-center gap-1 rounded border border-accent/40 px-2 font-mono text-2xs text-fg hover:bg-surface-2"
            aria-label={`Remove suite filter ${filters.suite_run_id}`}
          >
            suite {shortId(filters.suite_run_id)}
            <X className="h-3 w-3" aria-hidden />
          </button>
        )}
      </FilterBar>
      <DataTable
        aria-label="Simulation runs"
        columns={columns}
        rows={runs.data?.items}
        rowKey={(r) => r.id}
        onRowClick={(r) => onOpenRun(r.id)}
        selectedKey={selectedRunId}
        loading={runs.isLoading}
        error={runs.error}
        onRetry={() => void runs.refetch()}
        manualSort
        empty={
          hasFilters
            ? { title: "No runs match these filters", description: "Clear a filter to see more runs." }
            : { title: "No simulation runs yet", description: "Run a scenario from the Scenarios tab; each run appears here with its verdict.", icon: <History className="h-5 w-5" /> }
        }
      />
      {runs.data && (
        <Pagination
          className="border-t border-border px-4"
          total={runs.data.total}
          limit={PAGE_SIZE}
          offset={offset}
          onChange={(next) => setPage({ key: filterKey, offset: next })}
          itemLabel="runs"
        />
      )}
    </Section>
  );
}
