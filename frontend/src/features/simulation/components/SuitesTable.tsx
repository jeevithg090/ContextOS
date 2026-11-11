import { useState } from "react";
import { Layers } from "lucide-react";
import { DataTable, EntityLink, Pagination, Section, type DataTableColumn } from "@/components/data";
import { Button } from "@/components/ui";
import { cn, formatDateTime, shortId, timeAgo } from "@/lib/format";
import { useSuites } from "../api";
import { passRate } from "../logic";
import type { SuiteSummary } from "../types";

const PAGE_SIZE = 10;

export interface SuitesTableProps {
  selectedSuiteId: string | null;
  onShowRuns: (suiteRunId: string) => void;
  onCompare: (base: string, head: string) => void;
}

/** Regression suites (runs started together), newest first, with pass rate and a quick compare. */
export function SuitesTable({ selectedSuiteId, onShowRuns, onCompare }: SuitesTableProps) {
  const [offset, setOffset] = useState(0);
  const suites = useSuites(PAGE_SIZE, offset);
  const rows = suites.data?.items;

  const columns: Array<DataTableColumn<SuiteSummary>> = [
    {
      key: "suite",
      header: "Suite",
      render: (s) => (
        <div className="min-w-0">
          <div className="font-mono text-xs text-fg">{shortId(s.suite_run_id)}</div>
          <div className="text-2xs text-fg-faint" title={formatDateTime(s.started_at)}>
            {timeAgo(s.started_at)}
          </div>
        </div>
      ),
    },
    {
      key: "pass_rate",
      header: "Pass rate",
      align: "right",
      render: (s) => {
        const rate = passRate(s);
        return (
          <div className="text-right">
            <div className={cn("font-medium", s.failed_count > 0 ? "text-danger" : "text-fg")}>{rate === null ? "—" : `${rate}%`}</div>
            <div className="text-2xs text-fg-faint">
              {s.passed_count}/{s.run_count} passed
            </div>
          </div>
        );
      },
    },
    {
      key: "agent",
      header: "Agent / version",
      hideBelow: "sm",
      render: (s) => (
        <div className="min-w-0 text-xs">
          {s.agent_id ? <EntityLink type="agent" id={s.agent_id} /> : <span className="text-fg-muted">Simulated agent</span>}
          <div className="text-2xs text-fg-faint">{s.agent_version ? `v${s.agent_version}` : "no version recorded"}</div>
        </div>
      ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      render: (s, index) => {
        const previous = rows?.[index + 1];
        return (
          <div className="flex flex-wrap justify-end gap-1">
            <Button size="xs" variant="ghost" onClick={() => onShowRuns(s.suite_run_id)} aria-label={`Show runs of suite ${s.suite_run_id}`}>
              Runs
            </Button>
            {previous && (
              <Button
                size="xs"
                variant="outline"
                onClick={() => onCompare(previous.suite_run_id, s.suite_run_id)}
                aria-label={`Compare suite ${s.suite_run_id} with the previous suite ${previous.suite_run_id}`}
              >
                <span className="hidden sm:inline">Compare with previous</span>
                <span className="sm:hidden">Compare</span>
              </Button>
            )}
          </div>
        );
      },
    },
  ];

  return (
    <Section title="Regression suites" description="Scenarios run together as one suite. Pass rate is the share of scenarios whose checks all passed." flush>
      <DataTable
        aria-label="Regression suites"
        columns={columns}
        rows={rows}
        rowKey={(s) => s.suite_run_id}
        onRowClick={(s) => onShowRuns(s.suite_run_id)}
        selectedKey={selectedSuiteId}
        loading={suites.isLoading}
        error={suites.error}
        onRetry={() => void suites.refetch()}
        manualSort
        dense
        empty={{ title: "No suites yet", description: "Use “Run all as suite” on the Scenarios tab to run the whole catalogue as one suite.", icon: <Layers className="h-5 w-5" /> }}
      />
      {suites.data && (
        <Pagination className="border-t border-border px-4" total={suites.data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} itemLabel="suites" />
      )}
    </Section>
  );
}
