import { useEffect } from "react";
import { Link } from "react-router-dom";
import { FilterBar, FilterSelect, Pagination, SearchInput } from "@/components/data";
import { Checkbox, PageHeader } from "@/components/ui";
import { SEVERITIES, SEVERITY_META } from "@/lib/domain";
import { usePagination } from "@/hooks";
import { useRemediationPipeline } from "./analytics/api";
import { RemediationPipeline } from "./analytics/RemediationPipeline";
import { RemediationTable } from "./analytics/RemediationTable";
import { REMEDIATION_META } from "./analytics/taskMeta";
import { REMEDIATION_STATES } from "./analytics/types";
import { oneOf, useUrlState } from "./analytics/useUrlState";

/** "Which findings still need fixing?" — every open finding and where its fix stands. */
export function RemediationPage() {
  const { get, set } = useUrlState();
  const state = oneOf(get("state"), REMEDIATION_STATES);
  const severity = oneOf(get("severity"), SEVERITIES);
  const q = get("q");
  const includeSimulations = get("simulations") !== "exclude";
  const pagination = usePagination(50);
  const { reset } = pagination;

  useEffect(() => reset(), [state, severity, q, includeSimulations, reset]);

  const query = useRemediationPipeline({
    state,
    severity,
    q: q || undefined,
    include_simulations: includeSimulations,
    ...pagination.params,
  });
  const page = query.data;
  const filtered = !!(state || severity || q);

  return (
    <>
      <PageHeader
        eyebrow="Engineering Workspace"
        title="Security Remediation"
        description="Which findings still need fixing? Every open finding, most severe first, and where its fix stands — from no task, through work in progress, to a fix proven by a passed verification run."
        actions={
          <Link to="/work/analytics" className="text-xs text-accent hover:text-accent-strong">
            Remediation analytics
          </Link>
        }
      />
      <div className="space-y-4">
        <RemediationPipeline counts={page?.counts} selected={state} onSelect={(s) => set({ state: s })} loading={query.isLoading} />
        <div className="panel">
          <FilterBar
            className="border-b border-border px-4 pt-3"
            canClear={filtered}
            onClear={() => set({ state: null, severity: null, q: null })}
            actions={
              <Checkbox label="Include Simulation Lab findings" checked={includeSimulations} onChange={(v) => set({ simulations: v ? null : "exclude" })} />
            }
          >
            <SearchInput value={q} onChange={(v) => set({ q: v })} placeholder="Search finding titles…" label="Search findings" className="w-64" />
            <FilterSelect
              label="Severity"
              value={severity ?? ""}
              onChange={(v) => set({ severity: v })}
              options={SEVERITIES.map((s) => ({ value: s, label: SEVERITY_META[s].label }))}
            />
            <FilterSelect
              label="Stage"
              value={state ?? ""}
              onChange={(v) => set({ state: v })}
              allLabel="All open"
              options={REMEDIATION_STATES.map((s) => ({ value: s, label: REMEDIATION_META[s].label, count: page?.counts[s] }))}
            />
          </FilterBar>
          <RemediationTable rows={page?.items} loading={query.isLoading} error={query.error} onRetry={() => void query.refetch()} filtered={filtered} />
          {page && (
            <div className="border-t border-border px-3">
              <Pagination
                total={page.total}
                limit={pagination.limit}
                offset={pagination.offset}
                onChange={pagination.setOffset}
                onLimitChange={pagination.setLimit}
                pageSizeOptions={[25, 50, 100, 200]}
                itemLabel="findings"
              />
            </div>
          )}
        </div>
        <p className="text-2xs text-fg-faint">
          A finding is linked to a task by the task’s related finding or a finding reference on the task. “Done, unverified” means the task reached a done
          column without a passed verification run; a fix attempt marked complete is a claim, not proof. Resolved and false-positive findings leave this list.
        </p>
      </div>
    </>
  );
}
