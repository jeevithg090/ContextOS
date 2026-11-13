import { Info } from "lucide-react";
import { FilterSelect, SegmentedControl } from "@/components/data";
import { Checkbox, ErrorState, PageHeader } from "@/components/ui";
import { buildQuery } from "@/lib/api";
import { formatDateTime, formatNumber, pluralize } from "@/lib/format";
import { useBoards } from "./api";
import { useEngineeringAnalytics } from "./analytics/api";
import { Breakdowns, CycleTimeChart, FlowCharts } from "./analytics/AnalyticsCharts";
import { KpiTile, formatHours, percent } from "./analytics/KpiTile";
import { OutstandingCriticalList } from "./analytics/OutstandingCriticalList";
import { ANALYTICS_WINDOWS, type AnalyticsWindow, type EngineeringAnalytics } from "./analytics/types";
import { oneOf, useUrlState } from "./analytics/useUrlState";

const WINDOW_LABELS: Record<AnalyticsWindow, string> = { "7d": "7d", "30d": "30d", "90d": "90d", "180d": "180d", "365d": "1y" };

/** "Are we fixing things fast enough?" — flow, resolution time and remediation coverage from task records. */
export function EngineeringAnalyticsPage() {
  const { get, set } = useUrlState();
  const range = oneOf(get("window"), ANALYTICS_WINDOWS, "30d");
  const boardId = get("board_id") || undefined;
  const includeSimulated = get("sim") === "1";
  const boards = useBoards();
  const query = useEngineeringAnalytics({ window: range, board_id: boardId, include_simulated: includeSimulated });
  const data = query.data;
  const loading = query.isLoading;

  return (
    <>
      <PageHeader
        eyebrow="Engineering Workspace"
        title="Engineering Analytics"
        description="Are we fixing things fast enough? Every number is counted from task, verification and finding records, with what was counted beside it."
        actions={
          <SegmentedControl
            aria-label="Time window"
            value={range}
            onChange={(w) => set({ window: w === "30d" ? null : w })}
            options={ANALYTICS_WINDOWS.map((w) => ({ value: w, label: WINDOW_LABELS[w] }))}
          />
        }
      />
      <div className="flex flex-wrap items-center gap-4 pb-4">
        <FilterSelect
          label="Board"
          value={boardId ?? ""}
          onChange={(v) => set({ board_id: v })}
          allLabel="All boards"
          disabled={boards.isLoading}
          options={(boards.data?.items ?? []).map((b) => ({ value: b.id, label: b.name }))}
        />
        <Checkbox
          label="Include Simulation Lab findings"
          checked={includeSimulated}
          onChange={(v) => set({ sim: v ? "1" : null })}
        />
        {boardId && (
          <span className="inline-flex items-center gap-1.5 text-xs text-fg-muted">
            <Info className="h-3.5 w-3.5" aria-hidden />
            Task metrics are limited to this board; finding metrics always cover every board.
          </span>
        )}
      </div>

      {query.error && !data ? (
        <div className="panel">
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        </div>
      ) : (
        <div className="space-y-4" aria-busy={query.isFetching || undefined}>
          <KpiGrid data={data} loading={loading} />
          <FlowCharts data={data} loading={loading} />
          <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
            <CycleTimeChart data={data} loading={loading} />
            {data ? <OutstandingCriticalList data={data.outstanding_critical} /> : <div className="panel h-[260px] animate-pulse" aria-hidden />}
          </div>
          {data && <Breakdowns data={data} />}
          {data && (
            <p className="text-2xs text-fg-faint">
              Computed {formatDateTime(data.generated_at)} over the {pluralize(data.window_days, "day")} since {formatDateTime(data.window_start)}.
              Archived tasks are excluded. A reopened task leaves the completed counts until it is completed again.
            </p>
          )}
        </div>
      )}
    </>
  );
}

function KpiGrid({ data, loading }: { data: EngineeringAnalytics | undefined; loading: boolean }) {
  const days = data?.window_days ?? 0;
  const board = data?.board_id ?? undefined;
  const backlog = data?.findings_awaiting_remediation;
  const completion = data?.remediation_completion_rate;
  const failed = data?.failed_verification_runs;
  const critical = data?.outstanding_critical;
  const n = (v: number | undefined) => formatNumber(v ?? 0);
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <KpiTile
        label="Open tasks"
        loading={loading}
        value={n(data?.open_tasks)}
        detail={data ? <span className={data.overdue ? "text-danger" : undefined}>{pluralize(data.overdue, "overdue task")}</span> : null}
        definition="Tasks that are not archived and not in a done column. Overdue: the due date has passed."
        href={`/work/tasks${buildQuery({ board_id: board })}`}
        hrefLabel="All tasks"
      />
      <KpiTile
        label="Median time to complete"
        loading={loading}
        value={formatHours(data?.median_resolution_hours)}
        detail={data ? `mean ${formatHours(data.avg_resolution_hours)} · p90 ${formatHours(data.p90_resolution_hours)} · ${pluralize(data.completed_in_window, "task")}` : null}
        definition={`completed_at − created_at for tasks completed in the last ${days} days that are still done.`}
      />
      <KpiTile
        label="Remediation completion"
        loading={loading}
        value={completion ? percent(completion) : "—"}
        detail={completion ? `${n(completion.numerator)} of ${pluralize(completion.denominator, "finding")} with a linked task` : null}
        definition="Findings with at least one linked task in a done column ÷ findings with at least one linked task (any finding status, all time)."
        href="/work/remediation"
        hrefLabel="Pipeline"
      />
      <KpiTile
        label="Awaiting remediation"
        loading={loading}
        value={n(backlog?.total)}
        tone={backlog?.no_task ? "danger" : undefined}
        detail={backlog ? `${n(backlog.no_task)} without a task · ${n(backlog.task_open)} in progress · ${n(backlog.open_findings)} open` : null}
        definition="Open or acknowledged findings that no task tracks, plus those whose linked task is not in a done column yet."
        href="/work/remediation?state=no_task"
        hrefLabel="Untracked"
      />
      <KpiTile
        label="Failed verification runs"
        loading={loading}
        value={n(failed?.numerator)}
        tone={failed?.numerator ? "danger" : undefined}
        detail={failed ? `of ${pluralize(failed.denominator, "run")} recorded in ${days} days` : null}
        definition="Verification runs (tests, reviews, simulations, replays, deployments, manual checks) with status failed, out of all runs recorded in the window."
      />
      <KpiTile
        label="Reopened"
        loading={loading}
        value={n(data?.reopened_issues.reopen_events)}
        tone={data?.reopened_issues.reopen_events ? "warn" : undefined}
        detail={data ? `${pluralize(data.reopened_issues.tasks_reopened, "task")} reopened at least once` : null}
        definition="Times a task was moved out of a done column, summed over current tasks (all time)."
      />
      <KpiTile
        label="Outstanding critical"
        loading={loading}
        value={n(critical?.total)}
        tone={critical?.total ? "critical" : undefined}
        detail={critical ? `${pluralize(critical.findings, "finding")} · ${pluralize(critical.tasks, "open task")}` : null}
        definition="Critical open findings without a done task, plus open tasks with severity critical; a task tracking a listed finding is counted once."
      />
      <KpiTile
        label="Completed"
        loading={loading}
        value={n(data?.completed_in_window)}
        detail={data ? `tasks done in the last ${pluralize(days, "day")}` : null}
        definition="Tasks whose completed_at falls in the window and that are still in a done column."
        href={`/work/tasks${buildQuery({ board_id: board, status: "done", done: "1", sort: "updated" })}`}
        hrefLabel="Done tasks"
      />
    </div>
  );
}
