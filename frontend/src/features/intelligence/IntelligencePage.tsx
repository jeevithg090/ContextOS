/**
 * Security Intelligence — answers "what suspicious behaviour has been detected?".
 *
 * Severity summary (current open backlog + the selected window), the trend of new detections, the
 * category / source breakdowns (click to filter) and the findings list with quick triage. Every
 * filter lives in the URL so views are linkable (see ./filters.ts); live `finding.*` events refresh
 * the queries (hooks/useLiveEvents).
 */
import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { SegmentedControl } from "@/components/data";
import { Button, PageHeader } from "@/components/ui";
import { useFindingStats } from "./api";
import { includeSimulated, selectedStatuses, setParam, windowFrom, withStatuses } from "./filters";
import { FindingsList } from "./FindingsList";
import { BreakdownPanel, TrendPanel } from "./InsightPanels";
import { WINDOWS } from "./meta";
import { SummaryStrip } from "./SummaryStrip";
import type { StatsWindow } from "./types";

export function IntelligencePage() {
  const [params, setParams] = useSearchParams();
  const window = windowFrom(params);
  const stats = useFindingStats(window, includeSimulated(params));

  const update = useCallback(
    (fn: (p: URLSearchParams) => URLSearchParams) => setParams((current) => fn(current), { replace: true }),
    [setParams],
  );

  const severities = params.getAll("severity");
  const statuses = selectedStatuses(params);
  const activeSeverity = severities.length === 1 ? severities[0] : null;
  const needsTriageActive = statuses.length === 1 && statuses[0] === "open";

  /** Backlog tiles count open + acknowledged findings, so the list shows exactly those. */
  const focusSeverity = (severity: "critical" | "high") =>
    update((p) => {
      const next = withStatuses(p, ["open", "acknowledged"]);
      next.delete("severity");
      if (activeSeverity !== severity) next.append("severity", severity);
      return next;
    });

  const focusNeedsTriage = () => update((p) => withStatuses(p, needsTriageActive ? ["open", "acknowledged"] : ["open"]));

  const toggleParam = (key: string, value: string) => update((p) => setParam(p, key, p.get(key) === value ? null : value));

  return (
    <>
      <PageHeader
        title="Security Intelligence"
        description="Suspicious behaviour ContextOS detected in what your agents read and did: manipulative content, credential access and risky outbound calls. Repeats of the same problem are merged into one finding."
        actions={
          <SegmentedControl<StatsWindow>
            aria-label="Time window"
            value={window}
            onChange={(value) => update((p) => setParam(p, "window", value === "7d" ? null : value))}
            options={WINDOWS.map((w) => ({ value: w.value, label: w.label }))}
          />
        }
      />

      <div className="space-y-4">
        {stats.error && stats.data && (
          <div role="status" className="flex items-center gap-2 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-fg">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-warn" aria-hidden />
            The summary could not be refreshed; the figures below may be out of date.
            <Button size="xs" variant="ghost" className="ml-auto" onClick={() => void stats.refetch()}>
              Retry
            </Button>
          </div>
        )}

        {stats.error && !stats.data ? (
          <TrendPanel stats={undefined} loading={false} error={stats.error} onRetry={() => void stats.refetch()} />
        ) : (
          <>
            <SummaryStrip
              stats={stats.data}
              loading={stats.isLoading}
              activeSeverity={activeSeverity}
              needsTriageActive={needsTriageActive}
              onSeverity={focusSeverity}
              onNeedsTriage={focusNeedsTriage}
            />
            <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
              <TrendPanel stats={stats.data} loading={stats.isLoading} error={stats.error} onRetry={() => void stats.refetch()} />
              <BreakdownPanel
                stats={stats.data}
                loading={stats.isLoading}
                selectedCategory={params.get("category")}
                selectedSource={params.get("source")}
                onCategory={(category) => toggleParam("category", category)}
                onSource={(sourceId) => toggleParam("source", sourceId)}
              />
            </div>
          </>
        )}

        <FindingsList params={params} update={update} stats={stats.data} />
      </div>
    </>
  );
}
