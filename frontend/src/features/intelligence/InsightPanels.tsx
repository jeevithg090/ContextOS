/** Trend of new findings by severity, and the two breakdowns that filter the list: open findings by
 * category (current backlog) and the sources that produced most findings in the window. */
import { useState } from "react";
import { BarList, SegmentedControl, TimeSeriesChart, type TimeSeries } from "@/components/data";
import { ErrorState, TrustBadge } from "@/components/ui";
import { SEVERITIES, SEVERITY_META, severityTone } from "@/lib/domain";
import { formatNumber, truncate } from "@/lib/format";
import { CATEGORY_DESCRIPTIONS, categoryLabel, windowMeta } from "./meta";
import type { FindingStats } from "./types";
import { format } from "date-fns";

const SERIES: TimeSeries[] = [...SEVERITIES].reverse().map((s) => ({ key: s, label: SEVERITY_META[s].label, tone: SEVERITY_META[s].tone }));

export function TrendPanel({ stats, loading, error, onRetry }: { stats: FindingStats | undefined; loading: boolean; error: unknown; onRetry: () => void }) {
  const window = windowMeta(stats?.window);
  const hourly = stats?.bucket === "hour";
  const resolved = stats?.period.by_status.resolved ?? 0;
  return (
    <section className="panel min-w-0" aria-labelledby="intel-trend-title">
      <div className="flex flex-wrap items-start justify-between gap-2 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <h2 id="intel-trend-title" className="text-[13px] font-semibold text-fg">
            New findings per {hourly ? "hour" : "day"}
          </h2>
          <p className="mt-0.5 text-xs text-fg-muted">
            First detections in {window.long}, by severity. False positives are left out.
          </p>
        </div>
        {stats && (
          <div className="flex items-center gap-3 text-2xs text-fg-muted">
            <span>
              <span className="num font-mono text-fg">{formatNumber(stats.period.total)}</span> new
            </span>
            <span>
              <span className="num font-mono text-fg">{formatNumber(resolved)}</span> since resolved
            </span>
          </div>
        )}
      </div>
      <div className="p-4">
        {error && !stats ? (
          <ErrorState error={error} onRetry={onRetry} className="py-8" />
        ) : (
          <TimeSeriesChart
            aria-label={`New findings per ${hourly ? "hour" : "day"} by severity`}
            data={(stats?.period.trend ?? []).map((p) => ({ ...p }))}
            series={SERIES}
            variant="bar"
            height={196}
            loading={loading}
            xFormat={(v) => format(new Date(v), hourly ? "HH:mm" : "d MMM")}
            emptyLabel={`Nothing suspicious was detected in ${window.long}.`}
          />
        )}
      </div>
    </section>
  );
}

type Breakdown = "categories" | "sources";

export function BreakdownPanel({
  stats,
  loading,
  selectedCategory,
  selectedSource,
  onCategory,
  onSource,
}: {
  stats: FindingStats | undefined;
  loading: boolean;
  selectedCategory: string | null;
  selectedSource: string | null;
  onCategory: (category: string) => void;
  onSource: (sourceId: string) => void;
}) {
  const [view, setView] = useState<Breakdown>("categories");
  const window = windowMeta(stats?.window);
  return (
    <section className="panel min-w-0" aria-labelledby="intel-breakdown-title">
      <div className="flex flex-wrap items-start justify-between gap-2 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <h2 id="intel-breakdown-title" className="text-[13px] font-semibold text-fg">
            {view === "categories" ? "Open findings by category" : "Sources with most findings"}
          </h2>
          <p className="mt-0.5 text-xs text-fg-muted">
            {view === "categories" ? "Current backlog. Click a category to filter the list." : `New in ${window.long}, false positives excluded.`}
          </p>
        </div>
        <SegmentedControl
          aria-label="Breakdown"
          value={view}
          onChange={setView}
          options={[
            { value: "categories", label: "Categories" },
            { value: "sources", label: "Sources" },
          ]}
        />
      </div>
      <div className="p-3">
        {loading && !stats ? (
          <div className="space-y-2 p-1" aria-busy="true" aria-label="Loading breakdown">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="h-7 animate-pulse rounded bg-surface-3/60" />
            ))}
          </div>
        ) : view === "categories" ? (
          <BarList
            aria-label="Open findings by category"
            items={(stats?.open.by_category ?? []).map((c) => ({
              key: c.category,
              label: categoryLabel(c.category),
              hint: CATEGORY_DESCRIPTIONS[c.category],
              value: c.count,
              tone: "accent",
            }))}
            onSelect={onCategory}
            selectedKey={selectedCategory}
            limit={7}
            emptyLabel="Nothing is open. New detections appear here as soon as they are raised."
          />
        ) : (
          <BarList
            aria-label="Sources with most findings"
            items={(stats?.period.top_sources ?? []).map((s) => ({
              key: s.id,
              label: (
                <span className="inline-flex min-w-0 max-w-full items-center gap-2">
                  <span className="truncate" title={s.identifier}>
                    {truncate(s.display_name || s.identifier, 60)}
                  </span>
                  <TrustBadge level={s.trust_level} />
                </span>
              ),
              hint: `${s.source_type.replace(/_/g, " ")} · worst ${s.max_severity ?? "—"}`,
              value: s.count,
              tone: severityTone(s.max_severity),
            }))}
            onSelect={onSource}
            selectedKey={selectedSource}
            limit={7}
            emptyLabel={`No source produced findings in ${window.long}.`}
          />
        )}
      </div>
    </section>
  );
}
