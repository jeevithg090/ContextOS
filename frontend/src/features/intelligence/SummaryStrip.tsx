/** Severity summary: the open backlog (current state) plus what changed in the selected window.
 * Backlog tiles are buttons that filter the list below. */
import type { ReactNode } from "react";
import { Skeleton, Stat } from "@/components/ui";
import type { Tone } from "@/lib/domain";
import { cn, formatNumber, pluralize, timeAgo } from "@/lib/format";
import { formatDuration, windowMeta } from "./meta";
import type { FindingStats } from "./types";

function Tile({ label, value, hint, tone, onClick, active, title }: { label: string; value: ReactNode; hint: ReactNode; tone?: Tone; onClick?: () => void; active?: boolean; title: string }) {
  const body = <Stat label={label} value={value} hint={hint} tone={tone} />;
  const base = "min-w-0 px-4 py-3.5 text-left";
  if (!onClick) {
    return (
      <div className={base} title={title}>
        {body}
      </div>
    );
  }
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      title={title}
      className={cn(base, "transition-colors hover:bg-surface-2/70 focus-visible:bg-surface-2/70 focus-visible:outline-none", active && "bg-accent/[0.06] shadow-[inset_0_-2px_0_0_rgb(var(--accent))]")}
    >
      {body}
    </button>
  );
}

export function SummaryStrip({
  stats,
  loading,
  activeSeverity,
  needsTriageActive,
  onSeverity,
  onNeedsTriage,
}: {
  stats: FindingStats | undefined;
  loading: boolean;
  activeSeverity: string | null;
  needsTriageActive: boolean;
  onSeverity: (severity: "critical" | "high") => void;
  onNeedsTriage: () => void;
}) {
  if (loading || !stats) {
    return (
      <div className="panel grid grid-cols-2 divide-x divide-border md:grid-cols-5" aria-busy="true" aria-label="Loading summary">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="space-y-2 px-4 py-3.5">
            <Skeleton className="h-3 w-20" />
            <Skeleton className="h-6 w-12" />
            <Skeleton className="h-3 w-28" />
          </div>
        ))}
      </div>
    );
  }
  const { open, period } = stats;
  const window = windowMeta(stats.window);
  const fp = period.by_status.false_positive ?? 0;
  const mttr = period.mttr;

  return (
    <section aria-label="Detection summary" className="panel grid grid-cols-2 divide-border md:grid-cols-5 md:divide-x [&>*:nth-child(n+3)]:border-t [&>*:nth-child(n+3)]:border-border md:[&>*:nth-child(n+3)]:border-t-0">
      <Tile
        label="Open critical"
        value={formatNumber(open.by_severity.critical)}
        tone={open.by_severity.critical ? "critical" : undefined}
        hint={open.by_severity.critical ? "Each one opens or joins an incident" : "No critical findings open"}
        onClick={() => onSeverity("critical")}
        active={activeSeverity === "critical"}
        title="Open or acknowledged critical findings. Click to show only these."
      />
      <Tile
        label="Open high"
        value={formatNumber(open.by_severity.high)}
        tone={open.by_severity.high ? "high" : undefined}
        hint={`${formatNumber(open.total)} open in total`}
        onClick={() => onSeverity("high")}
        active={activeSeverity === "high"}
        title="Open or acknowledged high-severity findings. Click to show only these."
      />
      <Tile
        label="Needs triage"
        value={formatNumber(open.needs_triage)}
        tone={open.needs_triage ? "warn" : undefined}
        hint={open.needs_triage && open.oldest_first_seen_at ? `Oldest open since ${timeAgo(open.oldest_first_seen_at).replace(/ ago$/, "")}` : `${formatNumber(open.acknowledged)} acknowledged`}
        onClick={onNeedsTriage}
        active={needsTriageActive}
        title="Open findings nobody has acknowledged yet. Click to show only these."
      />
      <Tile
        label={`New · ${window.label}`}
        value={formatNumber(period.total)}
        hint={fp ? `${formatNumber(fp)} since marked false positive` : `First detected in ${window.long}`}
        title={`Findings first detected in ${window.long}, in any status.`}
      />
      <Tile
        label="Mean time to resolve"
        value={mttr.resolved_count ? formatDuration(mttr.mean_seconds) : "—"}
        hint={mttr.resolved_count ? `Median ${formatDuration(mttr.median_seconds)} · ${pluralize(mttr.resolved_count, "finding")}` : `Nothing resolved in ${window.long}`}
        title="From first detection to resolution, for findings resolved in the window (false positives excluded)."
      />
    </section>
  );
}
