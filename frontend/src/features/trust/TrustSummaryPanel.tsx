/** Header summary: how sources and destinations are classified, which sources carry findings and
 * what was downgraded recently (read from the audit trail). */
import { ArrowRight, Database, Globe } from "lucide-react";
import { ErrorState, Skeleton, SeverityBadge, SimulationBadge, TrustBadge } from "@/components/ui";
import { InlineStat } from "@/components/data";
import type { TrustLevel } from "@/lib/domain";
import { cn, pluralize, timeAgo, truncate } from "@/lib/format";
import { useTrustSummary } from "./api";
import { LevelDistribution } from "./components";
import { displayIdentifier, sourceTypeLabel } from "./meta";

export function TrustSummaryPanel({
  includeSimulated = false,
  onSourceLevel,
  onDestinationLevel,
  onOpenSource,
  onOpenDestination,
}: {
  /** Count sources and destinations only Simulation Lab traffic observed (the page's "Include simulated"). */
  includeSimulated?: boolean;
  onSourceLevel: (level: TrustLevel) => void;
  onDestinationLevel: (level: TrustLevel) => void;
  onOpenSource: (id: string) => void;
  onOpenDestination: (id: string) => void;
}) {
  const summary = useTrustSummary(includeSimulated);
  if (summary.isLoading)
    return (
      <div className="grid gap-3 lg:grid-cols-2" aria-busy="true" aria-label="Loading summary">
        <Skeleton className="h-[116px]" />
        <Skeleton className="h-[116px]" />
      </div>
    );
  if (summary.error) return <ErrorState error={summary.error} onRetry={() => void summary.refetch()} className="panel" />;
  const s = summary.data!;

  return (
    <div className="space-y-3">
      <div className="grid gap-3 lg:grid-cols-2">
        <section className="panel p-4" aria-labelledby="trust-sources-dist">
          <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
            <h2 id="trust-sources-dist" className="text-[13px] font-semibold text-fg">
              Sources <span className="num ml-1 font-normal text-fg-muted">{s.sources.total}</span>
            </h2>
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              <InlineStat label="Can instruct" value={s.sources.can_instruct} tone={s.sources.can_instruct ? "accent" : undefined} hint="Sources whose content may currently direct the agent" />
              <InlineStat label="Manual" value={s.sources.manual} hint="Classified by an administrator" />
              <InlineStat label="With findings" value={s.sources.with_findings} tone={s.sources.with_findings ? "high" : undefined} hint="Findings not marked false positive" />
            </div>
          </div>
          <LevelDistribution byLevel={s.sources.by_level} total={s.sources.total} label="Sources" onSelect={onSourceLevel} />
        </section>
        <section className="panel p-4" aria-labelledby="trust-dest-dist">
          <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
            <h2 id="trust-dest-dist" className="text-[13px] font-semibold text-fg">
              Destinations <span className="num ml-1 font-normal text-fg-muted">{s.destinations.total}</span>
            </h2>
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              <InlineStat label="Blocked calls" value={s.destinations.with_blocked_calls} tone={s.destinations.with_blocked_calls ? "deny" : undefined} hint="Destinations with at least one call denied at an enforcing integration" />
              <InlineStat label="Sensitive transfers" value={s.destinations.with_sensitive_transfers} tone={s.destinations.with_sensitive_transfers ? "high" : undefined} hint="Destinations with at least one call carrying secrets or sensitive resources that ContextOS did not stop" />
              <InlineStat label="Rules" value={`${s.rules.enabled}/${s.rules.total}`} hint="Enabled trust rules / all trust rules" />
            </div>
          </div>
          <LevelDistribution byLevel={s.destinations.by_level} total={s.destinations.total} label="Destinations" onSelect={onDestinationLevel} />
        </section>
      </div>

      {(s.sources_with_findings.length > 0 || s.recently_downgraded.length > 0) && (
        <div className="grid gap-3 lg:grid-cols-2">
          <section className="panel" aria-labelledby="trust-attention">
            <h2 id="trust-attention" className="border-b border-border px-4 py-2.5 text-[13px] font-semibold text-fg">
              Sources with findings
            </h2>
            {s.sources_with_findings.length === 0 ? (
              <p className="px-4 py-4 text-xs text-fg-muted">No source has findings that are not marked false positive.</p>
            ) : (
              <ul className="divide-y divide-border/70">
                {s.sources_with_findings.map((src) => (
                  <li key={src.id}>
                    <button type="button" onClick={() => onOpenSource(src.id)} className="flex w-full items-center gap-2 px-4 py-2 text-left hover:bg-surface-2/70">
                      <TrustBadge level={src.trust_level} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[13px] text-fg" title={src.identifier}>
                          {src.display_name || displayIdentifier(src.identifier)}
                        </span>
                        <span className="block text-2xs text-fg-faint">{sourceTypeLabel(src.source_type)}</span>
                      </span>
                      {src.is_simulation && <SimulationBadge />}
                      {src.max_finding_severity && <SeverityBadge severity={src.max_finding_severity} />}
                      <span className="num w-20 shrink-0 text-right text-xs text-fg-muted">{pluralize(src.finding_count, "finding")}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section className="panel" aria-labelledby="trust-downgrades">
            <h2 id="trust-downgrades" className="border-b border-border px-4 py-2.5 text-[13px] font-semibold text-fg">
              Recently downgraded <span className="font-normal text-fg-faint">· last {s.downgrade_window_days} days</span>
            </h2>
            {s.recently_downgraded.length === 0 ? (
              <p className="px-4 py-4 text-xs text-fg-muted">Nothing lost trust in the last {s.downgrade_window_days} days.</p>
            ) : (
              <ul className="divide-y divide-border/70">
                {s.recently_downgraded.map((d) => (
                  <li key={`${d.target_type}:${d.target_id}`}>
                    <button
                      type="button"
                      onClick={() => (d.target_type === "source" ? onOpenSource(d.target_id) : onOpenDestination(d.target_id))}
                      className="flex w-full items-center gap-2 px-4 py-2 text-left hover:bg-surface-2/70"
                      title={d.summary}
                    >
                      {d.target_type === "source" ? (
                        <Database className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-label="Source" />
                      ) : (
                        <Globe className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-label="Destination" />
                      )}
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[13px] text-fg">{truncate(displayIdentifier(d.label), 90)}</span>
                        <span className="block truncate text-2xs text-fg-faint">
                          {d.actor_label} · {timeAgo(d.at)}
                        </span>
                      </span>
                      <span className={cn("flex shrink-0 items-center gap-1")}>
                        <TrustBadge level={d.from_level} />
                        <ArrowRight className="h-3 w-3 text-fg-faint" aria-label="to" />
                        <TrustBadge level={d.to_level} />
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
