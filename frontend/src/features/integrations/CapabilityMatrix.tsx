import { ArrowRight } from "lucide-react";
import { Section } from "@/components/data";
import { Badge, Button, EnforcementBadge, Mono, StatusBadge } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { InlineCode } from "./InlineCode";
import type { Capability, CatalogEntry } from "./types";

function CapabilityList({ items, empty }: { items: Capability[]; empty: string }) {
  if (!items.length) return <span className="text-xs text-fg-faint">{empty}</span>;
  return (
    <ul className="space-y-2.5">
      {items.map((cap) => (
        <li key={cap.name} className="space-y-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-xs text-fg">{cap.name}</span>
            <EnforcementBadge mode={cap.mode} />
          </div>
          <p className="text-xs leading-5 text-fg-muted">{cap.description}</p>
        </li>
      ))}
    </ul>
  );
}

function ColumnLabel({ children }: { children: string }) {
  return <div className="label-caps mb-2">{children}</div>;
}

/** "What can each integration see, and what can it actually stop?" — supported integrations only. */
export function CapabilityMatrix({ entries, onSetup }: { entries: CatalogEntry[]; onSetup: (kind: string) => void }) {
  const supported = entries.filter((e) => e.status === "supported");
  return (
    <Section
      title="Capability matrix"
      description="Monitoring is always observed: it records what happened and cannot prevent it. Enforced means ContextOS decides at a boundary the integration honours before the tool runs; advisory means the decision is returned but may not be applied."
      flush
    >
      <div>
        {supported.map((entry) => (
          <article key={entry.kind} aria-labelledby={`cap-${entry.kind}`} className="border-b border-border/70 px-4 py-4 last:border-0">
            <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 max-w-3xl space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 id={`cap-${entry.kind}`} className="text-[13px] font-semibold text-fg">
                    {entry.name}
                  </h3>
                  <Mono className="text-2xs">{entry.kind}</Mono>
                  <StatusBadge status={entry.health} />
                  {entry.last_event_at && <span className="text-2xs text-fg-faint">last event {timeAgo(entry.last_event_at)}</span>}
                </div>
                <p className="text-xs leading-5 text-fg-muted">{entry.summary}</p>
              </div>
              <Button size="xs" variant="outline" icon={<ArrowRight className="h-3 w-3" aria-hidden />} onClick={() => onSetup(entry.kind)} aria-label={`Setup guide for ${entry.name}`}>
                Setup guide
              </Button>
            </header>
            <div className="grid gap-5 md:grid-cols-3 md:gap-6">
              <div className="min-w-0">
                <ColumnLabel>Monitoring · what it sees</ColumnLabel>
                <CapabilityList items={entry.monitoring} empty="Nothing is observed." />
              </div>
              <div className="min-w-0">
                <ColumnLabel>Enforcement · what it can stop</ColumnLabel>
                <CapabilityList items={entry.enforcement} empty="Nothing can be enforced." />
              </div>
              <div className="min-w-0">
                <ColumnLabel>Limitations</ColumnLabel>
                <ul className="list-disc space-y-1.5 pl-4 text-xs leading-5 text-fg-muted marker:text-fg-faint">
                  {entry.limitations.map((limit) => (
                    <li key={limit}>
                      <InlineCode text={limit} />
                    </li>
                  ))}
                </ul>
                {entry.docs_path && (
                  <p className="mt-2 text-2xs text-fg-faint">
                    Details: <span className="font-mono">{entry.docs_path}</span>
                  </p>
                )}
              </div>
            </div>
          </article>
        ))}
      </div>
    </Section>
  );
}

/** Planned integrations: nothing is claimed for them; the interim path (if any) is spelled out. */
export function PlannedIntegrations({ entries, onSetup }: { entries: CatalogEntry[]; onSetup: (kind: string) => void }) {
  const planned = entries.filter((e) => e.status === "planned");
  if (!planned.length) return null;
  return (
    <Section
      title="Planned — not supported yet"
      description="ContextOS has no native adapter for these frameworks, so it records and enforces nothing from them unless you use the interim path through an existing integration."
      flush
    >
      <div className="hidden grid-cols-[180px_minmax(0,1fr)_minmax(0,1fr)_112px] gap-4 border-b border-border px-4 py-2 text-2xs uppercase tracking-[0.06em] text-fg-faint lg:grid" aria-hidden>
        <div>Framework</div>
        <div>Likely integration surface</div>
        <div>What works today</div>
        <div />
      </div>
      <ul>
        {planned.map((entry) => (
          <li key={entry.kind} className="grid gap-x-4 gap-y-2 border-b border-border/70 px-4 py-3 last:border-0 lg:grid-cols-[180px_minmax(0,1fr)_minmax(0,1fr)_112px]">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-fg">{entry.name}</span>
                <Badge tone="neutral">Planned</Badge>
              </div>
              <Mono className="text-2xs">{entry.kind}</Mono>
            </div>
            <p className="text-xs leading-5 text-fg-muted">
              <span className="label-caps mr-1.5 lg:hidden">Surface</span>
              {entry.integration_surface ?? "—"}
            </p>
            <div className="text-xs leading-5 text-fg-muted">
              <span className="label-caps mr-1.5 lg:hidden">Today</span>
              {entry.available_today ?? "Nothing yet."}
              {entry.interim_kind && (
                <span className="mt-1 block text-2xs text-fg-faint">
                  Interim path: <span className="font-mono">{entry.interim_kind}</span>
                  {entry.health !== "never_seen" ? " · this framework name has sent events" : ""}
                </span>
              )}
            </div>
            <div className="lg:text-right">
              {entry.interim_kind && (
                <Button size="xs" variant="outline" onClick={() => onSetup(entry.kind)} aria-label={`Interim setup for ${entry.name}`}>
                  Interim setup
                </Button>
              )}
            </div>
          </li>
        ))}
      </ul>
    </Section>
  );
}
