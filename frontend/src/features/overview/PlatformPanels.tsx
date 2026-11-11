/** Where context comes from (trust distribution of sources) and whether integrations are reporting
 * and able to enforce decisions. */
import { Link, useNavigate } from "react-router-dom";
import { Database, Plug } from "lucide-react";
import { DonutChart, Section } from "@/components/data";
import { Badge, EmptyState, LoadingRows, StatusBadge } from "@/components/ui";
import { TRUST_LEVELS, TRUST_META } from "@/lib/domain";
import { formatNumber, pluralize, timeAgo } from "@/lib/format";
import { integrationLabel } from "./meta";
import type { Overview } from "./types";

export function TrustDistribution({ data, loading }: { data: Overview | undefined; loading: boolean }) {
  const navigate = useNavigate();
  const counts = data?.posture.sources_by_trust;
  const total = counts ? Object.values(counts).reduce((s, n) => s + n, 0) : 0;
  const untrusted = counts ? (counts.SUSPICIOUS ?? 0) + (counts.BLOCKED ?? 0) : 0;
  return (
    <Section
      title="Source trust"
      description="Current classification of every source your agents have read from."
      actions={
        <Link to="/trust" className="text-xs text-accent hover:underline">
          Trust Centre
        </Link>
      }
    >
      {!data || !counts ? (
        loading ? <LoadingRows rows={3} /> : null
      ) : total === 0 ? (
        <EmptyState className="py-8" icon={<Database className="h-4 w-4" />} title="No sources observed yet" description="Sources appear when agents read files, pages, tool output or messages." />
      ) : (
        <div className="space-y-3">
          <DonutChart
            data={TRUST_LEVELS.map((level) => ({ key: level, label: TRUST_META[level].label, value: counts[level] ?? 0, tone: TRUST_META[level].tone }))}
            centerValue={formatNumber(total)}
            centerLabel={total === 1 ? "source" : "sources"}
            size={132}
            onSelect={(level) => navigate(`/trust?slevel=${encodeURIComponent(level)}`)}
            aria-label="Context sources by trust level"
          />
          <p className="text-xs text-fg-muted">
            {untrusted
              ? `${pluralize(untrusted, "source")} classified suspicious or blocked. Select a level to review them.`
              : "No source is classified suspicious or blocked."}
          </p>
        </div>
      )}
    </Section>
  );
}

export function IntegrationHealth({ data, loading }: { data: Overview | undefined; loading: boolean }) {
  const rows = data?.integrations ?? [];
  return (
    <Section
      title="Integration health"
      description="Which integrations are reporting, and whether they can enforce decisions."
      flush
      actions={
        <Link to="/integrations" className="text-xs text-accent hover:underline">
          Integrations
        </Link>
      }
    >
      {!data ? (
        loading ? <LoadingRows rows={3} /> : null
      ) : rows.length === 0 ? (
        <EmptyState
          icon={<Plug className="h-4 w-4" />}
          title="No integration has reported yet"
          description="Integrations register themselves with their first event. Simulation Lab runs never mark an integration as connected."
          action={
            <Link to="/integrations" className="text-xs text-accent hover:underline">
              Set up an integration
            </Link>
          }
        />
      ) : (
        <ul className="divide-y divide-border/70">
          {rows.map((row) => (
            <li key={row.id} className="space-y-1 px-4 py-3">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <span className="text-[13px] font-medium text-fg">{integrationLabel(row.kind)}</span>
                {row.name !== row.kind && <span className="truncate font-mono text-2xs text-fg-faint">{row.name}</span>}
                <StatusBadge status={row.status} />
                {row.enforcement_capable ? (
                  <Badge tone="ok" title={row.enforcement_note}>
                    Can enforce
                  </Badge>
                ) : (
                  <Badge tone="neutral" title={row.enforcement_note}>
                    Reports only
                  </Badge>
                )}
                <span className="ml-auto shrink-0 text-xs text-fg-faint" title={row.last_event_at ?? undefined}>
                  {row.last_event_at ? `Last event ${timeAgo(row.last_event_at)}` : "No events yet"}
                </span>
              </div>
              <p className="text-xs text-fg-muted">
                {row.status_reason} {row.enforcement_note}
              </p>
              <p className="num font-mono text-2xs text-fg-faint">
                {pluralize(row.event_count, "event")} · {pluralize(row.decision_count, "decision")} requested
              </p>
              {row.last_error && <p className="text-xs text-danger">{row.last_error}</p>}
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
