/** Work waiting for a person: paused tool calls, open critical/high findings and open incidents. */
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Clock, Radar, Siren, UserCheck } from "lucide-react";
import { EntityLink, Section } from "@/components/data";
import { Badge, EmptyState, LoadingRows, SeverityBadge, SimulationBadge, StatusBadge } from "@/components/ui";
import { FINDING_CATEGORY_LABELS, humanize } from "@/lib/domain";
import { cn, formatNumber, timeAgo } from "@/lib/format";
import { formatRemaining, withSim } from "./meta";
import type { Overview } from "./types";

function Group({ icon, title, count, href, children }: { icon: ReactNode; title: string; count: number; href: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="flex items-center justify-between gap-2 px-4 pb-1.5 pt-3">
        <h3 className="flex items-center gap-1.5 text-xs font-medium text-fg-muted">
          <span className="text-fg-faint [&>svg]:h-3.5 [&>svg]:w-3.5" aria-hidden>
            {icon}
          </span>
          {title}
          <span className="num font-mono text-fg">{formatNumber(count)}</span>
        </h3>
        <Link to={href} className="text-xs text-accent hover:underline">
          View all
        </Link>
      </div>
      <ul className="divide-y divide-border/70">{children}</ul>
    </div>
  );
}

function Row({ children, className }: { children: ReactNode; className?: string }) {
  return <li className={cn("flex min-w-0 items-center gap-3 px-4 py-2", className)}>{children}</li>;
}

export function NeedsAttention({ data, loading }: { data: Overview | undefined; loading: boolean }) {
  if (!data) {
    return (
      <Section title="Needs attention" flush>
        {loading ? <LoadingRows rows={5} /> : null}
      </Section>
    );
  }
  const { attention, posture, include_simulated: sim } = data;
  const criticalHigh = (posture.open_findings_by_severity.critical ?? 0) + (posture.open_findings_by_severity.high ?? 0);
  const empty = !attention.pending_approvals.length && !attention.critical_findings.length && !attention.open_incidents.length;

  return (
    <Section title="Needs attention" description="Paused tool calls, serious open findings and open incidents, most urgent first." flush>
      {empty ? (
        <EmptyState icon={<CheckCircle2 className="h-4 w-4 text-ok" />} title="Nothing needs attention right now" description="No tool call is waiting for approval, no critical or high finding is open and no incident is open." />
      ) : (
        <div className="divide-y divide-border">
          {attention.pending_approvals.length > 0 && (
            <Group icon={<UserCheck />} title="Waiting for approval" count={posture.pending_approvals} href={withSim("/approvals", sim)}>
              {attention.pending_approvals.map((a) => (
                <Row key={a.id}>
                  <Badge tone="approval">Paused</Badge>
                  <Link to={`/approvals?approval=${encodeURIComponent(a.id)}`} className="min-w-0 flex-1 truncate text-[13px] text-fg hover:text-accent">
                    {a.summary}
                  </Link>
                  {a.is_simulation && <SimulationBadge />}
                  <span className={cn("inline-flex shrink-0 items-center gap-1 text-xs", a.seconds_remaining !== null && a.seconds_remaining < 120 ? "text-warn" : "text-fg-muted")} title={`Requested ${timeAgo(a.requested_at)}`}>
                    <Clock className="h-3 w-3" aria-hidden />
                    {formatRemaining(a.seconds_remaining)}
                  </span>
                </Row>
              ))}
            </Group>
          )}
          {attention.critical_findings.length > 0 && (
            <Group icon={<Radar />} title="Critical & high findings" count={criticalHigh} href={withSim("/intelligence?severity=critical&severity=high", sim)}>
              {attention.critical_findings.map((f) => (
                <Row key={f.id}>
                  <SeverityBadge severity={f.severity} className="w-[58px] justify-center" />
                  <div className="min-w-0 flex-1">
                    <Link to={`/intelligence/${encodeURIComponent(f.id)}`} className="block truncate text-[13px] text-fg hover:text-accent">
                      {f.title}
                    </Link>
                    <div className="flex min-w-0 items-center gap-1.5 text-2xs text-fg-muted">
                      <span className="truncate">{FINDING_CATEGORY_LABELS[f.category] ?? humanize(f.category)}</span>
                      {f.agent && (
                        <>
                          <span aria-hidden>·</span>
                          <EntityLink type="agent" id={f.agent.id} label={f.agent.name} showIcon={false} className="text-2xs" />
                        </>
                      )}
                      {f.occurrence_count > 1 && <span>· seen {formatNumber(f.occurrence_count)}×</span>}
                    </div>
                  </div>
                  {f.is_simulation && <SimulationBadge />}
                  <span className="shrink-0 text-xs text-fg-faint">{timeAgo(f.last_seen_at)}</span>
                </Row>
              ))}
            </Group>
          )}
          {attention.open_incidents.length > 0 && (
            <Group icon={<Siren />} title="Open incidents" count={posture.open_incidents} href={withSim("/incidents", sim)}>
              {attention.open_incidents.map((i) => (
                <Row key={i.id}>
                  <SeverityBadge severity={i.severity} className="w-[58px] justify-center" />
                  <Link to={`/incidents/${encodeURIComponent(i.id)}`} className="min-w-0 flex-1 truncate text-[13px] text-fg hover:text-accent">
                    <span className="mr-1.5 font-mono text-xs text-fg-muted">#{i.number}</span>
                    {i.title}
                  </Link>
                  {i.is_simulation && <SimulationBadge />}
                  <StatusBadge status={i.status} />
                  <span className="hidden shrink-0 text-xs text-fg-faint sm:inline">{timeAgo(i.opened_at)}</span>
                </Row>
              ))}
            </Group>
          )}
        </div>
      )}
    </Section>
  );
}
