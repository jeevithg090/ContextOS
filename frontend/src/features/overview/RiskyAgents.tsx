/** Agents ranked by their current risk score (the highest score among their open sessions), each with
 * the largest risk factor of that session as the reason. */
import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { EntityLink, RiskMeter, Section } from "@/components/data";
import { Badge, EmptyState, LoadingRows, SimulationBadge } from "@/components/ui";
import { humanize } from "@/lib/domain";
import { pluralize, timeAgo } from "@/lib/format";
import { withSim } from "./meta";
import type { Overview } from "./types";

export function RiskyAgents({ data, loading }: { data: Overview | undefined; loading: boolean }) {
  const sim = data?.include_simulated ?? false;
  return (
    <Section
      title="Riskiest agents"
      description="Current score of each agent's riskiest open session, and why."
      flush
      actions={
        <Link to={withSim("/agents?sort=risk", sim)} className="text-xs text-accent hover:underline">
          All agents
        </Link>
      }
    >
      {!data ? (
        loading ? <LoadingRows rows={4} /> : null
      ) : data.top_risky_agents.length === 0 ? (
        <EmptyState
          icon={<ShieldCheck className="h-4 w-4" />}
          title="No agent carries risk right now"
          description={data.posture.agents_total ? "None of your agents has an open session with risk factors." : "Agents appear here once an integration reports their sessions."}
        />
      ) : (
        <ul className="divide-y divide-border/70">
          {data.top_risky_agents.map((a) => (
            <li key={a.id} className="space-y-1.5 px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                <EntityLink type="agent" id={a.id} label={a.name} className="min-w-0 text-[13px] font-medium" />
                <span className="shrink-0 text-2xs text-fg-faint">{humanize(a.environment)}</span>
                {a.is_simulation && <SimulationBadge />}
                <RiskMeter score={a.risk_score} level={a.risk_level} size="sm" className="ml-auto shrink-0" label={`Risk score of ${a.name}`} />
              </div>
              {a.reason ? (
                <p className="text-xs text-fg" title={a.reason_detail ?? undefined}>
                  {a.reason}
                  {a.reason_detail && <span className="mt-0.5 line-clamp-2 block text-fg-muted">{a.reason_detail}</span>}
                </p>
              ) : (
                <p className="text-xs text-fg-muted">No single factor recorded for this score.</p>
              )}
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-2xs text-fg-muted">
                {a.trifecta && (
                  <Badge tone="critical" title="Sensitive data access, untrusted content and an outbound channel in one session. A risk condition, not proof of an attack.">
                    Lethal trifecta
                  </Badge>
                )}
                {a.open_findings > 0 && (
                  <Link to={withSim(`/intelligence?agent=${encodeURIComponent(a.id)}`, sim)} className="hover:text-accent">
                    {pluralize(a.open_findings, "open finding")}
                  </Link>
                )}
                {a.session_id && <EntityLink type="session" id={a.session_id} label="Riskiest session" showIcon={false} className="text-2xs" />}
                <span className="ml-auto text-fg-faint">Seen {timeAgo(a.last_seen_at)}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
