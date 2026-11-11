/**
 * Records attached to this incident's findings: agents, sessions, sources (with current trust) and
 * destinations. Observed together with the detections — not a claim that each one caused the incident.
 */
import type { ReactNode } from "react";
import { EntityLink, RiskMeter } from "@/components/data";
import { Badge, StatusBadge, TrustBadge } from "@/components/ui";
import { formatNumber, pluralize, timeAgo } from "@/lib/format";
import type { Involved } from "../types";

function Group({ title, count, children, empty }: { title: string; count: number; children: ReactNode; empty: string }) {
  return (
    <div>
      <div className="mb-1.5 flex items-center gap-2">
        <h3 className="label-caps">{title}</h3>
        <span className="num text-2xs text-fg-faint">{count}</span>
      </div>
      {count === 0 ? <p className="text-xs text-fg-faint">{empty}</p> : <ul className="space-y-2">{children}</ul>}
    </div>
  );
}

function FindingCount({ n }: { n: number }) {
  if (n === 0) return null;
  return (
    <span className="num shrink-0 text-2xs text-fg-faint" title="Linked findings that reference this record">
      {pluralize(n, "finding")}
    </span>
  );
}

function Primary() {
  return (
    <Badge tone="accent" title="The incident's primary record (from its most severe finding)">
      Primary
    </Badge>
  );
}

export function InvolvedPanel({ involved }: { involved: Involved }) {
  return (
    <div className="space-y-4">
      <Group title="Agents" count={involved.agents.length} empty="No agent recorded.">
        {involved.agents.map((a) => (
          <li key={a.id} className="flex items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <EntityLink type="agent" id={a.id} label={a.name} />
              {a.is_primary && <Primary />}
              {a.status !== "active" && <StatusBadge status={a.status} />}
            </div>
            <span className="flex shrink-0 items-center gap-2 text-2xs text-fg-faint">
              {a.framework} · {a.environment}
              <FindingCount n={a.finding_count} />
            </span>
          </li>
        ))}
      </Group>

      <Group title="Sessions" count={involved.sessions.length} empty="No session recorded.">
        {involved.sessions.map((s) => (
          <li key={s.id} className="space-y-1">
            <div className="flex items-center justify-between gap-2">
              <div className="flex min-w-0 items-center gap-2">
                <EntityLink type="session" id={s.id} label={s.external_session_id} className="font-mono text-xs" />
                {s.is_primary && <Primary />}
                {s.trifecta && (
                  <Badge tone="critical" title="Untrusted content, sensitive data access and an outbound channel were all observed in this session">
                    Trifecta
                  </Badge>
                )}
              </div>
              <FindingCount n={s.finding_count} />
            </div>
            <div className="flex items-center gap-3 text-2xs text-fg-faint">
              <span>{s.agent_name}</span>
              <span>started {timeAgo(s.started_at)}</span>
              <span className="num">{formatNumber(s.event_count)} events</span>
              <RiskMeter score={s.risk_score} level={s.risk_level} size="sm" label={`Risk of session ${s.external_session_id}`} className="ml-auto w-28" />
            </div>
          </li>
        ))}
      </Group>

      <Group title="Sources" count={involved.sources.length} empty="No context source is linked to these findings.">
        {involved.sources.map((s) => (
          <li key={s.id} className="space-y-0.5">
            <div className="flex items-center justify-between gap-2">
              <div className="flex min-w-0 items-center gap-2">
                <TrustBadge level={s.trust_level} />
                <EntityLink type="source" id={s.id} label={s.display_name || s.identifier} showIcon={false} className="text-[13px]" />
              </div>
              <FindingCount n={s.finding_count} />
            </div>
            <div className="truncate pl-0.5 font-mono text-2xs text-fg-faint" title={s.identifier}>
              {s.source_type} · {s.identifier}
            </div>
            {s.trust_reasons[0] && <div className="text-2xs text-fg-muted">{s.trust_reasons[0]}</div>}
          </li>
        ))}
      </Group>

      <Group title="Destinations" count={involved.destinations.length} empty="No outbound destination is linked to these findings.">
        {involved.destinations.map((d) => (
          <li key={d.id} className="space-y-0.5">
            <div className="flex items-center justify-between gap-2">
              <div className="flex min-w-0 items-center gap-2">
                <TrustBadge level={d.classification} />
                <EntityLink type="destination" id={d.id} label={d.display_name || d.identifier} showIcon={false} className="font-mono text-xs" />
              </div>
              <FindingCount n={d.finding_count} />
            </div>
            <div className="text-2xs text-fg-faint">
              {d.kind} · {pluralize(d.transfer_count, "transfer")}
              {d.blocked_count > 0 && <span className="text-dec-deny"> · {formatNumber(d.blocked_count)} blocked</span>}
            </div>
          </li>
        ))}
      </Group>

      <p className="border-t border-border pt-2 text-2xs text-fg-faint">{involved.note}</p>
    </div>
  );
}
