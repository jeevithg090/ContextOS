/** "Why ContextOS paused it": the deciding policy and matched conditions, other matches, and the
 * session's trifecta evidence as the policy engine saw it. */
import { Link } from "react-router-dom";
import { EntityLink, Section } from "@/components/data";
import { Badge, DecisionBadge, EnforcementBadge, SeverityBadge, StatusDot, TrustBadge } from "@/components/ui";
import { humanize } from "@/lib/domain";
import { cn, formatDateTime, timeAgo } from "@/lib/format";
import type { ApprovalDetail, MatchedPolicy, TrifectaLeg } from "../types";

export function WhySection({ approval }: { approval: ApprovalDetail }) {
  const decision = approval.policy_decision;
  if (!decision) {
    return (
      <Section title="Why ContextOS paused it">
        <p className="text-xs text-fg-muted">The policy decision behind this request is no longer available, so the reason cannot be shown.</p>
      </Section>
    );
  }
  const deciding = decision.deciding_policy;
  const others = decision.matched_policies.filter((m) => m.policy_id !== deciding?.policy_id);
  return (
    <Section
      title="Why ContextOS paused it"
      description={decision.evaluated_at ? `Evaluated ${formatDateTime(decision.evaluated_at)}` : undefined}
      actions={
        <div className="flex items-center gap-1.5">
          <DecisionBadge decision={decision.decision} />
          <EnforcementBadge mode={decision.enforcement} />
        </div>
      }
    >
      <div className="space-y-5">
        {deciding ? (
          <PolicyCard match={deciding} primary />
        ) : (
          <p className="text-xs text-fg-muted">No policy matched; the organisation's default decision paused this call.</p>
        )}

        {others.length > 0 && (
          <div>
            <div className="label-caps mb-2">Also matched ({others.length})</div>
            <div className="space-y-2">
              {others.map((m) => (
                <PolicyCard key={m.policy_id} match={m} />
              ))}
            </div>
          </div>
        )}

        {approval.monitor_matches.length > 0 && (
          <div>
            <div className="label-caps mb-1">Dry-run policies that also matched</div>
            <p className="mb-2 text-2xs text-fg-faint">Monitor mode: recorded only, they did not affect this decision.</p>
            <div className="space-y-2">
              {approval.monitor_matches.map((m) => (
                <PolicyCard key={m.policy_id} match={m} />
              ))}
            </div>
          </div>
        )}

        {approval.detection.rule_ids.length > 0 && (
          <div>
            <div className="label-caps mb-2">Detections on the request</div>
            <div className="flex flex-wrap items-center gap-1.5">
              {approval.detection.max_severity && <SeverityBadge severity={approval.detection.max_severity} />}
              {approval.detection.rule_ids.map((id) => (
                <Badge key={id} tone="neutral">
                  <span className="font-mono">{id}</span>
                </Badge>
              ))}
            </div>
          </div>
        )}

        <TrifectaBlock approval={approval} />
      </div>
    </Section>
  );
}

function PolicyCard({ match, primary = false }: { match: MatchedPolicy; primary?: boolean }) {
  return (
    <div className={cn("rounded-md border p-3", primary ? "border-dec-approval/30 bg-dec-approval/[0.05]" : "border-border")}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        {primary && <span className="label-caps">Deciding policy</span>}
        {match.exists ? (
          <EntityLink type="policy" id={match.policy_id} label={match.name} showIcon={false} className="text-[13px] font-medium" />
        ) : (
          <span className="text-[13px] font-medium text-fg">{match.name}</span>
        )}
        {match.version !== null && <span className="text-2xs text-fg-faint">v{match.version}</span>}
        {match.severity && <SeverityBadge severity={match.severity} />}
        {match.outcome && !primary && <DecisionBadge decision={match.outcome} />}
        {!match.exists && <Badge tone="neutral">Deleted since</Badge>}
      </div>
      {match.explanation && <p className="mt-1.5 text-xs leading-relaxed text-fg">{match.explanation}</p>}
      {primary && match.description && <p className="mt-1.5 text-xs leading-relaxed text-fg-muted">{match.description}</p>}
    </div>
  );
}

function TrifectaBlock({ approval }: { approval: ApprovalDetail }) {
  const risk = approval.session_risk;
  const ctx = risk.context_at_decision;
  const lowest = typeof ctx.lowest_trust === "string" ? ctx.lowest_trust : null;
  const untrusted = typeof ctx.untrusted_item_count === "number" ? ctx.untrusted_item_count : null;
  const injection = ctx.injection_detected === true;
  return (
    <div className="rounded-md border border-border">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <span className="label-caps">Session risk when paused</span>
          {risk.trifecta_at_decision && <Badge tone="critical">Lethal trifecta</Badge>}
        </div>
        <span className="num text-xs text-fg-muted">
          {risk.score_at_decision}/100{risk.level_at_decision ? ` (${risk.level_at_decision})` : ""}
          {risk.current_score !== risk.score_at_decision && (
            <span className="text-fg-faint">
              {" "}
              · now {risk.current_score}
              {risk.current_level ? ` (${risk.current_level})` : ""}
            </span>
          )}
        </span>
      </div>
      <ul className="divide-y divide-border/60">
        {risk.legs.map((leg) => (
          <LegRow key={leg.key} leg={leg} sessionId={approval.session.id} />
        ))}
      </ul>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border px-3 py-2 text-2xs text-fg-faint">
        {lowest && (
          <span className="inline-flex items-center gap-1">
            lowest context trust <TrustBadge level={lowest} />
          </span>
        )}
        {untrusted !== null && <span>{untrusted} untrusted context items</span>}
        {injection && <span className="text-sev-high">prompt injection detected in context</span>}
        <span>
          Evidence as recorded on the session{risk.evidence_computed_at ? ` (updated ${timeAgo(risk.evidence_computed_at)})` : ""}. The
          trifecta is a risk condition, not proof of an attack.
        </span>
        <Link to={`/sessions/${encodeURIComponent(approval.session.id)}`} className="text-accent hover:underline">
          Open session
        </Link>
      </div>
    </div>
  );
}

function LegRow({ leg, sessionId }: { leg: TrifectaLeg; sessionId: string }) {
  return (
    <li className="px-3 py-2">
      <div className="flex items-center gap-2 text-xs">
        <StatusDot tone={leg.active_at_decision ? "danger" : "ok"} />
        <span className="text-fg">{leg.label}</span>
        <span className="text-fg-faint">{leg.active_at_decision ? "yes, when paused" : "no, when paused"}</span>
      </div>
      {leg.evidence.length > 0 && (
        <ul className="mt-1 space-y-0.5 pl-4 text-2xs text-fg-muted">
          {leg.evidence.slice(0, 4).map((e, i) => (
            <li key={`${e.type}-${e.id ?? i}`} className="flex min-w-0 items-center gap-1.5">
              {e.id ? <EntityLink type={e.type} id={e.id} sessionId={sessionId} /> : <span>{humanize(e.type)}</span>}
              <span className="truncate" title={e.detail ?? undefined}>
                {e.detail}
              </span>
            </li>
          ))}
          {leg.evidence.length > 4 && <li className="text-fg-faint">and {leg.evidence.length - 4} more on the session page</li>}
        </ul>
      )}
    </li>
  );
}
