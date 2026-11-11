/**
 * One recorded step: what happened (redacted), what ContextOS decided and how it was enforced,
 * the findings it raised, and session risk recomputed after it — with links to the receipt,
 * provenance and related records.
 */
import { Link } from "react-router-dom";
import { FileText, Network } from "lucide-react";
import { Badge, DecisionBadge, EnforcementBadge, KeyValue, Mono, SeverityBadge, StatusBadge, TrustBadge } from "@/components/ui";
import { EntityLink, RiskMeter } from "@/components/data";
import { FINDING_CATEGORY_LABELS } from "@/lib/domain";
import { cn, formatDateTime, formatTime } from "@/lib/format";
import { CONDITION_LABELS, eventLabel, signed } from "../meta";
import type { ReplayStep } from "../types";

const linkClass =
  "inline-flex h-7 items-center gap-1.5 whitespace-nowrap rounded border border-border-strong px-2.5 text-xs text-fg transition-colors hover:bg-surface-2";

export function StepDetail({ step, sessionId, total }: { step: ReplayStep; sessionId: string; total: number }) {
  const refs = step.refs;
  const provenance = refs.context_item_id
    ? `/provenance?item=${encodeURIComponent(refs.context_item_id)}`
    : `/provenance?session=${encodeURIComponent(sessionId)}`;
  return (
    <article className="space-y-5 p-4" aria-label={`Step ${step.index + 1} detail`}>
      <header className="space-y-1.5">
        <div className="flex flex-wrap items-center gap-2 text-2xs text-fg-faint">
          <span className="label-caps">
            Step {step.index + 1} of {total}
          </span>
          <Badge>{eventLabel(step.event_type)}</Badge>
          <Mono className="text-2xs" title="Server-assigned sequence (authoritative order)">
            seq {step.sequence}
          </Mono>
          {step.from_other_session && <Badge tone="accent">Recorded in another session</Badge>}
          {step.processing_status === "error" && <Badge tone="danger">Processing error</Badge>}
        </div>
        <h3 className="text-[15px] font-semibold text-fg">{step.title}</h3>
        {/* For decision steps the summary is the decision's explanation, shown in full below. */}
        {step.summary && !step.outcome && <p className="break-words text-[13px] text-fg-muted">{step.summary}</p>}
        <p className="text-2xs text-fg-faint">
          Received <time dateTime={step.received_at}>{formatDateTime(step.received_at)}</time> (server time) · client reported{" "}
          <time dateTime={step.occurred_at}>{formatTime(step.occurred_at)}</time>
        </p>
      </header>

      {step.outcome && <Outcome step={step} sessionId={sessionId} />}

      <section aria-label="Records" className="space-y-2">
        <h4 className="label-caps">Records</h4>
        <KeyValue
          items={[
            ...(step.tool ? [{ label: "Tool", value: <span className="inline-flex items-center gap-2"><Mono className="text-fg">{step.tool.name}</Mono><span className="text-xs text-fg-faint">{step.tool.category}</span>{step.tool.status && <StatusBadge status={step.tool.status} />}</span> }] : []),
            ...(refs.tool_invocation_id ? [{ label: "Tool call", value: <EntityLink type="tool_invocation" id={refs.tool_invocation_id} sessionId={sessionId} /> }] : []),
            ...(refs.context_item_id
              ? [{ label: "Context item", value: <span className="inline-flex items-center gap-2"><EntityLink type="context_item" id={refs.context_item_id} />{step.trust_level && <TrustBadge level={step.trust_level} />}</span> }]
              : []),
            ...(refs.source_id ? [{ label: "Source", value: <EntityLink type="source" id={refs.source_id} /> }] : []),
            ...(refs.destination_id ? [{ label: "Destination", value: <EntityLink type="destination" id={refs.destination_id} /> }] : []),
            ...(refs.child_session_id ? [{ label: "Delegated session", value: <EntityLink type="session" id={refs.child_session_id} /> }] : []),
            { label: "Event", value: <Mono>{step.event_id}</Mono> },
          ]}
        />
        <div className="flex flex-wrap gap-2 pt-1">
          {refs.context_item_id && (
            <Link to={`/context/${encodeURIComponent(refs.context_item_id)}`} className={linkClass}>
              <FileText className="h-3.5 w-3.5" aria-hidden /> Context receipt
            </Link>
          )}
          <Link to={provenance} className={linkClass}>
            <Network className="h-3.5 w-3.5" aria-hidden /> Provenance
          </Link>
        </div>
      </section>

      <section aria-label="Findings" className="space-y-2">
        <h4 className="label-caps">Findings raised at this step</h4>
        {step.findings.length === 0 ? (
          <p className="text-xs text-fg-faint">None.</p>
        ) : (
          <ul className="space-y-1.5">
            {step.findings.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-2 text-[13px]">
                <SeverityBadge severity={f.severity} />
                <EntityLink type="finding" id={f.id} label={f.title} showIcon={false} className="min-w-0" />
                <span className="text-2xs text-fg-faint">{FINDING_CATEGORY_LABELS[f.category] ?? f.category}</span>
                <span title="Current triage status">
                  <StatusBadge status={f.status} />
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <RiskAfter step={step} />
    </article>
  );
}

function Outcome({ step, sessionId }: { step: ReplayStep; sessionId: string }) {
  const o = step.outcome!;
  return (
    <section aria-label="Recorded outcome" className="space-y-2 rounded-md border border-border bg-surface-2/50 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h4 className="label-caps mr-1">Recorded decision</h4>
        <DecisionBadge decision={o.decision} />
        <EnforcementBadge mode={o.enforcement} />
        {o.approval_status && (
          <span className="inline-flex items-center gap-1.5 text-xs text-fg-muted">
            approval <StatusBadge status={o.approval_status} />
          </span>
        )}
      </div>
      {o.enforcement !== "enforced" && (
        <p className="text-xs text-fg-muted">
          {o.enforcement === "observed"
            ? "Observed only: the call was reported after the fact, so this outcome was recorded but could not prevent anything."
            : "Advisory: the decision was returned, but the integration may not have honoured it."}
        </p>
      )}
      <p className="break-words text-[13px] text-fg">{o.explanation}</p>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg-muted">
        {o.matched_policies.length > 0 && <span>Matched: {o.matched_policies.join(", ")}</span>}
        {o.approval_id && <EntityLink type="approval" id={o.approval_id} label="Approval request" />}
        <EntityLink type="policy_decision" id={o.policy_decision_id} sessionId={sessionId} />
      </div>
      {step.recorded_risk && (
        <p className="text-2xs text-fg-faint">
          Session risk recorded when this was decided: <span className="num text-fg-muted">{step.recorded_risk.score}</span> ({step.recorded_risk.level}
          {step.recorded_risk.trifecta ? ", trifecta" : ""}).
        </p>
      )}
    </section>
  );
}

function RiskAfter({ step }: { step: ReplayStep }) {
  const r = step.risk_after;
  return (
    <section aria-label="Session risk after this step" className="space-y-2.5">
      <div className="flex flex-wrap items-center gap-3">
        <h4 className="label-caps">Risk after this step</h4>
        <RiskMeter score={r.score} level={r.level} showLevel size="sm" label="Recomputed session risk" />
        {r.delta !== 0 && <span className={cn("num text-xs", r.delta > 0 ? "text-sev-high" : "text-ok")}>{signed(r.delta)}</span>}
        <Badge title="Recomputed with the current risk engine from what was recorded up to this step">{r.basis}</Badge>
      </div>
      <div className="flex flex-wrap gap-1.5" aria-label="Lethal trifecta conditions">
        {CONDITION_LABELS.map((c) => {
          const on = r[c.key];
          return (
            <Badge key={c.key} tone={on ? "high" : "neutral"} dot>
              {c.label}: {on ? "observed" : "not observed"}
            </Badge>
          );
        })}
        {r.trifecta && <Badge tone="critical">Trifecta conditions</Badge>}
      </div>
      <p className="text-xs text-fg-muted">{r.summary}</p>
      {r.factors.length > 0 && (
        <ul className="grid gap-1 sm:grid-cols-2">
          {r.factors.map((f) => (
            <li key={f.key} className="flex items-center justify-between gap-2 rounded border border-border/70 px-2 py-1 text-xs">
              <span className="truncate text-fg">{f.label}</span>
              <span className="num text-fg-muted">+{f.weight}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
