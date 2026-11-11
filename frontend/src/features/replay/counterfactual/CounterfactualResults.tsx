/**
 * Original vs hypothetical outcome for every recorded decision of the session. Changed steps are
 * highlighted; each row expands to the explanation, which policies changed, and the recorded
 * (redacted) input fields the matching conditions used.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, ChevronDown, ChevronRight, History, TriangleAlert } from "lucide-react";
import { Badge, Checkbox, DecisionBadge, EmptyState, EnforcementBadge, Mono, SimulationBadge, Stat } from "@/components/ui";
import { JsonView } from "@/components/data";
import { cn, formatDateTime, pluralize } from "@/lib/format";
import { CHANGE_LABELS } from "../meta";
import type { CounterfactualResult, CounterfactualStep } from "../types";

export function CounterfactualResults({ result, sessionId }: { result: CounterfactualResult; sessionId: string }) {
  const [onlyChanged, setOnlyChanged] = useState(false);
  const s = result.summary;
  const steps = onlyChanged ? result.steps.filter((x) => x.changed) : result.steps;
  const transitions = Object.entries(s.transitions);

  return (
    <div className="space-y-4">
      <section aria-label="Summary" className="panel p-4">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 xl:grid-cols-7">
          <Stat label="Evaluated" value={s.evaluated} hint="Recorded decisions" />
          <Stat label="Changed" value={s.changed} tone={s.changed ? "accent" : undefined} hint="Different from recorded" />
          <Stat label="Would deny" value={s.would_deny} tone={s.would_deny ? "deny" : undefined} />
          <Stat label="Would pause" value={s.would_pause} tone={s.would_pause ? "approval" : undefined} hint="Require approval" />
          <Stat label="Would allow" value={s.would_allow} tone={s.would_allow ? "allow" : undefined} hint="Allow or audit" />
          <Stat label="Would restrict" value={s.would_restrict} tone={s.would_restrict ? "restrict" : undefined} />
          <Stat label="Drifted" value={s.drifted} tone={s.drifted ? "warn" : undefined} hint="Today's saved policies already differ" />
        </div>
        {(transitions.length > 0 || result.policy_set.warnings.length > 0 || s.drifted > 0) && (
          <div className="mt-4 space-y-2 border-t border-border pt-3 text-xs">
            {transitions.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-fg-faint">Changes:</span>
                {transitions.map(([key, n]) => {
                  const [from, to] = key.split("→");
                  return (
                    <span key={key} className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5">
                      <DecisionBadge decision={from} />
                      <ArrowRight className="h-3 w-3 text-fg-faint" aria-label="to" />
                      <DecisionBadge decision={to} />
                      <span className="num text-fg">×{n}</span>
                    </span>
                  );
                })}
              </div>
            )}
            {s.drifted > 0 && (
              <p className="text-warn">
                {pluralize(s.drifted, "decision")} would already come out differently under today's saved policies, independent of the changes simulated here.
                Compare "Today" with "Recorded" below to separate drift from your changes.
              </p>
            )}
            {result.policy_set.warnings.map((w) => (
              <p key={w} className="text-warn">
                {w}
              </p>
            ))}
          </div>
        )}
      </section>

      {result.not_evaluable_count > 0 && (
        <section aria-label="Not evaluable" className="panel p-4">
          <h3 className="flex items-center gap-1.5 text-[13px] font-semibold text-fg">
            <TriangleAlert className="h-4 w-4 text-warn" aria-hidden />
            {pluralize(result.not_evaluable_count, "event")} could not be evaluated
          </h3>
          <p className="mt-0.5 text-xs text-fg-muted">No recorded decision input exists for these, and ContextOS does not reconstruct missing history.</p>
          <ul className="mt-2 space-y-1 text-xs">
            {result.not_evaluable.map((n) => (
              <li key={`${n.event_id}-${n.policy_decision_id}`} className="flex flex-wrap gap-2 text-fg-muted">
                <Mono>seq {n.sequence ?? "?"}</Mono>
                <span>{n.event_type}</span>
                <span className="text-fg">{n.reason}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-label="Per-decision comparison" className="panel">
        <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
          <h3 className="mr-auto text-[13px] font-semibold text-fg">Recorded vs hypothetical, per decision</h3>
          <Checkbox label="Changed only" checked={onlyChanged} onChange={setOnlyChanged} />
        </div>
        {result.steps.length === 0 ? (
          <EmptyState icon={<History className="h-5 w-5" />} title="This session has no recorded policy decisions" description="Only tool requests that ContextOS evaluated can be replayed against other policies." />
        ) : steps.length === 0 ? (
          <EmptyState title="No decision changes under this policy set" description="Every recorded decision comes out the same." className="py-8" />
        ) : (
          <>
            <div className="hidden grid-cols-[3rem_minmax(0,1.2fr)_minmax(0,1fr)_1.5rem_minmax(0,1fr)] gap-3 border-b border-border px-4 py-2 text-2xs uppercase tracking-[0.06em] text-fg-faint md:grid">
              <span>Step</span>
              <span>Tool call</span>
              <span>Recorded</span>
              <span aria-hidden />
              <span>Hypothetical</span>
            </div>
            <ol className="divide-y divide-border/60">
              {steps.map((step) => (
                <ComparisonRow key={step.decision_id} step={step} sessionId={sessionId} />
              ))}
            </ol>
          </>
        )}
        {result.truncated && <p className="border-t border-border px-4 py-2 text-2xs text-warn">Only the first 2,000 decisions of this session were evaluated.</p>}
      </section>
    </div>
  );
}

function ComparisonRow({ step, sessionId }: { step: CounterfactualStep; sessionId: string }) {
  const [open, setOpen] = useState(step.changed);
  const detailId = `cf-${step.decision_id}`;
  return (
    <li className={cn(step.changed && "border-l-2 border-l-accent bg-accent/[0.04]", step.after_hypothetical_block && "opacity-80")}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={detailId}
        className="grid w-full grid-cols-1 gap-2 px-4 py-2.5 text-left hover:bg-surface-2/60 focus-visible:bg-surface-2 focus-visible:outline-none md:grid-cols-[3rem_minmax(0,1.2fr)_minmax(0,1fr)_1.5rem_minmax(0,1fr)] md:items-center md:gap-3"
      >
        <span className="flex items-center gap-1 text-2xs text-fg-faint">
          {open ? <ChevronDown className="h-3.5 w-3.5" aria-hidden /> : <ChevronRight className="h-3.5 w-3.5" aria-hidden />}
          <span className="num">{step.step_index !== null ? step.step_index + 1 : "—"}</span>
        </span>
        <span className="min-w-0">
          <span className="flex flex-wrap items-center gap-1.5">
            <Mono className="text-fg">{step.tool.name ?? "tool"}</Mono>
            {step.tool.category && <span className="text-2xs text-fg-faint">{step.tool.category}</span>}
            {step.is_simulation && <SimulationBadge />}
          </span>
          {step.after_hypothetical_block && (
            <span className="mt-0.5 flex items-center gap-1 text-2xs text-warn">
              <TriangleAlert className="h-3 w-3" aria-hidden /> Might not have occurred: an earlier step was hypothetically blocked
            </span>
          )}
        </span>
        <span className="flex flex-wrap items-center gap-1.5">
          <DecisionBadge decision={step.original_decision} />
          <EnforcementBadge mode={step.original_enforcement} />
        </span>
        <ArrowRight className={cn("hidden h-3.5 w-3.5 md:block", step.changed ? "text-accent" : "text-fg-faint")} aria-hidden />
        <span className="flex flex-wrap items-center gap-1.5">
          <DecisionBadge decision={step.hypothetical_decision} />
          {step.changed ? <Badge tone="accent">Changed</Badge> : <span className="text-2xs text-fg-faint">unchanged</span>}
          {step.drifted && <Badge tone="warn" title={`Today's saved policies return ${step.current_decision}`}>Drifted</Badge>}
        </span>
      </button>
      {open && <ComparisonDetail id={detailId} step={step} sessionId={sessionId} />}
    </li>
  );
}

function ComparisonDetail({ id, step, sessionId }: { id: string; step: CounterfactualStep; sessionId: string }) {
  return (
    <div id={id} className="space-y-3 px-4 pb-4 md:pl-[4.75rem]">
      <p className="text-[13px] text-fg">{step.explanation}</p>
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="rounded border border-border p-3">
          <div className="label-caps mb-1.5">Recorded · {formatDateTime(step.evaluated_at)}</div>
          <p className="text-xs text-fg-muted">{step.original_explanation || "No explanation recorded."}</p>
          {step.original_matches.length > 0 && <p className="mt-1.5 text-2xs text-fg-faint">Matched: {step.original_matches.join(", ")}</p>}
          <p className="mt-1.5 text-2xs text-fg-faint">
            Today's saved policies: <DecisionBadge decision={step.current_decision} className="align-middle" />
          </p>
        </div>
        <div className="rounded border border-accent/30 p-3">
          <div className="label-caps mb-1.5 text-accent">Hypothetical (simulation)</div>
          {step.hypothetical_matches.length === 0 ? (
            <p className="text-xs text-fg-muted">No enforce-mode policy matched; the default applied.</p>
          ) : (
            <ul className="space-y-1">
              {step.hypothetical_matches.map((m) => (
                <li key={m.policy_id} className="flex flex-wrap items-center gap-1.5 text-xs">
                  <DecisionBadge decision={m.outcome} />
                  <span className="text-fg">{m.name}</span>
                  {m.draft && <Badge tone="accent">Draft</Badge>}
                </li>
              ))}
            </ul>
          )}
          {step.hypothetical_monitor_matches.length > 0 && (
            <p className="mt-1.5 text-2xs text-fg-faint">Monitor mode (recorded only): {step.hypothetical_monitor_matches.map((m) => m.name).join(", ")}</p>
          )}
          {Object.keys(step.hypothetical_restrictions).length > 0 && (
            <p className="mt-1.5 text-2xs text-fg-faint">Restrictions: {JSON.stringify(step.hypothetical_restrictions)}</p>
          )}
          {step.evaluation_errors.map((e) => (
            <p key={`${e.policy_id}-${e.error}`} className="mt-1.5 text-2xs text-danger">
              {e.name}: {e.error}
            </p>
          ))}
        </div>
      </div>
      {step.policy_changes.length > 0 && (
        <div>
          <div className="label-caps mb-1.5">Why the policies differ</div>
          <ul className="space-y-1">
            {step.policy_changes.map((c) => (
              <li key={`${c.policy_id}-${c.change}`} className="flex flex-wrap items-center gap-2 text-xs">
                <Badge tone={c.change === "newly_matches" ? "accent" : "neutral"}>{CHANGE_LABELS[c.change] ?? c.change}</Badge>
                <span className="text-fg">{c.name}</span>
                <span className="text-fg-muted">{c.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {step.evidence.length > 0 && (
        <div>
          <div className="label-caps mb-1.5">Recorded input used by the matching conditions</div>
          <ul className="space-y-1.5">
            {step.evidence.map((e) => (
              <li key={e.field} className="grid gap-1 text-xs sm:grid-cols-[minmax(10rem,max-content)_1fr] sm:gap-3">
                <span>
                  <Mono className="text-fg">{e.field}</Mono>
                  <span className="block text-2xs text-fg-faint">{e.policies.join(", ")}</span>
                </span>
                {!e.present ? (
                  <span className="text-fg-faint">not present in the recorded input</span>
                ) : typeof e.value === "object" && e.value !== null ? (
                  <JsonView value={e.value} defaultExpandDepth={1} toolbar={false} maxHeightClassName="max-h-40" />
                ) : (
                  <Mono className="break-all text-fg">{JSON.stringify(e.value)}</Mono>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      <Link
        to={`/replay/${encodeURIComponent(sessionId)}?decision=${encodeURIComponent(step.decision_id)}`}
        className="inline-flex items-center gap-1 text-xs text-accent hover:underline"
      >
        Open this step in the player <ArrowRight className="h-3 w-3" aria-hidden />
      </Link>
    </div>
  );
}
