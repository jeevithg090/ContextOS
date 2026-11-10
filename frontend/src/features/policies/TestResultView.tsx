/** Result of a policy dry run. Always labelled as a simulation so it is never read as history. */
import { FlaskConical, TriangleAlert } from "lucide-react";
import { Badge, DecisionBadge, EnforcementBadge, SeverityBadge, SimulationBadge } from "@/components/ui";
import { EntityLink, JsonView } from "@/components/data";
import { formatDateTime } from "@/lib/format";
import { DRAFT_POLICY_ID, type PolicyMatch, type PolicyTestResult } from "./types";

function MatchList({ title, matches, draftId, draftLabel, monitor }: { title: string; matches: PolicyMatch[]; draftId: string; draftLabel: string; monitor?: boolean }) {
  if (!matches.length) return null;
  return (
    <div className="space-y-1.5">
      <div className="label-caps">{title}</div>
      <ul className="space-y-1.5">
        {matches.map((m) => (
          <li key={m.policy_id} className="rounded-md border border-border bg-surface-2/50 px-3 py-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[13px] font-medium text-fg">{m.name}</span>
              {m.policy_id === draftId && <Badge tone="accent">{draftLabel}</Badge>}
              <DecisionBadge decision={m.outcome} />
              <SeverityBadge severity={m.severity} />
              {monitor && <Badge tone="neutral">monitor — recorded only</Badge>}
              <span className="ml-auto font-mono text-2xs text-fg-faint">v{m.version}</span>
            </div>
            <p className="mt-1 text-xs leading-relaxed text-fg-muted">{m.explanation}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function TestResultView({ result, policyId }: { result: PolicyTestResult; policyId: string | null }) {
  const draftId = policyId ?? DRAFT_POLICY_ID;
  const draftLabel = policyId ? "this policy, as edited" : "this draft";
  const draftMatchedEnforce = result.matched.some((m) => m.policy_id === draftId);
  const draftMatchedMonitor = result.monitor_matches.some((m) => m.policy_id === draftId);
  const draftVerdict = draftMatchedEnforce
    ? result.deciding_policy_id === draftId
      ? "This policy matched and decided the outcome."
      : "This policy matched, but a policy with higher precedence decided the outcome."
    : draftMatchedMonitor
      ? "This policy matched in monitor mode: it would be recorded but would not change the decision."
      : "This policy did not match this input.";

  return (
    <section aria-label="Simulation result" className="space-y-4 rounded-lg border border-accent/30 bg-accent/[0.03] p-4">
      <div className="flex flex-wrap items-center gap-2">
        <FlaskConical className="h-4 w-4 text-accent" aria-hidden />
        <span className="text-[13px] font-semibold text-fg">{result.label}</span>
        <SimulationBadge />
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-fg-muted">Hypothetical decision</span>
        <DecisionBadge decision={result.decision} className="h-6 px-2 text-xs" />
        <span className="text-xs text-fg-muted">{draftVerdict}</span>
      </div>
      <p className="text-xs leading-relaxed text-fg-muted">{result.explanation}</p>

      {Object.keys(result.restrictions ?? {}).length > 0 && (
        <div className="space-y-1">
          <div className="label-caps">Restrictions that would apply</div>
          <JsonView value={result.restrictions} toolbar={false} defaultExpandDepth={2} />
        </div>
      )}

      <MatchList title="Matched (enforce)" matches={result.matched} draftId={draftId} draftLabel={draftLabel} />
      <MatchList title="Matched (monitor)" matches={result.monitor_matches} draftId={draftId} draftLabel={draftLabel} monitor />

      {result.evaluation_errors.length > 0 && (
        <div role="alert" className="space-y-1 rounded-md border border-danger/30 bg-danger/10 px-3 py-2">
          <div className="text-xs font-medium text-danger">Policies that could not be evaluated (they never match)</div>
          {result.evaluation_errors.map((e) => (
            <p key={`${e.policy_id}-${e.error}`} className="text-2xs text-fg-muted">
              <span className="text-fg">{e.name}</span>: {e.error}
            </p>
          ))}
        </div>
      )}

      {result.warnings.length > 0 && (
        <ul className="space-y-1">
          {result.warnings.map((w) => (
            <li key={w} className="flex items-start gap-1.5 text-2xs text-warn">
              <TriangleAlert className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
              {w}
            </li>
          ))}
        </ul>
      )}

      {result.recorded && (
        <div className="space-y-1.5 rounded-md border border-border bg-surface px-3 py-2.5">
          <div className="label-caps">Recorded outcome (historical, for comparison)</div>
          <div className="flex flex-wrap items-center gap-1.5 text-xs text-fg-muted">
            <DecisionBadge decision={result.recorded.decision} />
            <EnforcementBadge mode={result.recorded.enforcement} />
            {result.recorded.is_simulation && <SimulationBadge />}
            <span>{formatDateTime(result.recorded.evaluated_at)}</span>
            <EntityLink type="session" id={result.recorded.session_id} />
            <EntityLink type="policy_decision" id={result.recorded.id} sessionId={result.recorded.session_id} label="Open in Replay" />
          </div>
          <p className="text-2xs text-fg-faint">
            {result.recorded.matched_policy_names.length
              ? `Matched at the time: ${result.recorded.matched_policy_names.join(", ")}`
              : "No enforce-mode policy matched at the time."}
            {result.recorded.decision !== result.decision && " The simulated decision differs from what was recorded."}
          </p>
        </div>
      )}

      <div className="text-2xs text-fg-faint">
        Evaluated {result.evaluated_policies.length} {result.evaluated_policies.length === 1 ? "policy" : "policies"} · default when nothing matches:{" "}
        {result.default_decision} · input from {result.source === "policy_decision" ? "the recorded, redacted snapshot" : "the custom JSON"}
      </div>
      <JsonView value={result.evaluated_input} title="Input evaluated (redacted)" defaultExpandDepth={1} maxHeightClassName="max-h-64" />
    </section>
  );
}
