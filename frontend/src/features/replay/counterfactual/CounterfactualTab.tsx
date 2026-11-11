/**
 * Counterfactual tab — answers "what would ContextOS have decided if policy had been different?".
 * Every recorded decision of the session is re-evaluated against its recorded input snapshot under
 * the hypothetical policy set. Always labelled as a simulation; nothing is saved.
 */
import type { UseMutationResult } from "@tanstack/react-query";
import { Play, RotateCcw } from "lucide-react";
import { Button, ErrorState } from "@/components/ui";
import { Section } from "@/components/data";
import { pluralize } from "@/lib/format";
import { validationErrors } from "../api";
import { changeCount, EMPTY_POLICY_SET, toRequest, type PolicySetState } from "../policySet";
import type { CounterfactualRequest, CounterfactualResult } from "../types";
import { CounterfactualResults } from "./CounterfactualResults";
import { PolicySetEditor } from "./PolicySetEditor";
import { DEFAULT_CAVEATS, SimulationBanner } from "./SimulationBanner";

export interface CounterfactualTabProps {
  sessionId: string;
  decisionSteps: number;
  state: PolicySetState;
  onStateChange: (next: PolicySetState) => void;
  run: UseMutationResult<CounterfactualResult, Error, CounterfactualRequest>;
}

export function CounterfactualTab({ sessionId, decisionSteps, state, onStateChange, run }: CounterfactualTabProps) {
  const changes = changeCount(state);
  const result = run.data && run.data.session_id === sessionId ? run.data : null;
  const serverErrors = validationErrors(run.error);
  const stale = Boolean(result && run.variables && JSON.stringify(run.variables) !== JSON.stringify(toRequest(sessionId, state)));

  return (
    <div className="space-y-4">
      <SimulationBanner caveats={result?.caveats ?? DEFAULT_CAVEATS} />
      <Section
        title="Hypothetical policy set"
        description={`Each of this session's ${pluralize(decisionSteps, "recorded decision")} is re-evaluated against its recorded, redacted input. Saved policies are not changed.`}
        actions={
          <>
            <span className="text-xs text-fg-muted">{changes === 0 ? "No changes yet" : pluralize(changes, "change")}</span>
            <Button size="sm" variant="ghost" icon={<RotateCcw className="h-3.5 w-3.5" aria-hidden />} disabled={changes === 0} onClick={() => onStateChange(EMPTY_POLICY_SET)}>
              Reset
            </Button>
            <Button size="sm" variant="primary" icon={<Play className="h-3.5 w-3.5" aria-hidden />} loading={run.isPending} onClick={() => run.mutate(toRequest(sessionId, state))}>
              Run simulation
            </Button>
          </>
        }
      >
        <PolicySetEditor state={state} onChange={onStateChange} />
      </Section>

      {run.error && (
        <div role="alert" className="panel p-4">
          {serverErrors.length > 0 ? (
            <>
              <p className="text-[13px] font-medium text-danger">The hypothetical policy set is invalid</p>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs text-fg-muted">
                {serverErrors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </>
          ) : (
            <ErrorState error={run.error} onRetry={() => run.mutate(toRequest(sessionId, state))} className="py-4" />
          )}
        </div>
      )}
      {result && stale && (
        <p role="status" className="rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn">
          The policy set changed since this run. The results below are for the previous set; run the simulation again to update them.
        </p>
      )}
      {result ? (
        <CounterfactualResults result={result} sessionId={sessionId} />
      ) : (
        !run.isPending &&
        !run.error && (
          <p className="text-xs text-fg-muted">
            Run the simulation to compare. With no changes it shows how today's saved policies treat the recorded inputs, which reveals drift since the session ran.
          </p>
        )
      )}
    </div>
  );
}
