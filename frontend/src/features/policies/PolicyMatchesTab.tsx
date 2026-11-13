/** Recorded decisions in which this policy matched: evidence of what it actually did. */
import { useState } from "react";
import { FlaskConical } from "lucide-react";
import { Badge, Button, Checkbox, DecisionBadge, EmptyState, EnforcementBadge, ErrorState, LoadingRows, SimulationBadge } from "@/components/ui";
import { EntityLink } from "@/components/data";
import { formatDateTime, pluralize, timeAgo } from "@/lib/format";
import { usePolicyDecisions } from "./api";

export function PolicyMatchesTab({ policyId, onTest }: { policyId: string; onTest: (decisionId: string) => void }) {
  const [includeSimulation, setIncludeSimulation] = useState(false);
  const q = usePolicyDecisions(policyId, includeSimulation);

  return (
    <div className="space-y-3 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-fg-muted">
          Decisions from the last 30 days where this policy matched. An <span className="text-fg">enforce</span> match took part in the decision; a{" "}
          <span className="text-fg">monitor</span> match was recorded only.
        </p>
        <Checkbox label="Include simulated" checked={includeSimulation} onChange={setIncludeSimulation} />
      </div>
      {q.isLoading ? (
        <LoadingRows rows={4} />
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : !q.data?.items.length ? (
        <EmptyState
          title="No matches in the last 30 days"
          description="When an integration reports a tool call that satisfies these conditions, the decision appears here with a link to its session."
        />
      ) : (
        <>
          <ul className="divide-y divide-border rounded-md border border-border">
            {q.data.items.map((d) => (
              <li key={d.id} className="space-y-1.5 px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-xs text-fg">{d.tool_name ?? "unknown tool"}</span>
                  {d.tool_category && <span className="text-2xs text-fg-faint">{d.tool_category}</span>}
                  <Badge tone={d.match_mode === "monitor" ? "neutral" : "accent"} title={d.match_mode === "monitor" ? "Recorded only; did not change the decision" : "Took part in the decision"}>
                    {d.match_mode} match{d.matched_version !== null ? ` · v${d.matched_version}` : ""}
                  </Badge>
                  <span className="text-2xs text-fg-faint">recorded</span>
                  <DecisionBadge decision={d.decision} />
                  <EnforcementBadge mode={d.enforcement} />
                  {d.is_simulation && <SimulationBadge />}
                  <span className="ml-auto text-2xs text-fg-faint" title={formatDateTime(d.evaluated_at)}>
                    {timeAgo(d.evaluated_at)}
                  </span>
                </div>
                <p className="text-xs leading-relaxed text-fg-muted">{d.match_explanation}</p>
                <div className="flex flex-wrap items-center gap-3 text-2xs">
                  <EntityLink type="agent" id={d.agent_id} label={d.agent_name} className="text-2xs" />
                  <EntityLink type="session" id={d.session_id} className="text-2xs" />
                  <EntityLink type="policy_decision" id={d.id} sessionId={d.session_id} label="Replay" className="text-2xs" />
                  <Button size="xs" variant="ghost" className="ml-auto" icon={<FlaskConical className="h-3 w-3" aria-hidden />} onClick={() => onTest(d.id)}>
                    Test draft against this
                  </Button>
                </div>
              </li>
            ))}
          </ul>
          {q.data.total > q.data.items.length && (
            <p className="text-2xs text-fg-faint">
              Showing the {q.data.items.length} most recent of {pluralize(q.data.total, "match", "matches")}.
            </p>
          )}
        </>
      )}
    </div>
  );
}
