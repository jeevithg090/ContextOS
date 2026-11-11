/**
 * Detail of one simulation run: verdict, the scenario's checks (expected vs actual, with the
 * records they point at), what happened at each step, and the policy snapshot the run used.
 */
import { Link } from "react-router-dom";
import { GitBranch } from "lucide-react";
import { EntityLink, RedactedText, provenanceHref } from "@/components/data";
import { Button, DecisionBadge, EnforcementBadge, KeyValue, Mono, SimulationBadge, StatusBadge, TD, TH, THead, TR, Table } from "@/components/ui";
import { POLICY_MODE_META, TONE_CLASSES, labelFrom, type PolicyMode } from "@/lib/domain";
import { cn, formatDateTime, shortId } from "@/lib/format";
import { describeObservation, observationEnforcement, splitResults } from "../logic";
import type { ExpectationResult, ObservationResult, PolicySnapshotEntry, SimulationRun } from "../types";
import { EvidenceLinks } from "./EvidenceLinks";
import { VerdictBadge } from "./VerdictBadge";

const MODE_LABELS: Record<string, string> = Object.fromEntries(Object.entries(POLICY_MODE_META).map(([k, v]) => [k, v.label]));

export function RunDetail({ run, onShowSuite }: { run: SimulationRun; onShowSuite?: (suiteRunId: string) => void }) {
  const { checks, observations } = splitResults(run.results);
  return (
    <div className="space-y-6 p-5">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <VerdictBadge run={run} />
          <SimulationBadge />
          <span className="num text-xs text-fg-muted">
            {run.checks_passed} of {run.checks_total} checks passed
          </span>
        </div>
        {run.summary && (
          <p className="text-[13px] leading-5 text-fg">
            <RedactedText text={run.summary} />
          </p>
        )}
        {run.error && (
          <p role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            The run stopped early: <RedactedText text={run.error} />
          </p>
        )}
      </div>

      <KeyValue
        items={[
          { label: "Scenario", value: run.scenario_name },
          { label: "Target agent", value: run.agent_id ? <EntityLink type="agent" id={run.agent_id} /> : <span className="text-fg-muted">Dedicated simulated agent</span> },
          { label: "Agent version", value: run.agent_version ?? <span className="text-fg-faint">Not recorded</span> },
          {
            label: "Suite",
            value: run.suite_run_id ? (
              onShowSuite ? (
                <Button size="xs" variant="ghost" className="-ml-2 font-mono" onClick={() => onShowSuite(run.suite_run_id as string)}>
                  {shortId(run.suite_run_id)} · show all runs
                </Button>
              ) : (
                <Mono>{run.suite_run_id}</Mono>
              )
            ) : (
              <span className="text-fg-faint">Single run</span>
            ),
          },
          { label: "Started", value: formatDateTime(run.started_at) },
          { label: "Completed", value: formatDateTime(run.completed_at) },
          { label: "Run id", value: <Mono>{run.id}</Mono> },
        ]}
      />

      <SessionLinks sessionId={run.session_id} />

      <section aria-labelledby={`checks-${run.id}`} className="space-y-2">
        <h3 id={`checks-${run.id}`} className="text-[13px] font-semibold text-fg">
          Checks <span className="num font-normal text-fg-muted">({checks.length})</span>
        </h3>
        {checks.length === 0 ? (
          <p className="text-xs text-fg-muted">This run recorded no check results.</p>
        ) : (
          <ol className="space-y-2">
            {checks.map((c) => (
              <CheckRow key={c.step} check={c} sessionId={run.session_id} />
            ))}
          </ol>
        )}
      </section>

      <section aria-labelledby={`steps-${run.id}`} className="space-y-2">
        <h3 id={`steps-${run.id}`} className="text-[13px] font-semibold text-fg">
          Steps <span className="num font-normal text-fg-muted">({observations.length})</span>
        </h3>
        <p className="text-xs text-fg-muted">What the pipeline returned for each simulated step. Steps are observations, not pass/fail checks.</p>
        {observations.length === 0 ? (
          <p className="text-xs text-fg-muted">No steps were recorded for this run.</p>
        ) : (
          <ol className="space-y-2">
            {observations.map((o, i) => (
              <StepRow key={`${o.step}-${i}`} index={i + 1} step={o} sessionId={run.session_id} />
            ))}
          </ol>
        )}
      </section>

      <PolicySnapshot policies={run.policy_snapshot} />
    </div>
  );
}

function SessionLinks({ sessionId }: { sessionId: string | null }) {
  if (!sessionId) {
    return <p className="text-xs text-fg-muted">No session was recorded for this run, so there is no session or provenance graph to open.</p>;
  }
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border border-border bg-surface-2/40 px-3 py-2.5 text-xs">
      <span className="inline-flex items-center gap-1.5">
        <span className="text-fg-faint">Session</span>
        <EntityLink type="session" id={sessionId} />
      </span>
      <Link to={provenanceHref("session", sessionId)} className="inline-flex items-center gap-1 rounded-sm text-accent hover:text-accent-strong hover:underline hover:underline-offset-2">
        <GitBranch className="h-3.5 w-3.5" aria-hidden />
        Provenance graph
      </Link>
      <span className="basis-full text-fg-faint">The provenance graph shows observed relationships between records, not causes.</span>
    </div>
  );
}

function CheckRow({ check, sessionId }: { check: ExpectationResult; sessionId: string | null }) {
  return (
    <li className={cn("rounded-md border p-3", check.passed ? "border-border" : "border-danger/30 bg-danger/[0.04]")}>
      <div className="flex items-start gap-2">
        <StatusBadge status={check.passed ? "passed" : "failed"} className="mt-px shrink-0" />
        <div className="min-w-0 flex-1">
          <p className="text-[13px] leading-5 text-fg">{check.expectation}</p>
          <Mono className="text-2xs text-fg-faint">{check.step}</Mono>
        </div>
      </div>
      <dl className="mt-2 grid gap-2 text-xs sm:grid-cols-2">
        <div className="min-w-0">
          <dt className="label-caps">Expected</dt>
          <dd className="mt-0.5 break-words text-fg">{check.expected}</dd>
        </div>
        <div className="min-w-0">
          <dt className="label-caps">Actual</dt>
          <dd className="mt-0.5 break-words text-fg">
            <RedactedText text={check.actual ?? ""} />
          </dd>
        </div>
      </dl>
      <EvidenceLinks evidence={check.evidence} sessionId={sessionId} className="mt-2" />
    </li>
  );
}

function StepRow({ index, step, sessionId }: { index: number; step: ObservationResult; sessionId: string | null }) {
  const outcome = describeObservation(step);
  const mode = observationEnforcement(step);
  const policies = (step.matched_policies ?? []).filter((p): p is string => typeof p === "string" && p.length > 0);
  const emphasise = outcome.tone === "danger" || outcome.tone === "warn";
  return (
    <li className="rounded-md border border-border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="num text-2xs text-fg-faint">{index}.</span>
        <Mono className="text-fg">{step.step}</Mono>
        {step.decision && <DecisionBadge decision={step.decision} />}
        {mode && <EnforcementBadge mode={mode} />}
      </div>
      <p className={cn("mt-1.5 text-xs leading-5", emphasise ? TONE_CLASSES[outcome.tone].text : "text-fg")}>{outcome.text}</p>
      <p className="mt-0.5 text-2xs text-fg-faint">
        Recorded: <RedactedText text={step.actual ?? ""} />
      </p>
      {policies.length > 0 && <p className="mt-1 text-xs text-fg-muted">Matched policies: {policies.join(", ")}</p>}
      <EvidenceLinks evidence={step.evidence} sessionId={sessionId} className="mt-1.5" />
    </li>
  );
}

function PolicySnapshot({ policies }: { policies: PolicySnapshotEntry[] | null | undefined }) {
  const rows = Array.isArray(policies) ? policies : [];
  return (
    <details className="group rounded-md border border-border">
      <summary className="cursor-pointer select-none rounded-md px-3 py-2.5 text-[13px] font-medium text-fg hover:bg-surface-2/60">
        Policy snapshot <span className="num font-normal text-fg-muted">({rows.length})</span>
        <span className="ml-2 text-xs font-normal text-fg-muted">Policies as configured when the run started</span>
      </summary>
      {rows.length === 0 ? (
        <p className="border-t border-border px-3 py-3 text-xs text-fg-muted">The organisation had no policies when this run started.</p>
      ) : (
        <Table className="border-t border-border">
          <THead>
            <tr>
              <TH>Policy</TH>
              <TH>Outcome</TH>
              <TH>Mode</TH>
              <TH>Version</TH>
              <TH>State</TH>
            </tr>
          </THead>
          <tbody>
            {rows.map((p) => (
              <TR key={p.policy_id}>
                <TD className="max-w-[16rem]">
                  <EntityLink type="policy" id={p.policy_id} label={p.name} showIcon={false} />
                </TD>
                <TD>
                  <DecisionBadge decision={p.outcome} />
                </TD>
                <TD className="text-xs text-fg-muted">
                  <span title={POLICY_MODE_META[p.mode as PolicyMode]?.description}>{labelFrom(MODE_LABELS, p.mode)}</span>
                </TD>
                <TD className="num text-xs text-fg-muted">{p.version ?? "—"}</TD>
                <TD className="text-xs text-fg-muted">{p.enabled ? "Enabled" : "Disabled"}</TD>
              </TR>
            ))}
          </tbody>
        </Table>
      )}
    </details>
  );
}
