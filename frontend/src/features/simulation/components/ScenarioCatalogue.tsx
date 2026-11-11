/**
 * The scenario catalogue grouped by category, with a per-scenario "Run" and "Run all as suite".
 * Starting runs needs the `write` permission; viewers see disabled buttons with the reason.
 */
import { useId } from "react";
import { CheckCircle2, FlaskConical, Play, PlayCircle } from "lucide-react";
import { Section } from "@/components/data";
import { Button, EmptyState, ErrorState, LoadingRows } from "@/components/ui";
import { pluralize } from "@/lib/format";
import { groupScenarios, stepLabel } from "../logic";
import type { Scenario } from "../types";
import { RunTarget, type RunTargetValue } from "./RunTarget";

export interface ScenarioCatalogueProps {
  scenarios: Scenario[] | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  canWrite: boolean;
  target: RunTargetValue;
  onTargetChange: (next: RunTargetValue) => void;
  onRun: (scenario: Scenario) => void;
  onRunSuite: () => void;
  /** Scenario id of the single run in flight, if any. */
  runningScenarioId: string | null;
  suiteRunning: boolean;
}

export function ScenarioCatalogue(props: ScenarioCatalogueProps) {
  const { scenarios, loading, error, onRetry, canWrite, target, onTargetChange, onRun, onRunSuite, runningScenarioId, suiteRunning } = props;
  const permissionNoteId = useId();

  if (loading && !scenarios) return <LoadingRows rows={6} />;
  if (error && !scenarios) return <ErrorState error={error} onRetry={onRetry} />;
  if (!scenarios || scenarios.length === 0) {
    return <EmptyState icon={<FlaskConical className="h-5 w-5" />} title="No scenarios available" description="The server returned an empty scenario catalogue. Scenarios ship with the ContextOS server (backend/app/simulations/scenarios.py)." />;
  }

  const groups = groupScenarios(scenarios);
  const busy = suiteRunning || runningScenarioId !== null;
  const disabledReason = canWrite ? undefined : "Starting a simulation needs the write permission.";

  return (
    <div className="space-y-6">
      <Section
        title="Run target"
        description="Simulations are attributed to a dedicated simulated agent unless you pick a registered agent to regression-test it."
        actions={
          <Button
            variant="primary"
            size="sm"
            icon={<PlayCircle className="h-3.5 w-3.5" aria-hidden />}
            onClick={onRunSuite}
            loading={suiteRunning}
            disabled={!canWrite || busy}
            title={disabledReason}
            aria-describedby={canWrite ? undefined : permissionNoteId}
          >
            {suiteRunning ? `Running ${pluralize(scenarios.length, "scenario")}…` : "Run all as suite"}
          </Button>
        }
      >
        <RunTarget value={target} onChange={onTargetChange} disabled={!canWrite || busy} />
        {canWrite ? (
          <p className="mt-3 text-xs text-fg-muted">
            A suite runs every scenario once and groups the results, so two suites can be compared before and after a change to policies, trust rules or the agent.
          </p>
        ) : (
          <p id={permissionNoteId} className="mt-3 text-xs text-fg-muted">
            Your role can view scenarios and results but cannot start runs: starting a simulation writes simulated events and needs the write permission.
          </p>
        )}
      </Section>

      {groups.map((group) => (
        <section key={group.category} aria-labelledby={`cat-${group.category}`} className="space-y-2">
          <h2 id={`cat-${group.category}`} className="label-caps">
            {group.label} <span className="num">· {group.scenarios.length}</span>
          </h2>
          <ul className="grid gap-3 lg:grid-cols-2">
            {group.scenarios.map((s) => (
              <li key={s.id} className="min-w-0">
                <ScenarioCard
                  scenario={s}
                  onRun={() => onRun(s)}
                  running={runningScenarioId === s.id}
                  disabled={!canWrite || busy}
                  disabledReason={disabledReason}
                  describedBy={canWrite ? undefined : permissionNoteId}
                />
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

function ScenarioCard({ scenario, onRun, running, disabled, disabledReason, describedBy }: { scenario: Scenario; onRun: () => void; running: boolean; disabled: boolean; disabledReason?: string; describedBy?: string }) {
  const headingId = `scenario-${scenario.id}`;
  return (
    <article aria-labelledby={headingId} className="panel flex h-full flex-col p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="label-caps">{scenario.use_case}</div>
          <h3 id={headingId} className="mt-1 text-[14px] font-semibold text-fg">
            {scenario.name}
          </h3>
        </div>
        <Button
          size="sm"
          variant="outline"
          icon={<Play className="h-3.5 w-3.5" aria-hidden />}
          onClick={onRun}
          loading={running}
          disabled={disabled}
          title={disabledReason}
          aria-label={running ? `Running ${scenario.name}` : `Run ${scenario.name}`}
          aria-describedby={describedBy}
          className="shrink-0"
        >
          {running ? "Running…" : "Run"}
        </Button>
      </div>
      <p className="mt-2 text-xs leading-5 text-fg-muted">{scenario.description}</p>

      <div className="mt-3">
        <div className="text-2xs font-medium uppercase tracking-[0.06em] text-fg-faint">Checks · {scenario.checks.length}</div>
        <ul className="mt-1.5 space-y-1">
          {scenario.checks.map((c) => (
            <li key={c.id} className="flex items-start gap-1.5 text-xs leading-5 text-fg">
              <CheckCircle2 className="mt-[3px] h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
              <span>{c.description}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="mt-3">
        <div className="text-2xs font-medium uppercase tracking-[0.06em] text-fg-faint">Steps · {scenario.steps.length}</div>
        <ol className="mt-1.5 flex flex-wrap gap-1.5">
          {scenario.steps.map((step, i) => (
            <li key={`${step}-${i}`} className="inline-flex items-center gap-1 rounded border border-border bg-surface-2/60 px-1.5 py-0.5 text-2xs text-fg-muted" title={step}>
              <span className="num text-fg-faint">{i + 1}</span>
              {stepLabel(step)}
            </li>
          ))}
        </ol>
      </div>

      {scenario.tags.length > 0 && <p className="mt-auto pt-3 text-2xs text-fg-faint">Tags: {scenario.tags.join(", ")}</p>}
    </article>
  );
}
