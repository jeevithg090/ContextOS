/**
 * Simulation Lab — answers "would our controls catch these attacks?".
 *
 * Scenarios submit synthetic, inert events to the real pipeline (nothing is executed) and check
 * what the configured policies, trust rules and detectors recorded. Tabs: the scenario catalogue
 * (run one, or all as a regression suite against an optional real agent), run/suite history and
 * a before/after suite comparison. Every view is a link (./urlState.ts); `?run=<id>` opens a run.
 * Live `simulation.completed` events refresh the "simulations" queries (hooks/useLiveEvents).
 */
import { useState } from "react";
import { PageHeader, TabPanel, Tabs, useToast } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { useScenarios, useStartRun, useStartSuite } from "./api";
import { CompareTab } from "./components/CompareTab";
import { RunDrawer } from "./components/RunDrawer";
import type { RunTargetValue } from "./components/RunTarget";
import { RunsTable } from "./components/RunsTable";
import { ScenarioCatalogue } from "./components/ScenarioCatalogue";
import { SimulationBanner } from "./components/SimulationBanner";
import { SuitesTable } from "./components/SuitesTable";
import { runFiltersFrom, tabFrom, useSimulationParams, type SimulationTab } from "./urlState";
import type { Scenario } from "./types";

export function SimulationLabPage() {
  const { params, set } = useSimulationParams();
  const { can } = useAuth();
  const canWrite = can("write");
  const toast = useToast();
  const scenarios = useScenarios();
  const startRun = useStartRun();
  const startSuite = useStartSuite();
  const [target, setTarget] = useState<RunTargetValue>({ agentId: "", version: "" });

  const tab = tabFrom(params);
  const runId = params.get("run");
  const filters = runFiltersFrom(params);
  const targetBody = { agent_id: target.agentId || null, agent_version: target.version.trim() || null };

  const openRun = (id: string) => set({ run: id }, { push: true });
  const showSuite = (suiteRunId: string) => set({ tab: "history", suite: suiteRunId, run: null }, { push: true });

  const runScenario = (scenario: Scenario) => {
    startRun.mutate(
      { scenario_id: scenario.id, ...targetBody },
      {
        onSuccess: (run) => {
          if (run.passed) toast.success(`${run.scenario_name}: all checks passed`, run.summary);
          else toast.toast({ kind: "info", title: `${run.scenario_name}: ${run.checks_total - run.checks_passed} of ${run.checks_total} checks failed`, description: "Open the run to see which protection did not behave as expected." });
          set({ run: run.id }, { push: true });
        },
        onError: (err) => toast.error(`Could not run ${scenario.name}`, err instanceof Error ? err.message : undefined),
      },
    );
  };

  const runSuite = () => {
    startSuite.mutate(targetBody, {
      onSuccess: (suite) => {
        toast.success(`Suite finished: ${suite.passed_count} of ${suite.run_count} scenarios passed`, suite.failed_count ? `${suite.failed_count} scenario(s) had failing checks.` : undefined);
        set({ tab: "history", suite: suite.suite_run_id, scenario: null, verdict: null, agent: null, run: null }, { push: true });
      },
      onError: (err) => toast.error("Could not run the suite", err instanceof Error ? err.message : undefined),
    });
  };

  return (
    <>
      <PageHeader
        title="Simulation Lab"
        description="Replay controlled attack scenarios through the real ingestion and policy pipeline and check that detections, trust classifications and enforced decisions behave as expected. Run them as a suite to catch regressions after a policy or agent change."
      />
      <SimulationBanner />

      <Tabs
        value={tab}
        onValueChange={(v) => set({ tab: v === "scenarios" ? null : (v as SimulationTab) })}
        tabs={[
          { value: "scenarios", label: "Scenarios", count: scenarios.data?.items.length },
          { value: "history", label: "History" },
          { value: "compare", label: "Compare suites" },
        ]}
      >
        <TabPanel value="scenarios" className="pt-4">
          <ScenarioCatalogue
            scenarios={scenarios.data?.items}
            loading={scenarios.isLoading}
            error={scenarios.error}
            onRetry={() => void scenarios.refetch()}
            canWrite={canWrite}
            target={target}
            onTargetChange={setTarget}
            onRun={runScenario}
            onRunSuite={runSuite}
            runningScenarioId={startRun.isPending ? (startRun.variables?.scenario_id ?? null) : null}
            suiteRunning={startSuite.isPending}
          />
        </TabPanel>
        <TabPanel value="history" className="space-y-4 pt-4">
          <RunsTable filters={filters} scenarios={scenarios.data?.items} selectedRunId={runId} onOpenRun={openRun} onFilterChange={(u) => set(u)} />
          <SuitesTable
            selectedSuiteId={filters.suite_run_id ?? null}
            onShowRuns={(id) => set({ suite: id })}
            onCompare={(base, head) => set({ tab: "compare", base, head }, { push: true })}
          />
        </TabPanel>
        <TabPanel value="compare" className="pt-4">
          <CompareTab base={params.get("base")} head={params.get("head")} onChange={(pair) => set(pair)} onOpenRun={openRun} />
        </TabPanel>
      </Tabs>

      <RunDrawer runId={runId} onClose={() => set({ run: null })} onShowSuite={showSuite} />
    </>
  );
}
