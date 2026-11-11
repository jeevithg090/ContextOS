/**
 * Simulation Lab data hooks. Backend contract: backend/app/api/routes/simulations.py.
 *   GET  /simulations/scenarios            -> ScenarioList (read)
 *   POST /simulations/runs                 -> SimulationRun (write; 201, synchronous: complete on return)
 *   GET  /simulations/runs                 -> Page<SimulationRun> (read; scenario_id, suite_run_id, agent_id, passed)
 *   GET  /simulations/runs/{id}            -> SimulationRun (404 for another organisation's id)
 *   POST /simulations/suites               -> Suite (write; 201; omit scenario_ids to run the whole catalogue)
 *   GET  /simulations/suites               -> Page<SuiteSummary> (read; newest first)
 *   GET  /simulations/suites/compare       -> SuiteCompare (read; ?base=<suite>&head=<suite>)
 *   GET  /agents                           -> AgentPage (read; real agents only — the regression-test target picker)
 * Query keys start with "simulations" so the live `simulation.completed` notification refreshes them.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { api, ApiError, type Page } from "@/lib/api";
import { INVALIDATIONS } from "@/hooks/useLiveEvents";
import type { AgentOption, RunFilters, RunInput, ScenarioList, SimulationRun, Suite, SuiteCompare, SuiteInput, SuiteSummary } from "./types";

const enc = encodeURIComponent;

export const simulationKeys = {
  all: ["simulations"] as const,
  scenarios: () => ["simulations", "scenarios"] as const,
  runs: (filters: RunFilters, limit: number, offset: number) => ["simulations", "runs", filters, limit, offset] as const,
  run: (id: string) => ["simulations", "run", id] as const,
  suites: (limit: number, offset: number) => ["simulations", "suites", limit, offset] as const,
  compare: (base: string, head: string) => ["simulations", "compare", base, head] as const,
  agentOptions: () => ["simulations", "agent-options"] as const,
};

/** "Not found" / "forbidden" are definitive answers (another organisation's id): never retry them. */
export const retryUnlessMissing = (count: number, err: unknown) =>
  !(err instanceof ApiError && (err.status === 404 || err.status === 403)) && count < 2;

export function isNotFound(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

export function useScenarios() {
  return useQuery({
    queryKey: simulationKeys.scenarios(),
    queryFn: () => api.get<ScenarioList>("/simulations/scenarios"),
    staleTime: 5 * 60_000,
  });
}

export function useRuns(filters: RunFilters, limit: number, offset: number) {
  return useQuery({
    queryKey: simulationKeys.runs(filters, limit, offset),
    queryFn: () => api.get<Page<SimulationRun>>("/simulations/runs", { ...filters, limit, offset }),
    placeholderData: keepPreviousData,
  });
}

export function useRun(id: string | null | undefined) {
  return useQuery({
    queryKey: simulationKeys.run(id ?? ""),
    queryFn: () => api.get<SimulationRun>(`/simulations/runs/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessMissing,
  });
}

export function useSuites(limit: number, offset: number) {
  return useQuery({
    queryKey: simulationKeys.suites(limit, offset),
    queryFn: () => api.get<Page<SuiteSummary>>("/simulations/suites", { limit, offset }),
    placeholderData: keepPreviousData,
  });
}

export function useSuiteCompare(base: string | null, head: string | null) {
  return useQuery({
    queryKey: simulationKeys.compare(base ?? "", head ?? ""),
    queryFn: () => api.get<SuiteCompare>("/simulations/suites/compare", { base, head }),
    enabled: !!base && !!head && base !== head,
    retry: retryUnlessMissing,
  });
}

/** Registered (non-simulated) agents a run can target for regression testing. */
export function useAgentOptions(enabled = true) {
  return useQuery({
    queryKey: simulationKeys.agentOptions(),
    queryFn: async () => (await api.get<Page<AgentOption>>("/agents", { sort: "name", limit: 200 })).items,
    enabled,
    staleTime: 60_000,
  });
}

/**
 * A run writes simulated rows through the real pipeline (sessions, findings, decisions, approvals,
 * incidents, provenance …), so refresh exactly what the live `simulation.completed` event refreshes.
 */
function invalidateAfterRun(qc: QueryClient) {
  for (const queryKey of INVALIDATIONS["simulation.completed"] ?? [simulationKeys.all]) {
    void qc.invalidateQueries({ queryKey });
  }
  void qc.invalidateQueries({ queryKey: ["integrations"], refetchType: "none" });
}

export function useStartRun() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RunInput) => api.post<SimulationRun>("/simulations/runs", body),
    onSuccess: (run) => {
      qc.setQueryData(simulationKeys.run(run.id), run);
      invalidateAfterRun(qc);
    },
  });
}

export function useStartSuite() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SuiteInput) => api.post<Suite>("/simulations/suites", body),
    onSuccess: (suite) => {
      for (const run of suite.runs) qc.setQueryData(simulationKeys.run(run.id), run);
      invalidateAfterRun(qc);
    },
  });
}
