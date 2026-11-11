/**
 * URL-backed view state for the Simulation Lab, so every view is a link:
 *   ?tab=scenarios|history|compare  ?run=<run id> (detail drawer)
 *   history filters: ?scenario=&verdict=passed|failed&agent=&suite=
 *   comparison:      ?base=<suite id>&head=<suite id>
 */
import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import type { RunFilters } from "./types";

export const TABS = ["scenarios", "history", "compare"] as const;
export type SimulationTab = (typeof TABS)[number];

export type ParamUpdate = Record<string, string | null | undefined>;

export function tabFrom(params: URLSearchParams): SimulationTab {
  const tab = params.get("tab");
  return (TABS as readonly string[]).includes(tab ?? "") ? (tab as SimulationTab) : "scenarios";
}

export function runFiltersFrom(params: URLSearchParams): RunFilters {
  const verdict = params.get("verdict");
  const filters: RunFilters = {};
  const scenario = params.get("scenario");
  const agent = params.get("agent");
  const suite = params.get("suite");
  if (scenario) filters.scenario_id = scenario;
  if (agent) filters.agent_id = agent;
  if (suite) filters.suite_run_id = suite;
  if (verdict === "passed") filters.passed = true;
  else if (verdict === "failed") filters.passed = false;
  return filters;
}

/** Apply updates to a copy of the params (empty values remove the key). */
export function applyParams(prev: URLSearchParams, updates: ParamUpdate): URLSearchParams {
  const next = new URLSearchParams(prev);
  for (const [key, value] of Object.entries(updates)) {
    if (value) next.set(key, value);
    else next.delete(key);
  }
  return next;
}

export function useSimulationParams() {
  const [params, setSearchParams] = useSearchParams();
  const set = useCallback(
    (updates: ParamUpdate, opts?: { push?: boolean }) => setSearchParams((prev) => applyParams(prev, updates), { replace: !opts?.push }),
    [setSearchParams],
  );
  return { params, set };
}
