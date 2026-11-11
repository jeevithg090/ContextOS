/**
 * Simulation Lab API payloads. Mirrors backend/app/schemas/simulations.py (ScenarioOut,
 * SimulationRunOut, SuiteSummaryOut, SuiteOut, SuiteCompareOut) and the result rows written by
 * backend/app/services/simulations.py (`_evaluate`).
 */

export interface ScenarioCheck {
  id: string;
  /** Plain-language statement of what the configured pipeline should record. */
  description: string;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  category: string;
  use_case: string;
  demo: boolean;
  tags: string[];
  /** Step labels in order (what the simulated agent reports). */
  steps: string[];
  checks: ScenarioCheck[];
}

export interface ScenarioList {
  items: Scenario[];
  note: string;
}

/** Evidence reference attached to a result row: a record the pipeline wrote during the run. */
export interface ResultEvidence {
  type: string;
  id: string;
}

/** One expectation (check) of the scenario, evaluated against the rows the run wrote. */
export interface ExpectationResult {
  kind: "expectation";
  /** Check id, e.g. "decision:read-ssh-key" or "redaction". */
  step: string;
  expectation: string;
  expected: string;
  actual: string;
  passed: boolean;
  evidence: ResultEvidence[];
  evidence_ids: string[];
}

/** What happened at one step (informational; never pass/fail). */
export interface ObservationResult {
  kind: "observation";
  step: string;
  expectation: string;
  expected: null;
  /** e.g. "DENY (enforced) — not run", "recorded", "pipeline error: …". */
  actual: string;
  passed: null;
  decision?: string | null;
  matched_policies?: Array<string | null>;
  evidence: ResultEvidence[];
  evidence_ids: string[];
}

export type RunResult = ExpectationResult | ObservationResult;

/** Policy as configured when the run started (SimulationRun.policy_snapshot). */
export interface PolicySnapshotEntry {
  policy_id: string;
  name: string;
  version: number | string | null;
  enabled: boolean;
  mode: string;
  outcome: string;
}

export interface SimulationRun {
  id: string;
  scenario_id: string;
  scenario_name: string;
  suite_run_id: string | null;
  agent_id: string | null;
  agent_version: string | null;
  session_id: string | null;
  /** running | completed | failed (stopped early) */
  status: string;
  passed: boolean | null;
  summary: string;
  error: string | null;
  results: RunResult[];
  policy_snapshot: PolicySnapshotEntry[];
  started_at: string;
  completed_at: string | null;
  triggered_by_user_id: string | null;
  checks_total: number;
  checks_passed: number;
  is_simulation: boolean;
}

export interface SuiteSummary {
  suite_run_id: string;
  run_count: number;
  passed_count: number;
  failed_count: number;
  started_at: string;
  completed_at: string | null;
  agent_id: string | null;
  agent_version: string | null;
}

export interface Suite extends SuiteSummary {
  runs: SimulationRun[];
}

export interface CheckChange {
  check: string;
  expectation: string;
  base_passed: boolean | null;
  head_passed: boolean | null;
  base_actual: string;
  head_actual: string;
}

export interface DecisionChange {
  step: string;
  base: string | null;
  head: string | null;
}

export type DiffStatus = "regressed" | "fixed" | "unchanged_pass" | "unchanged_fail" | "added" | "removed";

export interface ScenarioDiff {
  scenario_id: string;
  scenario_name: string;
  status: DiffStatus | string;
  base_run_id: string | null;
  head_run_id: string | null;
  base_passed: boolean | null;
  head_passed: boolean | null;
  check_changes: CheckChange[];
  decision_changes: DecisionChange[];
  new_finding_categories: string[];
  resolved_finding_categories: string[];
}

export interface PolicyChange {
  policy_id: string;
  name: string | null;
  change: string;
}

export interface SuiteCompare {
  base: SuiteSummary;
  head: SuiteSummary;
  scenarios: ScenarioDiff[];
  counts: Record<string, number>;
  regressions: number;
  policy_changes: PolicyChange[];
  note: string;
}

export interface RunInput {
  scenario_id: string;
  agent_id?: string | null;
  agent_version?: string | null;
}

export interface SuiteInput {
  scenario_ids?: string[] | null;
  agent_id?: string | null;
  agent_version?: string | null;
}

/** GET /simulations/runs query filters. */
export interface RunFilters {
  scenario_id?: string;
  suite_run_id?: string;
  agent_id?: string;
  passed?: boolean;
}

/** The subset of AgentSummaryOut (backend/app/schemas/agents.py) the target picker needs. */
export interface AgentOption {
  id: string;
  name: string;
  framework: string;
  version: string | null;
  environment: string;
  status: string;
}
