/**
 * Pure Simulation Lab view logic (no React): grouping the catalogue, splitting run results,
 * honest step wording, verdicts, suite pass rates and ordering a suite comparison.
 */
import { FINDING_CATEGORY_LABELS, labelFrom, type EnforcementMode, type Tone } from "@/lib/domain";
import type { DiffStatus, ExpectationResult, ObservationResult, RunResult, Scenario, ScenarioDiff, SimulationRun, SuiteSummary } from "./types";

/* ----------------------------------------------------------------------------- catalogue */

const CATEGORY_LABELS: Record<string, string> = {
  ...FINDING_CATEGORY_LABELS,
  baseline: "Baseline (false-positive guard)",
};

export function categoryLabel(category: string): string {
  return labelFrom(CATEGORY_LABELS, category);
}

export interface ScenarioGroup {
  category: string;
  label: string;
  scenarios: Scenario[];
}

/** Group scenarios by category, keeping the server's catalogue order for groups and scenarios. */
export function groupScenarios(scenarios: Scenario[]): ScenarioGroup[] {
  const groups = new Map<string, ScenarioGroup>();
  for (const s of scenarios) {
    let group = groups.get(s.category);
    if (!group) {
      group = { category: s.category, label: categoryLabel(s.category), scenarios: [] };
      groups.set(s.category, group);
    }
    group.scenarios.push(s);
  }
  return [...groups.values()];
}

/** "read-ssh-key" → "read ssh key" (step labels are slugs). */
export function stepLabel(step: string): string {
  return step.replace(/[-_]+/g, " ").trim();
}

/* ----------------------------------------------------------------------------- run results */

export function isExpectation(r: RunResult): r is ExpectationResult {
  return r.kind === "expectation";
}

export function isObservation(r: RunResult): r is ObservationResult {
  return r.kind === "observation";
}

export function splitResults(results: RunResult[] | null | undefined): { checks: ExpectationResult[]; observations: ObservationResult[] } {
  const rows = Array.isArray(results) ? results : [];
  return { checks: rows.filter(isExpectation), observations: rows.filter(isObservation) };
}

export type Verdict = "passed" | "failed" | "stopped" | "running";

/** Overall outcome: every check passed, some failed, the run stopped early, or it is still running. */
export function runVerdict(run: Pick<SimulationRun, "status" | "passed">): Verdict {
  if (run.status === "running") return "running";
  if (run.status === "failed") return "stopped";
  return run.passed ? "passed" : "failed";
}

export const VERDICT_META: Record<Verdict, { label: string; status: string; description: string }> = {
  passed: { label: "All checks passed", status: "passed", description: "The configured pipeline recorded everything the scenario expects." },
  failed: { label: "Checks failed", status: "failed", description: "At least one expectation was not met — a protection did not behave as the scenario expects." },
  stopped: { label: "Stopped early", status: "error", description: "A pipeline error stopped the run before every step was submitted." },
  running: { label: "Running", status: "running", description: "The run has not finished." },
};

const ENFORCEMENT_IN_ACTUAL = /^[A-Z_]+ \((enforced|advisory|observed)\)/;

/**
 * Enforcement mode recorded for a step. Uses the server's `enforcement` field; runs recorded before
 * that field existed fall back to parsing the "DECISION (mode)" wording.
 */
export function observationEnforcement(o: Pick<ObservationResult, "actual" | "decision" | "enforcement">): EnforcementMode | null {
  if (!o.decision) return null;
  if (o.enforcement === "enforced" || o.enforcement === "advisory" || o.enforcement === "observed") return o.enforcement;
  const m = ENFORCEMENT_IN_ACTUAL.exec(o.actual ?? "");
  return m ? (m[1] as EnforcementMode) : null;
}

export interface StepOutcomeText {
  text: string;
  tone: Tone;
}

/**
 * Plain-language outcome of one step. "Denied before it ran" is said only when the decision was
 * enforced at the boundary; advisory/observed decisions are described as such. Nothing in a
 * simulation is ever executed, so allowed steps say "would have run".
 */
export function describeObservation(o: Pick<ObservationResult, "actual" | "decision" | "enforcement">): StepOutcomeText {
  const actual = o.actual ?? "";
  if (actual.startsWith("pipeline error")) return { text: "The pipeline reported an error for this step.", tone: "danger" };
  if (actual.startsWith("not run")) return { text: "Not submitted — an earlier step failed.", tone: "neutral" };
  if (!o.decision) return { text: "Recorded by the pipeline (no tool decision at this step).", tone: "neutral" };
  const mode = observationEnforcement(o);
  if (mode === "observed") return { text: "Recorded after the fact — nothing could be prevented.", tone: "neutral" };
  if (mode !== "enforced") {
    const verb = o.decision === "DENY" ? "would have been denied" : o.decision === "REQUIRE_APPROVAL" ? "would have needed approval" : "decision returned";
    return { text: `${capitalise(verb)}, but the decision was ${mode ?? "not recorded as enforced"} — the integration may not honour it.`, tone: "warn" };
  }
  switch (o.decision) {
    case "DENY":
      return { text: "Denied before it ran.", tone: "deny" };
    case "REQUIRE_APPROVAL":
      return { text: "Held for approval before it ran; the Simulation Lab closes simulated approval requests automatically.", tone: "approval" };
    case "RESTRICT":
      return { text: "Allowed only with restrictions; the Simulation Lab treats it as not run.", tone: "restrict" };
    case "AUDIT":
      return { text: "Allowed and recorded for review (nothing is executed in a simulation).", tone: "audit" };
    case "ALLOW":
      return { text: "Allowed (nothing is executed in a simulation).", tone: "allow" };
    default:
      return { text: actual, tone: "neutral" };
  }
}

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/* ----------------------------------------------------------------------------- evidence */

/** Backend evidence kinds → EntityLink types (unknown kinds render as plain ids). */
const EVIDENCE_TYPES: Record<string, string> = { context_source: "source" };

export function evidenceEntityType(type: string): string {
  return EVIDENCE_TYPES[type] ?? type;
}

/* ----------------------------------------------------------------------------- suites */

/** Share of runs whose checks all passed, 0–100 (null for an empty suite). */
export function passRate(s: Pick<SuiteSummary, "run_count" | "passed_count">): number | null {
  if (!s.run_count) return null;
  return Math.round((s.passed_count / s.run_count) * 100);
}

export const DIFF_STATUS_META: Record<DiffStatus, { label: string; tone: Tone; order: number; description: string }> = {
  regressed: { label: "Regressed", tone: "danger", order: 0, description: "Passed in the base suite, fails in the head suite." },
  fixed: { label: "Fixed", tone: "ok", order: 1, description: "Failed in the base suite, passes in the head suite." },
  unchanged_fail: { label: "Still failing", tone: "warn", order: 2, description: "Fails in both suites." },
  added: { label: "Only in head", tone: "accent", order: 3, description: "The scenario ran in the head suite only." },
  removed: { label: "Only in base", tone: "neutral", order: 4, description: "The scenario ran in the base suite only." },
  unchanged_pass: { label: "Still passing", tone: "neutral", order: 5, description: "Passes in both suites." },
};

export function diffStatusMeta(status: string) {
  return DIFF_STATUS_META[status as DiffStatus] ?? { label: labelFrom({}, status), tone: "neutral" as Tone, order: 9, description: "" };
}

/** Regressions first, then fixes, then the rest; scenario name breaks ties. */
export function sortDiffs(diffs: ScenarioDiff[]): ScenarioDiff[] {
  return [...diffs].sort((a, b) => diffStatusMeta(a.status).order - diffStatusMeta(b.status).order || a.scenario_name.localeCompare(b.scenario_name));
}

export interface CompareCounts {
  regressed: number;
  fixed: number;
  unchanged: number;
  other: number;
}

export function compareCounts(counts: Record<string, number>): CompareCounts {
  const get = (k: string) => counts[k] ?? 0;
  return {
    regressed: get("regressed"),
    fixed: get("fixed"),
    unchanged: get("unchanged_pass") + get("unchanged_fail"),
    other: get("added") + get("removed"),
  };
}

/** Default pair for the comparison: the two most recent suites (head = newest). */
export function defaultComparePair(suites: SuiteSummary[]): { base: string | null; head: string | null } {
  if (suites.length < 2) return { base: null, head: suites[0]?.suite_run_id ?? null };
  return { base: suites[1].suite_run_id, head: suites[0].suite_run_id };
}
