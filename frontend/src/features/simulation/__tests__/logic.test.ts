import { describe, expect, it } from "vitest";
import {
  categoryLabel,
  compareCounts,
  defaultComparePair,
  describeObservation,
  evidenceEntityType,
  groupScenarios,
  observationEnforcement,
  passRate,
  runVerdict,
  sortDiffs,
  splitResults,
  stepLabel,
} from "../logic";
import { applyParams, runFiltersFrom, tabFrom } from "../urlState";
import type { RunResult, Scenario, ScenarioDiff, SuiteSummary } from "../types";

const scenario = (id: string, category: string): Scenario => ({
  id,
  name: id,
  description: "",
  category,
  use_case: "",
  demo: true,
  tags: [],
  steps: [],
  checks: [],
});

describe("catalogue", () => {
  it("groups by category in catalogue order and labels categories", () => {
    const groups = groupScenarios([scenario("a", "prompt_injection"), scenario("b", "exfiltration"), scenario("c", "prompt_injection"), scenario("d", "baseline")]);
    expect(groups.map((g) => g.category)).toEqual(["prompt_injection", "exfiltration", "baseline"]);
    expect(groups[0].scenarios.map((s) => s.id)).toEqual(["a", "c"]);
    expect(groups[0].label).toBe("Prompt injection");
    expect(categoryLabel("baseline")).toMatch(/false-positive/);
    expect(categoryLabel("brand_new_category")).toBe("Brand new category");
  });

  it("humanises step slugs", () => {
    expect(stepLabel("read-ssh-key")).toBe("read ssh key");
  });
});

describe("run results", () => {
  const results: RunResult[] = [
    { kind: "expectation", step: "redaction", expectation: "No raw secret", expected: "x", actual: "y", passed: true, evidence: [], evidence_ids: [] },
    { kind: "observation", step: "s1", expectation: "Step", expected: null, actual: "DENY (enforced) — not run", passed: null, decision: "DENY", evidence: [], evidence_ids: [] },
  ];

  it("splits checks from step observations and tolerates a missing list", () => {
    const { checks, observations } = splitResults(results);
    expect(checks).toHaveLength(1);
    expect(observations).toHaveLength(1);
    expect(splitResults(null)).toEqual({ checks: [], observations: [] });
  });

  it("derives the verdict from status and passed", () => {
    expect(runVerdict({ status: "completed", passed: true })).toBe("passed");
    expect(runVerdict({ status: "completed", passed: false })).toBe("failed");
    expect(runVerdict({ status: "failed", passed: false })).toBe("stopped");
    expect(runVerdict({ status: "running", passed: null })).toBe("running");
  });

  it("parses the enforcement mode only from the decision wording", () => {
    expect(observationEnforcement({ actual: "DENY (enforced) — not run", decision: "DENY" })).toBe("enforced");
    expect(observationEnforcement({ actual: "REQUIRE_APPROVAL (advisory)", decision: "REQUIRE_APPROVAL" })).toBe("advisory");
    expect(observationEnforcement({ actual: "recorded", decision: null })).toBeNull();
    // A step without a decision never claims a mode, whatever its text says.
    expect(observationEnforcement({ actual: "DENY (enforced)", decision: null })).toBeNull();
  });
});

describe("honest step wording", () => {
  it("says 'denied before it ran' only for enforced denials", () => {
    expect(describeObservation({ actual: "DENY (enforced) — not run", decision: "DENY" }).text).toBe("Denied before it ran.");
    for (const actual of ["DENY (advisory) — not run", "DENY (observed)", "DENY something unexpected"]) {
      const text = describeObservation({ actual, decision: "DENY" }).text;
      expect(text).not.toMatch(/denied before it ran/i);
      expect(text).not.toMatch(/\bblocked\b/i);
    }
    expect(describeObservation({ actual: "DENY (advisory) — not run", decision: "DENY" }).text).toMatch(/would have been denied.*advisory/i);
    expect(describeObservation({ actual: "DENY (observed)", decision: "DENY" }).text).toMatch(/nothing could be prevented/i);
  });

  it("never claims an allowed step was executed", () => {
    expect(describeObservation({ actual: "ALLOW (enforced)", decision: "ALLOW" }).text).toMatch(/nothing is executed/i);
    expect(describeObservation({ actual: "AUDIT (enforced)", decision: "AUDIT" }).text).toMatch(/recorded for review/i);
  });

  it("describes approvals, errors, skipped and decision-less steps", () => {
    expect(describeObservation({ actual: "REQUIRE_APPROVAL (enforced) — not run", decision: "REQUIRE_APPROVAL" }).text).toMatch(/held for approval/i);
    expect(describeObservation({ actual: "pipeline error: ValueError", decision: null }).tone).toBe("danger");
    expect(describeObservation({ actual: "not run (an earlier step failed)", decision: null }).text).toMatch(/earlier step failed/);
    expect(describeObservation({ actual: "recorded", decision: null }).text).toMatch(/no tool decision/);
  });
});

describe("evidence and suites", () => {
  it("maps backend evidence kinds to app entity types", () => {
    expect(evidenceEntityType("context_source")).toBe("source");
    expect(evidenceEntityType("finding")).toBe("finding");
    expect(evidenceEntityType("ingested_events")).toBe("ingested_events");
  });

  it("computes the pass rate from persisted counts", () => {
    expect(passRate({ run_count: 9, passed_count: 6 })).toBe(67);
    expect(passRate({ run_count: 0, passed_count: 0 })).toBeNull();
  });

  const diff = (scenario_id: string, status: string): ScenarioDiff => ({
    scenario_id,
    scenario_name: scenario_id,
    status,
    base_run_id: "a",
    head_run_id: "b",
    base_passed: null,
    head_passed: null,
    check_changes: [],
    decision_changes: [],
    new_finding_categories: [],
    resolved_finding_categories: [],
  });

  it("orders regressions first, then fixes", () => {
    const sorted = sortDiffs([diff("z", "unchanged_pass"), diff("y", "fixed"), diff("b", "regressed"), diff("a", "regressed"), diff("x", "unchanged_fail")]);
    expect(sorted.map((d) => d.scenario_id)).toEqual(["a", "b", "y", "x", "z"]);
  });

  it("summarises comparison counts", () => {
    expect(compareCounts({ regressed: 2, fixed: 1, unchanged_pass: 3, unchanged_fail: 1, added: 1 })).toEqual({ regressed: 2, fixed: 1, unchanged: 4, other: 1 });
    expect(compareCounts({})).toEqual({ regressed: 0, fixed: 0, unchanged: 0, other: 0 });
  });

  it("defaults the comparison to the two newest suites", () => {
    const s = (id: string) => ({ suite_run_id: id }) as SuiteSummary;
    expect(defaultComparePair([s("new"), s("old"), s("older")])).toEqual({ base: "old", head: "new" });
    expect(defaultComparePair([s("only")])).toEqual({ base: null, head: "only" });
  });
});

describe("url state", () => {
  it("reads the tab and run filters", () => {
    expect(tabFrom(new URLSearchParams("tab=compare"))).toBe("compare");
    expect(tabFrom(new URLSearchParams("tab=bogus"))).toBe("scenarios");
    expect(runFiltersFrom(new URLSearchParams("scenario=s1&verdict=failed&suite=suite_1&agent=agt_1"))).toEqual({
      scenario_id: "s1",
      passed: false,
      suite_run_id: "suite_1",
      agent_id: "agt_1",
    });
    expect(runFiltersFrom(new URLSearchParams("verdict=passed"))).toEqual({ passed: true });
    expect(runFiltersFrom(new URLSearchParams("verdict=maybe"))).toEqual({});
  });

  it("applies updates without mutating the original", () => {
    const prev = new URLSearchParams("tab=history&run=r1");
    const next = applyParams(prev, { run: null, suite: "s1" });
    expect(next.toString()).toBe("tab=history&suite=s1");
    expect(prev.get("run")).toBe("r1");
  });
});
