import { describeActivity } from "../activityText";
import { cycleMembers, removeDraft, toggleDependency, toLines } from "../breakdownDrafts";
import { normalizeScenarios } from "../hooks";

const act = (kind: string, from: string | null, to: string | null, details: Record<string, unknown> = {}) => ({ kind, from_value: from, to_value: to, details });

describe("activity descriptions", () => {
  it("describes field changes with readable values, and long text without dumping it", () => {
    expect(describeActivity(act("updated", "medium", "urgent", { field: "priority" })).text).toBe("changed the priority from Medium to Urgent");
    expect(describeActivity(act("updated", "task", "prompt_injection", { field: "task_type" })).text).toBe("changed the type from Task to Prompt injection");
    expect(describeActivity(act("updated", "old text", "new text", { field: "description" })).text).toBe("edited the description");
    expect(describeActivity(act("updated", null, "high", { field: "severity" })).text).toBe("changed the severity from none to High");
  });

  it("flags WIP overrides and explains skipped automation", () => {
    const moved = describeActivity(act("moved", "To do", "Fixing", { wip_override: true }));
    expect(moved.text).toBe("moved the task from “To do” to “Fixing”");
    expect(moved.tone).toBe("warn");
    expect(moved.note).toMatch(/WIP limit was explicitly overridden/);
    const skipped = describeActivity(act("automation_skipped", "Review", null, { reason: "'Verified' requires passed verification." }));
    expect(skipped.note).toBe("'Verified' requires passed verification.");
  });

  it("never presents a claimed fix as verification", () => {
    const claim = describeActivity(act("fix_attempt_updated", "in_progress", "claimed_complete"));
    expect(claim.note).toBe("Claimed complete is a claim, not verification.");
    const pass = describeActivity(act("verification", "unverified", "passed", { kind: "test_run", run_status: "passed" }));
    expect(pass.text).toBe("recorded a verification run (test run) that passed");
    expect(pass.tone).toBe("ok");
    expect(describeActivity(act("verification_regressed", "passed", "failed")).tone).toBe("danger");
  });

  it("lists label and assignee changes and falls back for unknown kinds", () => {
    expect(describeActivity(act("labels_changed", null, null, { added: ["egress"], removed: [] })).text).toBe("added label “egress”");
    expect(describeActivity(act("labels_changed", null, null, { added: ["a", "b"], removed: ["c"] })).text).toBe("added labels “a”, “b” and removed label “c”");
    expect(describeActivity(act("assignees_changed", null, null, { added: ["Ada"], removed: ["Bo"] })).text).toBe("assigned Ada and unassigned Bo");
    expect(describeActivity(act("something_new", null, null)).text).toBe("something new");
  });
});

describe("breakdown draft editing", () => {
  const drafts = () => [{ depends_on: [] as number[] }, { depends_on: [0] }, { depends_on: [0, 1] }, { depends_on: [2] }];

  it("removes a draft and re-points the remaining dependencies", () => {
    expect(removeDraft(drafts(), 1).map((d) => d.depends_on)).toEqual([[], [0], [1]]);
    expect(removeDraft(drafts(), 0).map((d) => d.depends_on)).toEqual([[], [0], [1]]);
  });

  it("toggles dependencies and ignores self-dependencies", () => {
    expect(toggleDependency(drafts(), 3, 0)[3].depends_on).toEqual([0, 2]);
    expect(toggleDependency(drafts(), 2, 1)[2].depends_on).toEqual([0]);
    const same = drafts();
    expect(toggleDependency(same, 1, 1)).toBe(same);
  });

  it("finds dependency cycles (1-based draft numbers)", () => {
    expect(cycleMembers(drafts())).toEqual([]);
    expect(cycleMembers([{ depends_on: [2] }, { depends_on: [0] }, { depends_on: [1] }, { depends_on: [] }])).toEqual([1, 2, 3]);
  });

  it("splits text areas into one item per non-empty line", () => {
    expect(toLines(" a \n\n b\n")).toEqual(["a", "b"]);
  });
});

describe("simulation scenario catalogue", () => {
  it("accepts a list or a page and tolerates key/title naming", () => {
    expect(normalizeScenarios([{ id: "pi-01", name: "Indirect injection", description: "Fetched page tells the agent to exfiltrate", category: "prompt_injection" }])).toEqual([
      { id: "pi-01", name: "Indirect injection", description: "Fetched page tells the agent to exfiltrate", category: "prompt_injection" },
    ]);
    expect(normalizeScenarios({ items: [{ key: "exfil", title: "Paste-site exfiltration" }, { name: "no id" }, null] })).toEqual([
      { id: "exfil", name: "Paste-site exfiltration", description: null, category: null },
    ]);
    expect(normalizeScenarios("unexpected")).toEqual([]);
  });
});
