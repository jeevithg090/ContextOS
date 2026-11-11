import { capabilityAllowed, capabilityProblems, defaultCapabilities, reassessMessage } from "../meta";
import { draftFromRule, draftProblems, draftToInput, emptyDraft, parsePriority, withLevel, withScope } from "../ruleDraft";
import type { TrustRule } from "../types";

const RULE: TrustRule = {
  id: "trl_1",
  name: "Acme wiki",
  description: null,
  applies_to: "source",
  source_type: "web",
  match_field: "domain",
  pattern: "*.acme.dev",
  trust_level: "TRUSTED",
  capabilities: ["read", "instruct", "execute"],
  priority: 120,
  enabled: true,
  created_by: null,
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z",
  is_default: false,
  is_override: false,
  classified_sources: 2,
  classified_destinations: 0,
  reassessment: null,
};

describe("capability rules mirror the backend", () => {
  it("defaults follow the level and scope", () => {
    expect(defaultCapabilities("TRUSTED", "source")).toEqual(["read", "instruct", "execute"]);
    expect(defaultCapabilities("APPROVED", "source")).toEqual(["read"]);
    expect(defaultCapabilities("APPROVED", "destination")).toEqual(["send"]);
    expect(defaultCapabilities("TRUSTED", "both")).toEqual(["read", "instruct", "execute", "send"]);
    expect(defaultCapabilities("BLOCKED", "both")).toEqual([]);
    expect(defaultCapabilities("SUSPICIOUS", "destination")).toEqual([]);
  });

  it("data-only levels can never instruct, and BLOCKED grants nothing", () => {
    expect(capabilityAllowed("EXTERNAL", "read")).toBe(true);
    expect(capabilityAllowed("EXTERNAL", "instruct")).toBe(false);
    expect(capabilityAllowed("UNKNOWN", "send")).toBe(false);
    expect(capabilityAllowed("BLOCKED", "read")).toBe(false);
    expect(capabilityAllowed("APPROVED", "instruct")).toBe(true);
    expect(capabilityProblems("EXTERNAL", "source", ["read", "execute"])).toEqual([
      "EXTERNAL content is always treated as data, so only 'read' can be granted.",
    ]);
    expect(capabilityProblems("TRUSTED", "source", ["send"])).toEqual(["'send' applies to destinations only."]);
  });
});

describe("rule drafts", () => {
  it("round-trips a saved rule and drops capabilities the level cannot grant", () => {
    const draft = draftFromRule(RULE);
    expect(draftToInput(draft)).toMatchObject({ name: "Acme wiki", source_type: "web", priority: 120, capabilities: ["read", "instruct", "execute"] });
    expect(draftToInput({ ...draft, trust_level: "EXTERNAL" }).capabilities).toEqual(["read"]);
  });

  it("re-derives capabilities when the level or scope changes and clears the source type for destinations", () => {
    const lowered = withLevel(draftFromRule(RULE), "APPROVED");
    expect(lowered.capabilities).toEqual(["read"]);
    const dest = withScope(draftFromRule(RULE), "destination");
    expect(dest.source_type).toBe("");
    expect(dest.capabilities).toEqual(["send"]);
    expect(draftToInput(dest).source_type).toBeNull();
  });

  it("reports fixable problems before saving", () => {
    expect(draftProblems(emptyDraft())).toEqual(["Give the rule a name.", "Enter a pattern."]);
    const bad = { ...emptyDraft(), name: "x", pattern: "docs.acme.com/guide", priority: "-1" };
    expect(draftProblems(bad)).toHaveLength(2);
    expect(parsePriority("100000")).toBe(100000);
    expect(parsePriority("100001")).toBeNull();
    expect(parsePriority("1.5")).toBeNull();
  });
});

describe("reassessMessage", () => {
  it("summarises what a rule change reclassified and says when it was bounded", () => {
    expect(reassessMessage({ sources_checked: 10, sources_changed: 1, destinations_checked: 0, destinations_changed: 0, truncated: false, limit: 5000 })).toBe(
      "1 source reclassified of 10 checked.",
    );
    expect(reassessMessage({ sources_checked: 0, sources_changed: 0, destinations_checked: 0, destinations_changed: 0, truncated: false, limit: 5000 })).toBe(
      "No stored sources or destinations were affected.",
    );
    expect(reassessMessage({ sources_checked: 5000, sources_changed: 2, destinations_checked: 3, destinations_changed: 0, truncated: true, limit: 5000 })).toContain(
      "Only the 5000 most recently seen",
    );
  });
});
