/** Editor draft model: the form state of one policy and its conversion to API payloads. */
import type { Decision, Severity } from "@/lib/domain";
import type { Condition, Policy, PolicyDraftForTest, PolicyInput, PolicyMode, PolicyPatch, Restrictions } from "./types";

export interface PolicyDraft {
  name: string;
  description: string;
  outcome: Decision;
  mode: PolicyMode;
  enabled: boolean;
  priority: number;
  severity: Severity;
  /** Raw JSON value: may be invalid while the user edits; the server validates it. */
  conditions: unknown;
  restrictions: Restrictions;
  tags: string[];
}

export function emptyDraft(): PolicyDraft {
  return {
    name: "",
    description: "",
    outcome: "REQUIRE_APPROVAL",
    // New policies start in monitor mode so their impact can be measured before enforcing.
    mode: "monitor",
    enabled: true,
    priority: 100,
    severity: "medium",
    conditions: {},
    restrictions: {},
    tags: [],
  };
}

export function draftFromPolicy(policy: Policy): PolicyDraft {
  return {
    name: policy.name,
    description: policy.description ?? "",
    outcome: policy.outcome,
    mode: policy.mode,
    enabled: policy.enabled,
    priority: policy.priority,
    severity: policy.severity,
    conditions: policy.conditions,
    restrictions: policy.restrictions ?? {},
    tags: policy.tags ?? [],
  };
}

/** Restrictions only apply to RESTRICT; other outcomes must send none. */
export function effectiveRestrictions(draft: PolicyDraft): Restrictions {
  if (draft.outcome !== "RESTRICT") return {};
  const out: Restrictions = {};
  if (draft.restrictions.redact_secrets) out.redact_secrets = true;
  if (draft.restrictions.allowed_path_globs !== undefined) out.allowed_path_globs = draft.restrictions.allowed_path_globs;
  if (draft.restrictions.deny_path_globs?.length) out.deny_path_globs = draft.restrictions.deny_path_globs;
  if (draft.restrictions.max_argument_bytes !== undefined) out.max_argument_bytes = draft.restrictions.max_argument_bytes;
  return out;
}

export function draftToInput(draft: PolicyDraft): PolicyInput {
  return {
    name: draft.name.trim(),
    description: draft.description.trim() || null,
    outcome: draft.outcome,
    mode: draft.mode,
    enabled: draft.enabled,
    priority: draft.priority,
    severity: draft.severity,
    conditions: draft.conditions as Condition,
    restrictions: effectiveRestrictions(draft),
    tags: draft.tags,
  };
}

export function draftForTest(draft: PolicyDraft, policyId: string | null): PolicyDraftForTest {
  return { ...draftToInput(draft), name: draft.name.trim() || "Draft policy", id: policyId };
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** Only the fields that differ from the saved policy (PATCH payload). Empty = nothing to save. */
export function draftPatch(policy: Policy, draft: PolicyDraft): PolicyPatch {
  const next = draftToInput(draft);
  const saved = draftToInput(draftFromPolicy(policy));
  const patch: PolicyPatch = {};
  (Object.keys(next) as Array<keyof PolicyInput>).forEach((key) => {
    if (!same(next[key], saved[key])) (patch as Record<string, unknown>)[key] = next[key];
  });
  return patch;
}

export function isDirty(policy: Policy | null, draft: PolicyDraft): boolean {
  if (!policy) return !same(draft, emptyDraft());
  return Object.keys(draftPatch(policy, draft)).length > 0;
}

/** Fields whose change makes the server bump the policy version (mirrors EVALUATION_FIELDS). */
export const VERSIONED_FIELDS: ReadonlyArray<keyof PolicyInput> = ["conditions", "outcome", "mode", "enabled", "restrictions", "priority", "severity"];

/** True when a change would stop an enabled, enforce-mode DENY policy from blocking calls. */
export function stopsEnforcingDeny(
  policy: Pick<Policy, "outcome" | "mode" | "enabled">,
  next: Partial<Pick<PolicyInput, "outcome" | "mode" | "enabled">>,
): boolean {
  if (!(policy.outcome === "DENY" && policy.mode === "enforce" && policy.enabled)) return false;
  const outcome = next.outcome ?? policy.outcome;
  const mode = next.mode ?? policy.mode;
  const enabled = next.enabled ?? policy.enabled;
  return !(outcome === "DENY" && mode === "enforce" && enabled);
}
