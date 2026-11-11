/**
 * Hypothetical policy-set state for the Counterfactual tab, and its conversion to the
 * POST /replay/counterfactual body. Pure so it can be unit tested.
 */
import { DECISIONS, type Decision } from "@/lib/domain";
import type { DefaultDecision, DraftPolicy, PolicyBase, PolicyMode, PolicyOverride, ReplayPolicy, CounterfactualRequest } from "./types";

export interface PolicySetState {
  base: PolicyBase;
  /** Saved policies switched off for this simulation. */
  disabled: string[];
  /** Saved policies whose outcome/mode (or enabled state, for disabled ones) is changed. */
  overrides: Record<string, PolicyOverride>;
  drafts: DraftPolicy[];
  /** null = the organisation's configured default. */
  defaultDecision: DefaultDecision | null;
}

export const EMPTY_POLICY_SET: PolicySetState = { base: "current", disabled: [], overrides: {}, drafts: [], defaultDecision: null };

/** Effective enabled state of a saved policy under the hypothetical set. */
export function isEnabled(state: PolicySetState, policy: ReplayPolicy): boolean {
  if (state.disabled.includes(policy.id)) return false;
  return state.overrides[policy.id]?.enabled ?? policy.enabled;
}

/** Turn a saved policy on/off. Enabling a policy saved as disabled is expressed as an override. */
export function setEnabled(state: PolicySetState, policy: ReplayPolicy, enabled: boolean): PolicySetState {
  const disabled = state.disabled.filter((id) => id !== policy.id);
  const overrides = { ...state.overrides };
  const current = { ...(overrides[policy.id] ?? {}) };
  delete current.enabled;
  if (enabled === policy.enabled) {
    // Back to its saved state; keep any outcome/mode override.
  } else if (!enabled && !current.outcome && !current.mode) {
    disabled.push(policy.id);
  } else {
    current.enabled = enabled;
  }
  if (Object.keys(current).length) overrides[policy.id] = current;
  else delete overrides[policy.id];
  return { ...state, disabled, overrides };
}

/** Override a saved policy's outcome or mode; passing its saved value clears the override. */
export function setOverride(state: PolicySetState, policy: ReplayPolicy, patch: { outcome?: Decision; mode?: PolicyMode }): PolicySetState {
  const current: PolicyOverride = { ...(state.overrides[policy.id] ?? {}) };
  if (patch.outcome !== undefined) {
    if (patch.outcome === policy.outcome) delete current.outcome;
    else current.outcome = patch.outcome;
  }
  if (patch.mode !== undefined) {
    if (patch.mode === policy.mode) delete current.mode;
    else current.mode = patch.mode;
  }
  let disabled = state.disabled;
  if ((current.outcome || current.mode) && disabled.includes(policy.id)) {
    // The API rejects a policy that is both disabled and overridden: carry the disable into the override.
    disabled = disabled.filter((id) => id !== policy.id);
    current.enabled = false;
  }
  const overrides = { ...state.overrides };
  if (Object.keys(current).length) overrides[policy.id] = current;
  else delete overrides[policy.id];
  return { ...state, disabled, overrides };
}

export function changeCount(state: PolicySetState): number {
  const base = state.base === "current" ? state.disabled.length + Object.keys(state.overrides).length : 0;
  return base + state.drafts.length + (state.defaultDecision ? 1 : 0) + (state.base === "none" ? 1 : 0);
}

export function toRequest(sessionId: string, state: PolicySetState): CounterfactualRequest {
  const current = state.base === "current";
  return {
    session_id: sessionId,
    policy_set: {
      base: state.base,
      disable_policy_ids: current ? state.disabled : [],
      overrides: current ? state.overrides : {},
      add_policies: state.drafts,
    },
    ...(state.defaultDecision ? { default_decision: state.defaultDecision } : {}),
  };
}

/** Client-side shape check of draft JSON before server validation. Returns [draft, errors]. */
export function parseDraft(text: string): [DraftPolicy | null, string[]] {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (e) {
    return [null, [`Not valid JSON: ${e instanceof Error ? e.message : "parse error"}`]];
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return [null, ["The draft must be a JSON object."]];
  const obj = value as Record<string, unknown>;
  const errors: string[] = [];
  if (typeof obj.name !== "string" || !obj.name.trim()) errors.push('"name" is required (a short label).');
  if (typeof obj.outcome !== "string" || !(DECISIONS as readonly string[]).includes(obj.outcome.toUpperCase())) {
    errors.push(`"outcome" must be one of ${DECISIONS.join(", ")}.`);
  }
  if (!obj.conditions || typeof obj.conditions !== "object" || Array.isArray(obj.conditions)) errors.push('"conditions" must be a condition object.');
  if (obj.mode !== undefined && obj.mode !== "enforce" && obj.mode !== "monitor") errors.push('"mode" must be "enforce" or "monitor".');
  if (errors.length) return [null, errors];
  return [{ ...(obj as unknown as DraftPolicy), outcome: String(obj.outcome).toUpperCase() as Decision }, []];
}

export const DRAFT_TEMPLATE = JSON.stringify(
  {
    name: "Require approval for outbound calls with secrets",
    outcome: "REQUIRE_APPROVAL",
    mode: "enforce",
    priority: 500,
    severity: "high",
    conditions: {
      all: [
        { field: "tool.category", op: "in", value: ["http", "email", "messaging"] },
        { field: "secrets_in_arguments", op: "not_empty" },
      ],
    },
  },
  null,
  2,
);
