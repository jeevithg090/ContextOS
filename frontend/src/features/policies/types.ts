/**
 * Policy Studio types. Mirrors backend/app/schemas/policies.py and the condition DSL documented in
 * backend/app/engines/policy/__init__.py.
 */
import type { Decision, Severity } from "@/lib/domain";

export type PolicyMode = "enforce" | "monitor";

/* ----------------------------------------------------------------------------- condition DSL */

export type ConditionOp =
  | "eq"
  | "neq"
  | "in"
  | "not_in"
  | "contains"
  | "not_contains"
  | "glob"
  | "any_glob"
  | "exists"
  | "empty"
  | "not_empty"
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "is_true"
  | "is_false";

export type JsonScalar = string | number | boolean;
export type ConditionValue = JsonScalar | JsonScalar[];

export interface LeafCondition {
  field: string;
  op: ConditionOp;
  value?: ConditionValue;
}

/** Wire format: {"all": [...]} | {"any": [...]} | {"not": cond} | {field, op, value}. */
export type Condition = LeafCondition | { all: Condition[] } | { any: Condition[] } | { not: Condition };

export type FieldType = "string" | "number" | "boolean" | "list" | "enum" | "any";

/** One entry of GET /policies/fields (backend FIELD_CATALOG). */
export interface FieldSpec {
  path: string;
  type: FieldType;
  description: string;
  example: unknown;
  values?: string[];
  ordered?: boolean;
  item_type?: "string" | "enum" | "object";
  ops: ConditionOp[];
}

/** One entry of GET /policies/operators (backend OPERATORS). */
export interface OperatorSpec {
  op: ConditionOp;
  label: string;
  value: "scalar" | "list" | "glob" | "none" | "comparable";
}

export interface Restrictions {
  redact_secrets?: boolean;
  allowed_path_globs?: string[];
  deny_path_globs?: string[];
  max_argument_bytes?: number;
}

/* ----------------------------------------------------------------------------- policies */

export interface PolicyMatchStats {
  window_days: number;
  /** Real (non-simulated) decisions where the policy matched in enforce mode. */
  matched: number;
  /** Real decisions where it matched in monitor mode (recorded only). */
  monitor_matched: number;
  /** Simulation Lab decisions where it matched (either mode). */
  simulated: number;
  last_matched_at: string | null;
  /** Real matches (both modes) per UTC day, oldest first. */
  daily: number[];
}

export interface Policy {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  mode: PolicyMode;
  priority: number;
  outcome: Decision;
  conditions: Condition | Record<string, never>;
  restrictions: Restrictions;
  severity: Severity;
  tags: string[];
  version: number;
  is_builtin: boolean;
  builtin_key: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  /** The conditions in plain English (server-generated). */
  explanation: string;
  stats: PolicyMatchStats | null;
}

export interface PolicyInput {
  name: string;
  description: string | null;
  outcome: Decision;
  mode: PolicyMode;
  enabled: boolean;
  priority: number;
  severity: Severity;
  conditions: Condition;
  restrictions: Restrictions;
  tags: string[];
}

export type PolicyPatch = Partial<PolicyInput>;

export interface PolicyFilters {
  enabled?: boolean;
  mode?: PolicyMode;
  outcome?: Decision;
  builtin?: boolean;
  q?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  explanation: string | null;
}

/* ----------------------------------------------------------------------------- recorded decisions */

export interface DecisionSummary {
  id: string;
  session_id: string;
  agent_id: string;
  agent_name: string | null;
  tool_name: string | null;
  tool_category: string | null;
  decision: Decision;
  enforcement: string;
  evaluated_at: string;
  explanation: string;
  is_simulation: boolean;
}

export interface PolicyDecisionMatch extends DecisionSummary {
  /** "enforce" = influenced the decision; "monitor" = recorded only. */
  match_mode: PolicyMode;
  matched_outcome: Decision;
  matched_version: number | null;
  match_explanation: string;
}

/* ----------------------------------------------------------------------------- dry-run tests */

export interface PolicyDraftForTest extends PolicyInput {
  /** The saved policy this draft would replace (so org-wide tests swap it in). */
  id?: string | null;
}

export interface PolicyTestRequest {
  policy?: PolicyDraftForTest;
  policy_ids?: string[];
  with_org_policies?: boolean;
  input?: Record<string, unknown>;
  policy_decision_id?: string;
}

export interface PolicyMatch {
  policy_id: string;
  name: string;
  version: number;
  outcome: Decision;
  mode: PolicyMode;
  severity: Severity;
  explanation: string;
}

export interface EvaluatedPolicy {
  id: string;
  name: string;
  version: number;
  outcome: Decision;
  mode: PolicyMode;
  draft: boolean;
  forced_enabled: boolean;
}

export interface RecordedDecision {
  id: string;
  session_id: string;
  agent_id: string;
  decision: Decision;
  enforcement: string;
  evaluated_at: string;
  explanation: string;
  matched_policy_names: string[];
  is_simulation: boolean;
}

export interface PolicyTestResult {
  simulation: true;
  label: string;
  decision: Decision;
  matched: PolicyMatch[];
  monitor_matches: PolicyMatch[];
  explanation: string;
  restrictions: Restrictions;
  deciding_policy_id: string | null;
  evaluation_errors: Array<{ policy_id: string; name: string; error: string }>;
  default_decision: Decision;
  evaluated_policies: EvaluatedPolicy[];
  source: "input" | "policy_decision";
  recorded: RecordedDecision | null;
  evaluated_input: Record<string, unknown>;
  warnings: string[];
}

/** Id the backend gives an unsaved draft in test results. */
export const DRAFT_POLICY_ID = "draft";
