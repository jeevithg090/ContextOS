import { coerceValue, leafForField, parseConditions, resolveField, serializeConditions, updateNode, valueKind, type UiLeaf } from "../conditions";
import { draftFromPolicy, draftPatch, draftToInput, emptyDraft, stopsEnforcingDeny } from "../draft";
import type { FieldSpec, OperatorSpec, Policy } from "../types";

const CATALOG: FieldSpec[] = [
  { path: "tool.category", type: "enum", description: "Tool category", example: "http", values: ["shell", "http", "email"], ordered: false, ops: ["eq", "neq", "in", "not_in", "glob", "exists"] },
  { path: "session.trifecta", type: "boolean", description: "Trifecta", example: true, ops: ["is_true", "is_false", "eq", "neq", "exists"] },
  { path: "arguments.*", type: "any", description: "Any argument", example: "arguments.command", ops: [] },
  { path: "resources[*].sensitive", type: "boolean", description: "Sensitive resource", example: true, ops: ["is_true", "is_false", "eq", "neq", "exists"] },
];
const OPERATORS: OperatorSpec[] = [
  { op: "eq", label: "is", value: "scalar" },
  { op: "in", label: "is one of", value: "list" },
  { op: "is_true", label: "is true", value: "none" },
  { op: "glob", label: "matches glob", value: "glob" },
];

const BUILTIN_EXFIL = {
  all: [
    { any: [{ field: "secrets_in_arguments", op: "not_empty" }, { field: "session_secret_matches", op: "not_empty" }] },
    { any: [{ field: "destination.identifier", op: "exists" }, { field: "tool.category", op: "in", value: ["http", "email"] }] },
    { not: { field: "destination.classification", op: "in", value: ["TRUSTED", "APPROVED"] } },
  ],
};

describe("condition tree round trip", () => {
  it("preserves nested all/any/not structures exactly", () => {
    const parsed = parseConditions(BUILTIN_EXFIL);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(serializeConditions(parsed.tree)).toEqual(BUILTIN_EXFIL);
  });

  it("keeps a single leaf policy as a single leaf", () => {
    const leaf = { field: "detection.rule_ids", op: "any_glob", value: ["TOOL-DESTRUCTIVE-*"] };
    const parsed = parseConditions(leaf);
    expect(parsed.ok && serializeConditions(parsed.tree)).toEqual(leaf);
  });

  it("represents a negated group and writes it back as not", () => {
    const cond = { not: { any: [{ field: "tool.category", op: "eq", value: "shell" }, { field: "session.trifecta", op: "is_true" }] } };
    const parsed = parseConditions(cond);
    expect(parsed.ok && serializeConditions(parsed.tree)).toEqual(cond);
  });

  it("refuses shapes the builder cannot show instead of guessing", () => {
    expect(parseConditions({ all: [] })).toEqual({ ok: false, reason: 'an empty "all" group' });
    expect(parseConditions({ field: "tool.category", op: "eq", value: { nested: 1 } }).ok).toBe(false);
    expect(parseConditions({ foo: 1 }).ok).toBe(false);
  });

  it("starts empty conditions with one empty row", () => {
    const parsed = parseConditions({});
    expect(parsed.ok && parsed.tree.children).toHaveLength(1);
  });

  it("removes nodes by key", () => {
    const parsed = parseConditions(BUILTIN_EXFIL);
    if (!parsed.ok) throw new Error("parse failed");
    const firstKey = parsed.tree.children[0].key;
    const next = updateNode(parsed.tree, firstKey, () => null);
    expect(serializeConditions(next)).toEqual({ all: BUILTIN_EXFIL.all.slice(1) });
  });
});

describe("field and operator helpers", () => {
  it("resolves argument keys and indexed paths to catalog entries", () => {
    expect(resolveField("arguments.command", CATALOG)).toMatchObject({ spec: { path: "arguments.*" }, argumentKey: "command" });
    expect(resolveField("resources[0].sensitive", CATALOG).spec?.path).toBe("resources[*].sensitive");
    expect(resolveField("tool.categry", CATALOG).spec).toBeNull();
  });

  it("coerces values when the operator changes", () => {
    expect(valueKind("is_true")).toBe("none");
    expect(coerceValue("shell", "in", CATALOG[0])).toEqual(["shell"]);
    expect(coerceValue(["shell", "http"], "eq", CATALOG[0])).toBe("shell");
    expect(coerceValue(undefined, "eq", CATALOG[0])).toBe("shell");
    expect(coerceValue("x", "is_true", CATALOG[1])).toBeUndefined();
  });

  it("picks a valid operator for a new field", () => {
    const leaf: UiLeaf = { kind: "leaf", key: "k", negated: false, field: "tool.category", op: "in", value: ["http"] };
    const next = leafForField(leaf, "session.trifecta", CATALOG[1], OPERATORS);
    expect(next).toMatchObject({ field: "session.trifecta", op: "is_true", value: undefined });
  });
});

describe("draft payloads", () => {
  const policy: Policy = {
    id: "pol_1", name: "Block x", description: null, enabled: true, mode: "enforce", priority: 100, outcome: "DENY",
    conditions: { field: "tool.category", op: "eq", value: "shell" }, restrictions: {}, severity: "high", tags: [], version: 3,
    is_builtin: true, builtin_key: "builtin.x", created_by: null, created_at: "", updated_at: "", explanation: "", stats: null,
  };

  it("patches only changed fields and drops restrictions unless RESTRICT", () => {
    const draft = { ...draftFromPolicy(policy), name: "Block y", restrictions: { redact_secrets: true } };
    expect(draftPatch(policy, draft)).toEqual({ name: "Block y" });
    expect(draftToInput({ ...draft, outcome: "RESTRICT" }).restrictions).toEqual({ redact_secrets: true });
  });

  it("new drafts start in monitor mode", () => {
    expect(emptyDraft().mode).toBe("monitor");
  });

  it("flags changes that stop an enforced DENY", () => {
    expect(stopsEnforcingDeny(policy, { enabled: false })).toBe(true);
    expect(stopsEnforcingDeny(policy, { mode: "monitor" })).toBe(true);
    expect(stopsEnforcingDeny(policy, { priority: 5 } as never)).toBe(false);
    expect(stopsEnforcingDeny({ ...policy, outcome: "AUDIT" }, { enabled: false })).toBe(false);
  });
});
