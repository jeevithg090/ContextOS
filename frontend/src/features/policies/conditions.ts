/**
 * Visual condition builder model: converts the policy DSL (JSON) to an editable tree with stable
 * React keys and back. Pure functions only; the server remains the validator of record
 * (POST /policies/validate), so this module never decides whether a policy is valid.
 *
 * Tree shape: every group is ALL/ANY over children; NOT is a `negated` flag on any node, written
 * back as {"not": ...}. A root group with a single, non-negated child is written as that child so
 * simple policies keep their simple JSON.
 */
import type { Condition, ConditionOp, ConditionValue, FieldSpec, JsonScalar, OperatorSpec } from "./types";

export interface UiLeaf {
  kind: "leaf";
  key: string;
  negated: boolean;
  field: string;
  op: ConditionOp | "";
  value: ConditionValue | undefined;
}

export interface UiGroup {
  kind: "group";
  key: string;
  negated: boolean;
  combinator: "all" | "any";
  children: UiNode[];
}

export type UiNode = UiLeaf | UiGroup;

/** Matches backend MAX_DEPTH (engines/policy/conditions.py). */
export const MAX_DEPTH = 16;
export const VALUELESS_OPS: ReadonlySet<string> = new Set(["exists", "empty", "not_empty", "is_true", "is_false"]);
const LIST_OPS: ReadonlySet<string> = new Set(["in", "not_in"]);
const GLOB_OPS: ReadonlySet<string> = new Set(["glob", "any_glob"]);
export const ARGUMENT_FIELD = "arguments.*";

let counter = 0;
export const nextKey = () => `c${++counter}`;

export function emptyLeaf(): UiLeaf {
  return { kind: "leaf", key: nextKey(), negated: false, field: "", op: "", value: undefined };
}

export function emptyGroup(combinator: "all" | "any" = "all"): UiGroup {
  return { kind: "group", key: nextKey(), negated: false, combinator, children: [emptyLeaf()] };
}

/* ----------------------------------------------------------------------------- JSON -> tree */

export type ParseResult = { ok: true; tree: UiGroup } | { ok: false; reason: string };

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScalar(value: unknown): value is JsonScalar {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function parseNode(node: unknown, depth: number): UiNode | string {
  if (depth > MAX_DEPTH) return `nested deeper than ${MAX_DEPTH} levels`;
  if (!isObject(node)) return "a condition is not an object";
  const keys = Object.keys(node);
  if (keys.length === 1 && keys[0] === "not") {
    const inner = parseNode(node.not, depth + 1);
    if (typeof inner === "string") return inner;
    return { ...inner, negated: !inner.negated };
  }
  if (keys.length === 1 && (keys[0] === "all" || keys[0] === "any")) {
    const combinator = keys[0];
    const items = node[combinator];
    if (!Array.isArray(items) || items.length === 0) return `an empty "${combinator}" group`;
    const children: UiNode[] = [];
    for (const item of items) {
      const child = parseNode(item, depth + 1);
      if (typeof child === "string") return child;
      children.push(child);
    }
    return { kind: "group", key: nextKey(), negated: false, combinator, children };
  }
  if (keys.every((k) => k === "field" || k === "op" || k === "value") && "field" in node && "op" in node) {
    const { field, op, value } = node;
    if (typeof field !== "string" || typeof op !== "string") return "a condition with a non-text field or operator";
    if (value !== undefined && value !== null && !isScalar(value) && !(Array.isArray(value) && value.every(isScalar))) {
      return "a condition value that is not text, a number, a boolean or a list of those";
    }
    return { kind: "leaf", key: nextKey(), negated: false, field, op: op as ConditionOp, value: (value ?? undefined) as ConditionValue | undefined };
  }
  return `unrecognised keys ${keys.map((k) => `"${k}"`).join(", ")}`;
}

/** Parse stored/edited conditions into a builder tree. Empty conditions become one empty row. */
export function parseConditions(conditions: unknown): ParseResult {
  if (conditions === undefined || conditions === null || (isObject(conditions) && Object.keys(conditions).length === 0)) {
    return { ok: true, tree: emptyGroup() };
  }
  const node = parseNode(conditions, 0);
  if (typeof node === "string") return { ok: false, reason: node };
  if (node.kind === "group" && !node.negated) return { ok: true, tree: node };
  return { ok: true, tree: { kind: "group", key: nextKey(), negated: false, combinator: "all", children: [node] } };
}

/* ----------------------------------------------------------------------------- tree -> JSON */

function serializeNode(node: UiNode): Condition {
  let out: Condition;
  if (node.kind === "group") {
    const children = node.children.map(serializeNode);
    out = node.combinator === "all" ? { all: children } : { any: children };
  } else {
    const leaf: { field: string; op: ConditionOp; value?: ConditionValue } = { field: node.field, op: node.op as ConditionOp };
    if (!VALUELESS_OPS.has(node.op) && node.value !== undefined) leaf.value = node.value;
    out = leaf;
  }
  return node.negated ? { not: out } : out;
}

export function serializeConditions(tree: UiGroup): Condition {
  if (!tree.negated && tree.children.length === 1) return serializeNode(tree.children[0]);
  return serializeNode(tree);
}

/* ----------------------------------------------------------------------------- tree edits */

export function updateNode(root: UiGroup, key: string, fn: (node: UiNode) => UiNode | null): UiGroup {
  const visit = (node: UiNode): UiNode | null => {
    if (node.key === key) return fn(node);
    if (node.kind !== "group") return node;
    const children = node.children.map(visit).filter((c): c is UiNode => c !== null);
    return { ...node, children };
  };
  const next = visit(root);
  return next && next.kind === "group" ? next : { ...root, children: [emptyLeaf()] };
}

/* ----------------------------------------------------------------------------- field catalog */

export interface FieldRef {
  spec: FieldSpec | null;
  /** For arguments.*: the argument key after "arguments." (e.g. "command"). */
  argumentKey: string | null;
}

export function resolveField(path: string, catalog: FieldSpec[]): FieldRef {
  const exact = catalog.find((f) => f.path === path);
  if (exact) return { spec: exact, argumentKey: null };
  if (path.startsWith("arguments.") || path.startsWith("arguments[")) {
    const spec = catalog.find((f) => f.path === ARGUMENT_FIELD) ?? null;
    return { spec, argumentKey: path.replace(/^arguments\.?/, "") };
  }
  const canonical = path.replace(/\[\d+\]/g, "[*]");
  return { spec: catalog.find((f) => f.path === canonical) ?? null, argumentKey: null };
}

export type ValueKind = "none" | "scalar" | "list" | "glob";
export type ScalarKind = "enum" | "number" | "boolean" | "string" | "any";

export function valueKind(op: string): ValueKind {
  if (!op || VALUELESS_OPS.has(op)) return "none";
  if (LIST_OPS.has(op)) return "list";
  if (GLOB_OPS.has(op)) return "glob";
  return "scalar";
}

/** Type of a single comparison value for this field (list fields compare their items). */
export function scalarKind(spec: FieldSpec | null): ScalarKind {
  if (!spec) return "any";
  if (spec.type === "list") return spec.item_type === "enum" ? "enum" : "string";
  return spec.type;
}

export function opsFor(spec: FieldSpec | null, operators: OperatorSpec[]): OperatorSpec[] {
  if (!spec || spec.type === "any") return operators;
  return spec.ops.map((op) => operators.find((o) => o.op === op) ?? { op, label: op, value: "scalar" as const });
}

function defaultScalar(spec: FieldSpec | null): JsonScalar {
  const kind = scalarKind(spec);
  if (kind === "enum") return spec?.values?.[0] ?? "";
  if (kind === "number") return 0;
  if (kind === "boolean") return true;
  return "";
}

/** Carry a value across an operator change where it still makes sense, else a sensible default. */
export function coerceValue(value: ConditionValue | undefined, op: string, spec: FieldSpec | null): ConditionValue | undefined {
  const kind = valueKind(op);
  if (kind === "none") return undefined;
  const items = Array.isArray(value) ? value : value === undefined || value === "" ? [] : [value];
  if (kind === "list") return items;
  if (kind === "glob") return items.filter((v): v is string => typeof v === "string");
  return items[0] ?? defaultScalar(spec);
}

export function leafForField(leaf: UiLeaf, path: string, spec: FieldSpec | null, operators: OperatorSpec[]): UiLeaf {
  const ops = opsFor(spec, operators).map((o) => o.op);
  const op = leaf.op && ops.includes(leaf.op) ? leaf.op : (ops[0] ?? "eq");
  // Values rarely carry over between fields (different enums / types), so start fresh.
  return { ...leaf, field: path, op, value: coerceValue(undefined, op, spec) };
}

/** Group catalog entries by their root ("tool", "session"...) for the field picker. */
export function groupFields(catalog: FieldSpec[]): Array<{ root: string; fields: FieldSpec[] }> {
  const groups = new Map<string, FieldSpec[]>();
  for (const field of catalog) {
    const root = field.path.split(/[.[]/)[0];
    groups.set(root, [...(groups.get(root) ?? []), field]);
  }
  return Array.from(groups, ([root, fields]) => ({ root, fields }));
}

/** Parse number input text; empty or invalid text stays as text so the server can explain it. */
export function parseScalarInput(text: string, kind: ScalarKind): JsonScalar {
  if (kind === "number") {
    const n = Number(text);
    return text.trim() !== "" && Number.isFinite(n) ? n : text;
  }
  return text;
}
