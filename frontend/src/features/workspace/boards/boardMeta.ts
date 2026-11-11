/**
 * Board presentation helpers: column colour tokens, template names, card-field defaults and the
 * client-side board filters (the board detail already carries every card, so filtering is local).
 */
import { TONE_CLASSES, type Tone } from "@/lib/domain";
import {
  CARD_FIELDS,
  COLUMN_COLORS,
  type BoardConfig,
  type BoardTemplateKey,
  type CardField,
  type Column,
  type ColumnColor,
  type TaskCard,
  type TaskPriority,
  type TaskType,
} from "../types";

/** Column colour token → tone (the same mapping task labels use). */
export const COLUMN_COLOR_TONES: Record<ColumnColor, Tone> = {
  slate: "neutral",
  accent: "accent",
  trusted: "trusted",
  approved: "approved",
  external: "external",
  suspicious: "suspicious",
  blocked: "blocked",
  high: "high",
  medium: "medium",
  low: "low",
};

export const COLUMN_COLOR_LABELS: Record<ColumnColor, string> = {
  slate: "Slate",
  accent: "Indigo",
  trusted: "Green",
  approved: "Teal",
  external: "Sky",
  suspicious: "Amber",
  blocked: "Rose",
  high: "Orange",
  medium: "Yellow",
  low: "Blue",
};

const HEX = /^#[0-9a-f]{6}$/i;

export const isColumnColor = (value: string): value is ColumnColor => (COLUMN_COLORS as readonly string[]).includes(value);

/** Classes / inline style for a column's colour accent (token or "#rrggbb"). */
export function columnAccent(color: string): { dot: string; style?: { background: string } } {
  if (isColumnColor(color)) return { dot: TONE_CLASSES[COLUMN_COLOR_TONES[color]].dot };
  if (HEX.test(color)) return { dot: "", style: { background: color } };
  return { dot: TONE_CLASSES.neutral.dot };
}

export const TEMPLATE_LABELS: Record<BoardTemplateKey, string> = {
  software_development: "Software development",
  security_remediation: "Security remediation",
  incident_response: "Incident response",
  bug_tracking: "Bug tracking",
  feature_development: "Feature development",
  technical_debt: "Technical debt",
  research_experiments: "Research & experiments",
};

export const templateLabel = (key: string) => TEMPLATE_LABELS[key as BoardTemplateKey] ?? (key === "custom" ? "Custom" : key.replace(/_/g, " "));

export const CARD_FIELD_LABELS: Record<CardField, string> = {
  key: "Task key",
  type: "Type",
  priority: "Priority",
  severity: "Severity",
  labels: "Labels",
  assignees: "Assignees",
  due_date: "Due date",
  subtasks: "Subtask progress",
  verification: "Verification state",
  finding: "Linked finding",
};

/** Fields shown on cards: the board's configuration, or every field when it has never been set. */
export function cardFields(config: BoardConfig | undefined): Set<CardField> {
  const chosen = config?.card_fields;
  return new Set(Array.isArray(chosen) ? chosen : CARD_FIELDS);
}

/** Task types whose cards show the severity of the underlying security problem. */
export const SECURITY_TASK_TYPES: ReadonlySet<TaskType> = new Set<TaskType>([
  "security_vulnerability",
  "prompt_injection",
  "agent_misconfiguration",
  "data_exposure",
]);

// ---------------------------------------------------------------------------- filters

export interface BoardFilterState {
  q: string;
  /** User id, "me", "none" (unassigned) or "" (anyone). */
  assignee: string;
  /** Label id or "". */
  label: string;
  priority: TaskPriority | "";
  type: TaskType | "";
}

export const EMPTY_FILTERS: BoardFilterState = { q: "", assignee: "", label: "", priority: "", type: "" };

export function hasActiveFilters(f: BoardFilterState): boolean {
  return Boolean(f.q.trim() || f.assignee || f.label || f.priority || f.type);
}

/** Whether a card matches the board filters. `meId` resolves the "me" assignee filter. */
export function matchesFilters(card: TaskCard, f: BoardFilterState, meId: string | null | undefined): boolean {
  const q = f.q.trim().toLowerCase();
  if (q && !card.title.toLowerCase().includes(q) && !card.key.toLowerCase().includes(q)) return false;
  if (f.priority && card.priority !== f.priority) return false;
  if (f.type && card.task_type !== f.type) return false;
  if (f.label && !card.labels.some((l) => l.id === f.label)) return false;
  if (f.assignee) {
    const people = card.assignees.filter((a) => a.role === "assignee");
    if (f.assignee === "none") return people.length === 0;
    const target = f.assignee === "me" ? meId : f.assignee;
    if (!target || !people.some((a) => a.user_id === target)) return false;
  }
  return true;
}

/**
 * Column id → name of the column whose verification gate applies on entry (mirrors the server's
 * `verification_gate`: the column itself when it requires verification, or for a done column the
 * first earlier column that does). The server remains the authority; this only drives hints.
 */
export function verificationGates(columns: Array<Pick<Column, "id" | "name" | "position" | "requires_verification" | "is_done_column">>): Record<string, string | null> {
  const ordered = [...columns].sort((a, b) => a.position - b.position);
  const gates: Record<string, string | null> = {};
  let firstGate: string | null = null;
  for (const column of ordered) {
    if (column.requires_verification) gates[column.id] = column.name;
    else gates[column.id] = column.is_done_column ? firstGate : null;
    if (column.requires_verification && firstGate === null) firstGate = column.name;
  }
  return gates;
}
