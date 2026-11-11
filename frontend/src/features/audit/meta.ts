/** Presentation helpers for audit entries: where a target lives in the app and how actors read. */
import { isEntityType, type EntityType } from "@/components/data";
import type { AuditEntry } from "./types";

/** Action families written by the server (prefix filters). Free text is accepted too. */
export const ACTION_FAMILIES: Array<{ value: string; label: string }> = [
  { value: "auth.", label: "Sign-in and sign-out" },
  { value: "member.", label: "Members" },
  { value: "api_key.", label: "API keys" },
  { value: "organization.", label: "Organisation settings" },
  { value: "policy.", label: "Policies" },
  { value: "trust.", label: "Trust classifications" },
  { value: "trust_rule.", label: "Trust rules" },
  { value: "tool.", label: "Denied and held tool calls" },
  { value: "approval.", label: "Approvals" },
  { value: "finding.", label: "Findings" },
  { value: "incident.", label: "Incidents" },
  { value: "agent.", label: "Agents" },
  { value: "ingest.", label: "Ingestion problems" },
  { value: "audit.", label: "Audit exports" },
];

export const TIME_WINDOWS: Array<{ value: string; label: string; ms: number }> = [
  { value: "1h", label: "Last hour", ms: 3_600_000 },
  { value: "24h", label: "Last 24 hours", ms: 86_400_000 },
  { value: "7d", label: "Last 7 days", ms: 7 * 86_400_000 },
  { value: "30d", label: "Last 30 days", ms: 30 * 86_400_000 },
];

export const ACTOR_TYPE_LABELS: Record<string, string> = { user: "User", api_key: "API key", system: "System" };

/** Audit target types whose names differ from the app's entity vocabulary. */
const TARGET_ALIASES: Record<string, EntityType> = {
  context_source: "source",
  trust_destination: "destination",
  ingested_event: "event",
};

/** In-app pages for targets that are not entities with their own detail route. */
const SETTINGS_TARGETS: Record<string, { label: string; href: (id: string) => string }> = {
  api_key: { label: "API key", href: () => "/settings?tab=api-keys" },
  membership: { label: "Membership", href: () => "/settings?tab=members" },
  user: { label: "User", href: () => "/settings?tab=members" },
  organization: { label: "Organisation", href: () => "/settings" },
  trust_rule: { label: "Trust rule", href: (id) => `/trust?tab=rules&rule=${encodeURIComponent(id)}` },
  board: { label: "Board", href: (id) => `/work/boards/${encodeURIComponent(id)}` },
};

export type AuditTargetRef =
  | { kind: "entity"; type: EntityType; id: string; sessionId: string | null; label: string | null }
  | { kind: "page"; label: string; href: string; id: string }
  | { kind: "plain"; type: string; id: string };

function str(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

/** How to render an entry's target: an EntityLink, a link to a settings page, or plain text. */
export function auditTarget(entry: Pick<AuditEntry, "target_type" | "target_id" | "details">): AuditTargetRef | null {
  const { target_type: type, target_id: id, details } = entry;
  if (!type || !id) return null;
  const entityType = TARGET_ALIASES[type] ?? type;
  if (isEntityType(entityType)) {
    return { kind: "entity", type: entityType, id, sessionId: str(details?.session_id), label: str(details?.name) };
  }
  const page = SETTINGS_TARGETS[type];
  if (page) return { kind: "page", label: str(details?.name) ?? page.label, href: page.href(id), id };
  return { kind: "plain", type, id };
}

export function actorTypeLabel(type: string): string {
  return ACTOR_TYPE_LABELS[type] ?? type;
}
