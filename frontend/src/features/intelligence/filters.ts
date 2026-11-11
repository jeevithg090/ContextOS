/**
 * URL-backed filter state for the findings list, so every view is linkable and survives reloads.
 *
 *   ?status=open&status=acknowledged   repeated; absent = the active default; status=all = every status
 *   ?severity=critical&severity=high   repeated
 *   ?category=<cat>  ?agent=<id>  ?session=<id>  ?source=<id>  ?incident=<id>
 *   ?q=<text>  ?sim=1 (include simulated)  ?sort=severity|recent|first_seen|occurrences  ?window=7d
 */
import { ACTIVE_STATUSES, SORT_OPTIONS, STATUS_OPTIONS, WINDOWS } from "./meta";
import type { FindingFilters, StatsWindow } from "./types";

export const SCOPE_KEYS = ["session", "source", "incident"] as const;
const FILTER_KEYS = ["status", "severity", "category", "agent", "q", "sort", ...SCOPE_KEYS];

export function selectedStatuses(params: URLSearchParams): string[] {
  const values = params.getAll("status");
  if (values.length === 0) return [...ACTIVE_STATUSES];
  if (values.includes("all")) return [];
  return values;
}

export function windowFrom(params: URLSearchParams): StatsWindow {
  const value = params.get("window");
  return (WINDOWS.find((w) => w.value === value)?.value ?? "7d") as StatsWindow;
}

export function includeSimulated(params: URLSearchParams): boolean {
  return params.get("sim") === "1";
}

export function findingFiltersFrom(params: URLSearchParams): FindingFilters {
  const statuses = selectedStatuses(params);
  const severity = params.getAll("severity");
  const sort = SORT_OPTIONS.find((o) => o.value === params.get("sort"))?.value;
  const filters: FindingFilters = {
    status: statuses.length ? statuses : undefined,
    severity: severity.length ? severity : undefined,
    category: params.get("category") ? [params.get("category") as string] : undefined,
    agent_id: params.get("agent") || undefined,
    session_id: params.get("session") || undefined,
    source_id: params.get("source") || undefined,
    incident_id: params.get("incident") || undefined,
    q: params.get("q")?.trim() || undefined,
    include_simulated: includeSimulated(params) || undefined,
    sort: sort && sort !== "severity" ? sort : undefined,
  };
  return Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined)) as FindingFilters;
}

/** True when anything differs from the default view (active statuses, every severity, no scope). */
export function hasActiveFilters(params: URLSearchParams): boolean {
  return FILTER_KEYS.some((key) => key !== "sort" && params.has(key));
}

export function clearedParams(params: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams(params);
  FILTER_KEYS.forEach((key) => next.delete(key));
  return next;
}

/** Set the status selection; the active default is stored as "no parameter". */
export function withStatuses(params: URLSearchParams, statuses: string[]): URLSearchParams {
  const next = new URLSearchParams(params);
  next.delete("status");
  const isDefault = statuses.length === ACTIVE_STATUSES.length && ACTIVE_STATUSES.every((s) => statuses.includes(s));
  if (isDefault) return next;
  // Deselecting every chip means "no status filter" rather than an always-empty list.
  if (statuses.length === 0 || statuses.length >= STATUS_OPTIONS.length) next.append("status", "all");
  else statuses.forEach((s) => next.append("status", s));
  return next;
}

export function toggleStatus(params: URLSearchParams, status: string): URLSearchParams {
  const current = selectedStatuses(params);
  // "Every status" is shown as all chips selected, so toggling one off leaves the others.
  const base = current.length === 0 ? STATUS_OPTIONS.map((o) => o.value) : current;
  const next = base.includes(status) ? base.filter((s) => s !== status) : [...base, status];
  return withStatuses(params, next);
}

export function toggleValue(params: URLSearchParams, key: string, value: string): URLSearchParams {
  const next = new URLSearchParams(params);
  const values = next.getAll(key);
  next.delete(key);
  const updated = values.includes(value) ? values.filter((v) => v !== value) : [...values, value];
  updated.forEach((v) => next.append(key, v));
  return next;
}

export function setParam(params: URLSearchParams, key: string, value: string | null): URLSearchParams {
  const next = new URLSearchParams(params);
  if (value) next.set(key, value);
  else next.delete(key);
  return next;
}
