/**
 * URL <-> filter state for the Context Explorer, so every view is linkable and the back button works.
 *
 *   view=items|sources  q  trust=<level> (repeatable)  sensitivity=<s> (repeatable)  type=<source type>
 *   detections=yes|no  secrets=yes  since=1h|24h|7d|30d  sim=1  agent=<id>  session=<id>  source=<id>
 *   Sources view: strust=<level>  findings=yes|no  sort=last_seen|items|findings
 *   Drawers: item=<context item id>  src=<source id>
 */
import type { ItemFilters, SourceFilters, SourceSort } from "./types";

export type ExplorerView = "items" | "sources";

export const SINCE_PRESETS: Record<string, { label: string; ms: number }> = {
  "1h": { label: "Last hour", ms: 3_600_000 },
  "24h": { label: "Last 24 hours", ms: 86_400_000 },
  "7d": { label: "Last 7 days", ms: 7 * 86_400_000 },
  "30d": { label: "Last 30 days", ms: 30 * 86_400_000 },
};

/** Start of the preset window, rounded down to the minute so the query key is stable while typing. */
export function sinceIso(preset: string | null, now: number = Date.now()): string | undefined {
  const p = preset ? SINCE_PRESETS[preset] : undefined;
  if (!p) return undefined;
  const start = Math.floor((now - p.ms) / 60_000) * 60_000;
  return new Date(start).toISOString();
}

function yesNo(value: string | null): boolean | undefined {
  if (value === "yes") return true;
  if (value === "no") return false;
  return undefined;
}

export function readView(params: URLSearchParams): ExplorerView {
  return params.get("view") === "sources" ? "sources" : "items";
}

export function itemFiltersFrom(params: URLSearchParams, now?: number): ItemFilters {
  const trust = params.getAll("trust").filter(Boolean);
  const sensitivity = params.getAll("sensitivity").filter(Boolean);
  const filters: ItemFilters = {
    q: params.get("q") || undefined,
    source_id: params.get("source") || undefined,
    source_type: params.get("type") || undefined,
    agent_id: params.get("agent") || undefined,
    session_id: params.get("session") || undefined,
    trust_level: trust.length ? trust : undefined,
    sensitivity: sensitivity.length ? sensitivity : undefined,
    has_detections: yesNo(params.get("detections")),
    contains_secrets: params.get("secrets") === "yes" ? true : undefined,
    since: sinceIso(params.get("since"), now),
    include_simulated: params.get("sim") === "1" ? true : undefined,
  };
  return Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined)) as ItemFilters;
}

const SORTS: SourceSort[] = ["last_seen", "items", "findings"];

export function sourceFiltersFrom(params: URLSearchParams): SourceFilters {
  const sort = params.get("sort") as SourceSort | null;
  const filters: SourceFilters = {
    q: params.get("q") || undefined,
    source_type: params.get("type") || undefined,
    trust_level: params.get("strust") || undefined,
    has_findings: yesNo(params.get("findings")),
    include_simulated: params.get("sim") === "1" ? true : undefined,
    sort: sort && SORTS.includes(sort) ? sort : undefined,
  };
  return Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined)) as SourceFilters;
}

/** URL keys that narrow the current view (drawer, view and paging keys are not filters). */
const ITEM_FILTER_KEYS = ["q", "trust", "sensitivity", "type", "detections", "secrets", "since", "agent", "session", "source"];
const SOURCE_FILTER_KEYS = ["q", "type", "strust", "findings"];

export function hasActiveFilters(params: URLSearchParams, view: ExplorerView): boolean {
  return (view === "items" ? ITEM_FILTER_KEYS : SOURCE_FILTER_KEYS).some((k) => params.getAll(k).some(Boolean));
}

/** Clears filters for the view but keeps the view itself, the simulation toggle and open drawers. */
export function clearedParams(params: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams();
  for (const key of ["view", "sim", "item", "src", "sort"]) {
    const value = params.get(key);
    if (value) next.set(key, value);
  }
  return next;
}

/** Toggle one value of a repeatable key (e.g. a trust chip). */
export function toggleValue(params: URLSearchParams, key: string, value: string): URLSearchParams {
  const next = new URLSearchParams(params);
  const values = next.getAll(key);
  next.delete(key);
  const updated = values.includes(value) ? values.filter((v) => v !== value) : [...values, value];
  updated.forEach((v) => next.append(key, v));
  return next;
}
