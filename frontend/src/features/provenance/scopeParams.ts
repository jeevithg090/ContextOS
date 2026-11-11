/**
 * URL <-> graph query mapping for the provenance page. Other pages link here with ?session=, ?agent=,
 * ?item= or ?finding= (plus ?depth= and ?limit=); the API field names (?session_id=, ?agent_id=,
 * ?context_item_id=, ?finding_id=) are accepted as aliases so links built from API payloads work too.
 */
import type { GraphQuery } from "./types";

/** URL parameter → graph query field. The first parameter present wins (the API allows one scope). */
export const SCOPE_PARAMS = [
  { param: "session", alias: "session_id", field: "session_id" },
  { param: "agent", alias: "agent_id", field: "agent_id" },
  { param: "item", alias: "context_item_id", field: "context_item_id" },
  { param: "finding", alias: "finding_id", field: "finding_id" },
] as const;
export type ScopeParam = (typeof SCOPE_PARAMS)[number]["param"];

/** Node budgets offered when a graph is truncated (the API accepts 20–1000). */
export const NODE_LIMITS = [200, 400, 1000];
export const DEFAULT_DEPTH = 2;

export function queryFromParams(params: URLSearchParams): GraphQuery {
  const depth = Number(params.get("depth"));
  const limit = Number(params.get("limit"));
  const query: GraphQuery = {};
  for (const { param, alias, field } of SCOPE_PARAMS) {
    const value = (params.get(param) || params.get(alias) || "").trim();
    if (value) {
      query[field] = value;
      break;
    }
  }
  if ((query.context_item_id || query.finding_id) && Number.isInteger(depth) && depth >= 1 && depth <= 4) query.depth = depth;
  if (NODE_LIMITS.includes(limit)) query.limit = limit;
  return query;
}

/** New search params with the scope replaced (or cleared when `id` is null). Hop depth resets with
 * the scope; unrelated parameters (such as the node budget) are kept. */
export function withScope(params: URLSearchParams, param: ScopeParam | null, id: string | null): URLSearchParams {
  const next = new URLSearchParams(params);
  for (const spec of SCOPE_PARAMS) {
    next.delete(spec.param);
    next.delete(spec.alias);
  }
  next.delete("depth");
  if (param && id) next.set(param, id);
  return next;
}
