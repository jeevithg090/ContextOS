/**
 * Provenance data hooks. Backend contract: backend/app/api/routes/provenance.py (prefix /provenance).
 *   GET /provenance/graph?session_id|agent_id|context_item_id|finding_id&depth&limit -> ProvenanceGraph
 *   GET /provenance/scopes?q&limit                                                   -> ScopeOptions (sessions, agents, findings)
 *   GET /provenance/nodes/{type}/{ref_id}                                           -> NodeDetail
 * Query keys start with "provenance" so the event.ingested live notification refreshes them.
 */
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { GraphQuery, NodeDetail, ProvenanceGraph, ScopeOptions } from "./types";

export const provenanceKeys = {
  all: ["provenance"] as const,
  graph: (query: GraphQuery) => ["provenance", "graph", query] as const,
  node: (type: string, refId: string) => ["provenance", "node", type, refId] as const,
  scopes: (q: string) => ["provenance", "scopes", q] as const,
};

const notFound = (err: unknown) => err instanceof ApiError && (err.status === 404 || err.status === 422);

export function useProvenanceGraph(query: GraphQuery) {
  return useQuery({
    queryKey: provenanceKeys.graph(query),
    queryFn: () => api.get<ProvenanceGraph>("/provenance/graph", { ...query }),
    retry: (count, err) => !notFound(err) && count < 2,
    staleTime: 15_000,
  });
}

export function useProvenanceNode(type: string | null, refId: string | null) {
  return useQuery({
    queryKey: provenanceKeys.node(type ?? "", refId ?? ""),
    queryFn: () => api.get<NodeDetail>(`/provenance/nodes/${encodeURIComponent(type ?? "")}/${encodeURIComponent(refId ?? "")}`),
    enabled: !!type && !!refId,
    retry: (count, err) => !notFound(err) && count < 2,
  });
}

export function useProvenanceScopes(q: string, enabled = true) {
  return useQuery({
    queryKey: provenanceKeys.scopes(q),
    queryFn: () => api.get<ScopeOptions>("/provenance/scopes", { q: q || undefined, limit: 25 }),
    enabled,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
}
