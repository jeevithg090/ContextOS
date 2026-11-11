/**
 * Context Explorer data hooks. Backend contract: backend/app/api/routes/context.py (prefix /context).
 *   GET /context/items                  -> Page<ContextItemSummary> (read; ItemFilters, newest first)
 *   GET /context/facets                 -> ContextFacets (same filters; each facet ignores its own filter)
 *   GET /context/items/{id}             -> ContextItemDetail
 *   GET /context/items/{id}/receipt     -> ContextReceipt (?events_limit, signature re-verified on read)
 *   GET /context/sources                -> Page<ContextSourceSummary> (SourceFilters)
 *   GET /context/sources/{id}           -> ContextSourceDetail (?include_simulated)
 * Query keys start with "context" so event.ingested / trust.updated live events refresh them.
 */
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api, ApiError, type Page } from "@/lib/api";
import type {
  ContextFacets,
  ContextItemDetail,
  ContextItemSummary,
  ContextReceipt,
  ContextSourceDetail,
  ContextSourceSummary,
  ItemFilters,
  SourceFilters,
} from "./types";

const enc = encodeURIComponent;

export const contextKeys = {
  all: ["context"] as const,
  items: (filters: ItemFilters, limit: number, offset: number) => ["context", "items", filters, limit, offset] as const,
  facets: (filters: ItemFilters) => ["context", "facets", filters] as const,
  item: (id: string) => ["context", "item", id] as const,
  receipt: (id: string, eventsLimit: number) => ["context", "receipt", id, eventsLimit] as const,
  sources: (filters: SourceFilters, limit: number, offset: number) => ["context", "sources", filters, limit, offset] as const,
  source: (id: string, includeSimulated: boolean) => ["context", "source", id, includeSimulated] as const,
};

/** Do not retry "not found": it is a definitive answer (deleted, or another organisation's id). */
const retryUnlessMissing = (count: number, err: unknown) => !(err instanceof ApiError && (err.status === 404 || err.status === 403)) && count < 2;

export function isNotFound(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

export function useContextItems(filters: ItemFilters, limit: number, offset: number) {
  return useQuery({
    queryKey: contextKeys.items(filters, limit, offset),
    queryFn: () => api.get<Page<ContextItemSummary>>("/context/items", { ...filters, limit, offset }),
    placeholderData: keepPreviousData,
  });
}

export function useContextFacets(filters: ItemFilters) {
  return useQuery({
    queryKey: contextKeys.facets(filters),
    queryFn: () => api.get<ContextFacets>("/context/facets", { ...filters }),
    placeholderData: keepPreviousData,
  });
}

export function useContextItem(id: string | null) {
  return useQuery({
    queryKey: contextKeys.item(id ?? ""),
    queryFn: () => api.get<ContextItemDetail>(`/context/items/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessMissing,
  });
}

export function useContextReceipt(id: string | undefined, eventsLimit: number) {
  return useQuery({
    queryKey: contextKeys.receipt(id ?? "", eventsLimit),
    queryFn: () => api.get<ContextReceipt>(`/context/items/${enc(id ?? "")}/receipt`, { events_limit: eventsLimit }),
    enabled: !!id,
    retry: retryUnlessMissing,
    placeholderData: keepPreviousData,
  });
}

export function useContextSources(filters: SourceFilters, limit: number, offset: number) {
  return useQuery({
    queryKey: contextKeys.sources(filters, limit, offset),
    queryFn: () => api.get<Page<ContextSourceSummary>>("/context/sources", { ...filters, limit, offset }),
    placeholderData: keepPreviousData,
  });
}

export function useContextSource(id: string | null, includeSimulated: boolean) {
  return useQuery({
    queryKey: contextKeys.source(id ?? "", includeSimulated),
    queryFn: () => api.get<ContextSourceDetail>(`/context/sources/${enc(id ?? "")}`, { include_simulated: includeSimulated }),
    enabled: !!id,
    retry: retryUnlessMissing,
  });
}
