/**
 * Trust Centre data hooks. Backend contract: backend/app/api/routes/trust.py (prefix /trust).
 *   GET    /trust/summary                    -> TrustSummary (read)
 *   GET    /trust/rules                      -> Page<TrustRule> (read; precedence order)
 *   POST   /trust/rules                      -> TrustRule (trust:manage; re-assesses stored rows)
 *   GET    /trust/rules/{id}                 -> TrustRule
 *   PATCH  /trust/rules/{id}                 -> TrustRule (trust:manage)
 *   DELETE /trust/rules/{id}                 -> RuleDeleteResult (trust:manage)
 *   POST   /trust/rules/test                 -> RuleTestResult (read; dry run, optional draft rule)
 *   GET    /trust/sources                    -> Page<TrustSource>
 *   GET    /trust/sources/{id}               -> TrustSourceDetail
 *   PATCH  /trust/sources/{id}               -> TrustSourceDetail (trust:manage; manual classification)
 *   POST   /trust/sources/{id}/reassess      -> TrustSourceDetail (trust:manage; ?reset_manual)
 *   GET    /trust/destinations               -> Page<TrustDestination>
 *   GET    /trust/destinations/{id}          -> TrustDestinationDetail
 *   PATCH  /trust/destinations/{id}          -> TrustDestinationDetail (trust:manage; exact-match rule)
 *   POST   /trust/destinations/verify        -> DestinationVerifyResult (read; dry run)
 * Query keys start with "trust" so the trust.updated live event refreshes them.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Page } from "@/lib/api";
import type {
  DestinationClassifyInput,
  DestinationFilters,
  DestinationKind,
  DestinationVerifyResult,
  RuleDeleteResult,
  RuleTestRequest,
  RuleTestResult,
  SourceClassifyInput,
  SourceFilters,
  TrustDestination,
  TrustDestinationDetail,
  TrustRule,
  TrustRuleInput,
  TrustRulePatch,
  TrustSource,
  TrustSourceDetail,
  TrustSummary,
} from "./types";

const enc = encodeURIComponent;

export const trustKeys = {
  all: ["trust"] as const,
  summary: ["trust", "summary"] as const,
  rules: ["trust", "rules"] as const,
  sources: (filters: SourceFilters) => ["trust", "sources", filters] as const,
  source: (id: string) => ["trust", "source", id] as const,
  destinations: (filters: DestinationFilters) => ["trust", "destinations", filters] as const,
  destination: (id: string) => ["trust", "destination", id] as const,
};

const no404Retry = (count: number, err: unknown) => !(err instanceof ApiError && err.status === 404) && count < 2;

/** Server-side validation messages from a 422 envelope ({details: {errors: [...]}} or FastAPI's list). */
export function validationErrors(error: unknown): string[] {
  if (!(error instanceof ApiError) || error.status !== 422) return [];
  const details = error.details as { errors?: unknown } | Array<{ loc?: unknown[]; msg?: string }> | null | undefined;
  if (details && !Array.isArray(details) && Array.isArray(details.errors)) return details.errors.map(String);
  if (Array.isArray(details)) return details.map((d) => `${(d.loc ?? []).slice(1).join(".") || "request"}: ${d.msg ?? "invalid"}`);
  return [];
}

export function errorMessage(error: unknown): string {
  const list = validationErrors(error);
  if (list.length) return list.join(" · ");
  return error instanceof Error ? error.message : "The request failed.";
}

/* ----------------------------------------------------------------------------- reads */

export function useTrustSummary() {
  return useQuery({ queryKey: trustKeys.summary, queryFn: () => api.get<TrustSummary>("/trust/summary") });
}

export function useTrustRules() {
  return useQuery({ queryKey: trustKeys.rules, queryFn: () => api.get<Page<TrustRule>>("/trust/rules", { limit: 1000 }) });
}

export function useTrustSources(filters: SourceFilters) {
  return useQuery({
    queryKey: trustKeys.sources(filters),
    queryFn: () =>
      api.get<Page<TrustSource>>("/trust/sources", {
        trust_level: filters.trust_level,
        source_type: filters.source_type,
        q: filters.q,
        manual: filters.manual,
        has_findings: filters.has_findings,
        capability: filters.capability,
        sort: filters.sort,
        limit: filters.limit,
        offset: filters.offset,
      }),
    placeholderData: keepPreviousData,
  });
}

export function useTrustSource(id: string | null) {
  return useQuery({
    queryKey: trustKeys.source(id ?? ""),
    queryFn: () => api.get<TrustSourceDetail>(`/trust/sources/${enc(id ?? "")}`),
    enabled: !!id,
    retry: no404Retry,
  });
}

export function useTrustDestinations(filters: DestinationFilters) {
  return useQuery({
    queryKey: trustKeys.destinations(filters),
    queryFn: () =>
      api.get<Page<TrustDestination>>("/trust/destinations", {
        classification: filters.classification,
        kind: filters.kind,
        q: filters.q,
        has_blocked: filters.has_blocked,
        sort: filters.sort,
        limit: filters.limit,
        offset: filters.offset,
      }),
    placeholderData: keepPreviousData,
  });
}

export function useTrustDestination(id: string | null) {
  return useQuery({
    queryKey: trustKeys.destination(id ?? ""),
    queryFn: () => api.get<TrustDestinationDetail>(`/trust/destinations/${enc(id ?? "")}`),
    enabled: !!id,
    retry: no404Retry,
  });
}

/* ----------------------------------------------------------------------------- dry runs */

/** Live dry run for the rule editor: cached per (draft, example) so typing does not refetch the same input. */
export function useRuleTestQuery(body: RuleTestRequest | null) {
  return useQuery({
    queryKey: ["trust", "rule-test", body] as const,
    queryFn: () => api.post<RuleTestResult>("/trust/rules/test", body),
    enabled: !!body,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
}

export function useRuleTest() {
  return useMutation({ mutationFn: (body: RuleTestRequest) => api.post<RuleTestResult>("/trust/rules/test", body) });
}

export function useDestinationVerify() {
  return useMutation({
    mutationFn: (body: { kind: DestinationKind; identifier: string }) => api.post<DestinationVerifyResult>("/trust/destinations/verify", body),
  });
}

/* ----------------------------------------------------------------------------- mutations */

/** Any trust change can reclassify sources and destinations everywhere: refresh the whole feature. */
function useInvalidateTrust() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: trustKeys.all });
    void qc.invalidateQueries({ queryKey: ["context"] });
  };
}

export function useCreateRule() {
  const invalidate = useInvalidateTrust();
  return useMutation({ mutationFn: (body: TrustRuleInput) => api.post<TrustRule>("/trust/rules", body), onSuccess: invalidate });
}

export function useUpdateRule() {
  const invalidate = useInvalidateTrust();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: TrustRulePatch }) => api.patch<TrustRule>(`/trust/rules/${enc(id)}`, patch),
    onSuccess: invalidate,
  });
}

export function useDeleteRule() {
  const invalidate = useInvalidateTrust();
  return useMutation({ mutationFn: (id: string) => api.delete<RuleDeleteResult>(`/trust/rules/${enc(id)}`), onSuccess: invalidate });
}

export function useClassifySource(id: string) {
  const qc = useQueryClient();
  const invalidate = useInvalidateTrust();
  return useMutation({
    mutationFn: (body: SourceClassifyInput) => api.patch<TrustSourceDetail>(`/trust/sources/${enc(id)}`, body),
    onSuccess: (saved) => {
      qc.setQueryData(trustKeys.source(saved.id), saved);
      invalidate();
    },
  });
}

export function useReassessSource(id: string) {
  const qc = useQueryClient();
  const invalidate = useInvalidateTrust();
  return useMutation({
    mutationFn: (resetManual: boolean) =>
      api.post<TrustSourceDetail>(`/trust/sources/${enc(id)}/reassess`, undefined, resetManual ? { reset_manual: true } : undefined),
    onSuccess: (saved) => {
      qc.setQueryData(trustKeys.source(saved.id), saved);
      invalidate();
    },
  });
}

export function useClassifyDestination(id: string) {
  const qc = useQueryClient();
  const invalidate = useInvalidateTrust();
  return useMutation({
    mutationFn: (body: DestinationClassifyInput) => api.patch<TrustDestinationDetail>(`/trust/destinations/${enc(id)}`, body),
    onSuccess: (saved) => {
      qc.setQueryData(trustKeys.destination(saved.id), saved);
      invalidate();
    },
  });
}
