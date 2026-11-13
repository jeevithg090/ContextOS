/**
 * Policy Studio data hooks. Backend contract: backend/app/api/routes/policies.py (prefix /policies).
 *   GET    /policies                    -> Page<Policy> (read; filters enabled, mode, outcome, builtin, q)
 *   POST   /policies                    -> Policy (policy:manage; 422 {details.errors} when invalid)
 *   GET    /policies/{id}               -> Policy
 *   PATCH  /policies/{id}               -> Policy (policy:manage; version += 1 on evaluation changes)
 *   DELETE /policies/{id}               -> 204 (policy:manage; built-ins cannot be deleted)
 *   POST   /policies/validate           -> ValidationResult
 *   POST   /policies/test               -> PolicyTestResult (dry run, nothing persisted)
 *   GET    /policies/fields             -> FieldSpec[]
 *   GET    /policies/operators          -> OperatorSpec[]
 *   GET    /policies/{id}/decisions     -> Page<PolicyDecisionMatch>
 *   GET    /policies/recent-decisions   -> Page<DecisionSummary> (test-input picker)
 * Query keys start with "policies" so the policy.updated live event refreshes them.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Page } from "@/lib/api";
import type {
  DecisionSummary,
  FieldSpec,
  OperatorSpec,
  Policy,
  PolicyDecisionMatch,
  PolicyFilters,
  PolicyInput,
  PolicyPatch,
  PolicyTestRequest,
  PolicyTestResult,
  ValidationResult,
} from "./types";

const enc = encodeURIComponent;

export const policyKeys = {
  all: ["policies"] as const,
  list: (filters: PolicyFilters) => ["policies", "list", filters] as const,
  detail: (id: string) => ["policies", "detail", id] as const,
  decisions: (id: string, includeSimulation: boolean) => ["policies", "decisions", id, includeSimulation] as const,
  recent: (filters: Record<string, unknown>) => ["policies", "recent-decisions", filters] as const,
  fields: ["policies", "fields"] as const,
  operators: ["policies", "operators"] as const,
};

/** Server-side validation messages from a 422 envelope ({details: {errors: [...]}}), if any. */
export function validationErrors(error: unknown): string[] {
  if (!(error instanceof ApiError) || error.status !== 422) return [];
  const details = error.details as { errors?: unknown } | Array<{ loc?: unknown[]; msg?: string }> | null | undefined;
  if (details && !Array.isArray(details) && Array.isArray(details.errors)) return details.errors.map(String);
  if (Array.isArray(details)) return details.map((d) => `${(d.loc ?? []).slice(1).join(".") || "request"}: ${d.msg ?? "invalid"}`);
  return [];
}

export function usePolicies(filters: PolicyFilters) {
  return useQuery({
    queryKey: policyKeys.list(filters),
    queryFn: () => api.get<Page<Policy>>("/policies", { ...filters, limit: 500 }),
    placeholderData: keepPreviousData,
  });
}

export function usePolicy(id: string | null) {
  return useQuery({
    queryKey: policyKeys.detail(id ?? ""),
    queryFn: () => api.get<Policy>(`/policies/${enc(id ?? "")}`),
    enabled: !!id,
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 2,
  });
}

export function usePolicyFields() {
  return useQuery({ queryKey: policyKeys.fields, queryFn: () => api.get<FieldSpec[]>("/policies/fields"), staleTime: Infinity });
}

export function usePolicyOperators() {
  return useQuery({ queryKey: policyKeys.operators, queryFn: () => api.get<OperatorSpec[]>("/policies/operators"), staleTime: Infinity });
}

export function usePolicyDecisions(id: string | null, includeSimulation: boolean) {
  return useQuery({
    queryKey: policyKeys.decisions(id ?? "", includeSimulation),
    queryFn: () =>
      api.get<Page<PolicyDecisionMatch>>(`/policies/${enc(id ?? "")}/decisions`, { limit: 25, days: 30, include_simulated: includeSimulation }),
    enabled: !!id,
  });
}

export function useRecentDecisions(filters: { session_id?: string; decision?: string; include_simulated?: boolean }, enabled: boolean) {
  return useQuery({
    queryKey: policyKeys.recent(filters),
    queryFn: () => api.get<Page<DecisionSummary>>("/policies/recent-decisions", { ...filters, limit: 25 }),
    enabled,
  });
}

export function useCreatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: PolicyInput) => api.post<Policy>("/policies", body),
    onSuccess: (created) => {
      qc.setQueryData(policyKeys.detail(created.id), created);
      void qc.invalidateQueries({ queryKey: ["policies", "list"] });
    },
  });
}

export function useUpdatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: PolicyPatch }) => api.patch<Policy>(`/policies/${enc(id)}`, patch),
    onSuccess: (saved) => {
      qc.setQueryData(policyKeys.detail(saved.id), saved);
      void qc.invalidateQueries({ queryKey: ["policies", "list"] });
    },
  });
}

export function useDeletePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/policies/${enc(id)}`),
    onSuccess: (_, id) => {
      qc.removeQueries({ queryKey: policyKeys.detail(id) });
      void qc.invalidateQueries({ queryKey: ["policies", "list"] });
    },
  });
}

export interface ValidationRequest {
  conditions: unknown;
  outcome?: string;
  restrictions?: unknown;
}

/** Live validation + plain-English preview for a (debounced) draft. Keyed by its JSON text. */
export function useConditionValidation(body: ValidationRequest | null) {
  const key = body ? JSON.stringify(body) : "";
  return useQuery({
    queryKey: ["policies", "validate", key],
    queryFn: () => api.post<ValidationResult>("/policies/validate", body ?? { conditions: {} }),
    enabled: body !== null,
    placeholderData: keepPreviousData,
    staleTime: 60_000,
    retry: false,
  });
}

export function useTestPolicy() {
  return useMutation({ mutationFn: (body: PolicyTestRequest) => api.post<PolicyTestResult>("/policies/test", body) });
}

/** The organisation's outcome when no policy matches (Settings → default decision). */
export function useDefaultDecision() {
  return useQuery({
    queryKey: ["policies", "org-default-decision"],
    queryFn: () => api.get<{ settings: { default_decision: "ALLOW" | "AUDIT" } }>("/org"),
    select: (org) => org.settings.default_decision,
    staleTime: 5 * 60_000,
  });
}
