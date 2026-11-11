/**
 * Replay Lab data hooks. Backend contract: backend/app/api/routes/replay.py (prefix /replay).
 *   GET  /replay/sessions/{id}?limit&offset&decision_id -> Replay (recorded steps + recomputed risk)
 *   POST /replay/counterfactual                         -> CounterfactualResult (SIMULATION; nothing persisted)
 * Also reads GET /sessions (picker), GET /policies (policy-set editor) and POST /policies/validate
 * (draft validation). Query keys start with the owning feature ("replay", "sessions", "policies")
 * so the matching live events refresh them.
 */
import { useEffect } from "react";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Page } from "@/lib/api";
import { onLiveMessage } from "@/hooks/useLiveEvents";
import type {
  CounterfactualRequest,
  CounterfactualResult,
  Replay,
  ReplayPolicy,
  ReplaySessionSummary,
  SessionPickerFilters,
  ValidationResult,
} from "./types";

const enc = encodeURIComponent;
export const REPLAY_WINDOW = 500;

export const replayKeys = {
  all: ["replay"] as const,
  session: (id: string, params: { offset: number; decisionId: string | null }) => ["replay", "session", id, params] as const,
  picker: (filters: SessionPickerFilters) => ["sessions", "replay-picker", filters] as const,
  policies: ["policies", "replay-editor"] as const,
};

/** Messages from a 422 envelope: {details: {errors: [...]}} or FastAPI's field list. */
export function validationErrors(error: unknown): string[] {
  if (!(error instanceof ApiError) || error.status !== 422) return [];
  const details = error.details as { errors?: unknown } | Array<{ loc?: unknown[]; msg?: string }> | null | undefined;
  if (details && !Array.isArray(details) && Array.isArray(details.errors)) return details.errors.map(String);
  if (Array.isArray(details)) return details.map((d) => `${(d.loc ?? []).slice(1).join(".") || "request"}: ${d.msg ?? "invalid"}`);
  return [];
}

export function useReplaySessions(filters: SessionPickerFilters) {
  return useQuery({
    queryKey: replayKeys.picker(filters),
    queryFn: () =>
      api.get<Page<ReplaySessionSummary>>("/sessions", {
        q: filters.q || undefined,
        sort: filters.sort,
        include_simulated: filters.include_simulated,
        limit: 50,
      }),
    placeholderData: keepPreviousData,
  });
}

export function useReplay(sessionId: string | undefined, params: { offset: number; decisionId: string | null }) {
  return useQuery({
    queryKey: replayKeys.session(sessionId ?? "", params),
    queryFn: () =>
      api.get<Replay>(`/replay/sessions/${enc(sessionId ?? "")}`, {
        limit: REPLAY_WINDOW,
        offset: params.decisionId ? undefined : params.offset,
        decision_id: params.decisionId ?? undefined,
      }),
    enabled: Boolean(sessionId),
    placeholderData: keepPreviousData,
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 2,
  });
}

/** New events in the replayed session append steps: refetch when the stream reports them. */
export function useReplayLiveRefresh(sessionId: string | undefined) {
  const qc = useQueryClient();
  useEffect(() => {
    if (!sessionId) return;
    return onLiveMessage((msg) => {
      if (msg.type === "event.ingested" && msg.session_id === sessionId) {
        void qc.invalidateQueries({ queryKey: ["replay", "session", sessionId] });
      }
    });
  }, [qc, sessionId]);
}

export function useReplayPolicies() {
  return useQuery({
    queryKey: replayKeys.policies,
    queryFn: () => api.get<Page<ReplayPolicy>>("/policies", { limit: 500 }),
    staleTime: 30_000,
  });
}

export function useValidateDraft() {
  return useMutation({
    mutationFn: (body: { conditions: unknown; outcome?: string; restrictions?: unknown }) =>
      api.post<ValidationResult>("/policies/validate", body),
  });
}

export function useCounterfactual() {
  return useMutation({
    mutationFn: (body: CounterfactualRequest) => api.post<CounterfactualResult>("/replay/counterfactual", body),
  });
}
