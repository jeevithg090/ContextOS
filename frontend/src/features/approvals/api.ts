/**
 * Approval Centre data hooks. Backend contract: backend/app/api/routes/approvals.py.
 *   GET  /approvals                 -> Page<Approval> (read; ?status=… repeatable, default pending;
 *                                      include_simulated; sort oldest|newest|recently_decided)
 *   GET  /approvals/{id}            -> ApprovalDetail (read)
 *   POST /approvals/{id}/decide     -> ApprovalDetail (approve; {approve, note}; 409 when no longer pending)
 * Reads lazily expire overdue requests on the server. Query keys start with "approvals" so the
 * approval.created / approval.decided live events (hooks/useLiveEvents) refresh them.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Page } from "@/lib/api";
import type { Approval, ApprovalDetail, ApprovalListParams, DecideInput } from "./types";

const enc = encodeURIComponent;

export const HISTORY_STATUSES = ["approved", "rejected", "expired", "cancelled"];

export const approvalKeys = {
  all: ["approvals"] as const,
  list: (params: ApprovalListParams) => ["approvals", "list", params] as const,
  count: (view: ApprovalListParams["view"], includeSimulated: boolean) => ["approvals", "count", view, includeSimulated] as const,
  detail: (id: string) => ["approvals", "detail", id] as const,
};

const retryUnlessMissing = (count: number, err: unknown) => !(err instanceof ApiError && (err.status === 404 || err.status === 403)) && count < 2;

export function isNotFound(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

export function isConflict(err: unknown): boolean {
  return err instanceof ApiError && err.status === 409;
}

function listQuery(params: ApprovalListParams) {
  return {
    status: params.view === "queue" ? ["pending"] : HISTORY_STATUSES,
    include_simulated: params.includeSimulated,
    sort: params.view === "queue" ? "oldest" : "recently_decided",
    limit: params.limit,
    offset: params.offset,
  };
}

/** The pending queue (oldest first) or the decision history (latest first). The queue also refetches
 * every 30 s so requests that time out move to the history even when the live stream is offline. */
export function useApprovals(params: ApprovalListParams, options: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: approvalKeys.list(params),
    queryFn: () => api.get<Page<Approval>>("/approvals", listQuery(params)),
    placeholderData: keepPreviousData,
    refetchInterval: params.view === "queue" ? 30_000 : false,
    enabled: options.enabled ?? true,
  });
}

/** Total for a tab badge (one row fetched; the server counts). */
export function useApprovalCount(view: ApprovalListParams["view"], includeSimulated: boolean) {
  return useQuery({
    queryKey: approvalKeys.count(view, includeSimulated),
    queryFn: () => api.get<Page<Approval>>("/approvals", listQuery({ view, includeSimulated, limit: 1, offset: 0 })),
    select: (page) => page.total,
  });
}

export function useApproval(id: string | null | undefined) {
  return useQuery({
    queryKey: approvalKeys.detail(id ?? ""),
    queryFn: () => api.get<ApprovalDetail>(`/approvals/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessMissing,
  });
}

/** Approve or reject. On success the detail cache is replaced and every approval list refetches. */
export function useDecideApproval() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: DecideInput }) => api.post<ApprovalDetail>(`/approvals/${enc(id)}/decide`, body),
    onSuccess: (detail) => {
      qc.setQueryData(approvalKeys.detail(detail.id), detail);
      for (const key of [["approvals", "list"], ["approvals", "count"], ["overview"], ["sessions"]]) {
        void qc.invalidateQueries({ queryKey: key });
      }
    },
    onError: (_err, { id }) => {
      // 409: someone else decided, or it expired. Show the current state.
      void qc.invalidateQueries({ queryKey: approvalKeys.all });
      void qc.invalidateQueries({ queryKey: approvalKeys.detail(id) });
    },
  });
}
