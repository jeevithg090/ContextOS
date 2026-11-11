/**
 * Security Intelligence data hooks. Backend contract: backend/app/api/routes/findings.py.
 *   GET   /findings                 -> Page<FindingSummary> (read; FindingFilters, severity then last seen)
 *   GET   /findings/stats           -> FindingStats (?window=24h|7d|30d|90d&include_simulated)
 *   GET   /findings/{id}            -> FindingDetail
 *   PATCH /findings/{id}            -> FindingDetail (write; {status?, resolution_note?}; 409 invalid transition)
 *   POST  /findings/{id}/incident   -> LinkIncidentResult (write; {incident_id?} attach, or open a new one)
 *   POST  /workspace/tasks/from-finding -> RemediationTaskResult (write; 201 created / 200 existing open task)
 * Query keys start with "findings" so finding.created / finding.updated live events refresh them.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Page } from "@/lib/api";
import type { FindingDetail, FindingFilters, FindingStats, FindingSummary, FindingUpdate, LinkIncidentInput, LinkIncidentResult, RemediationTaskResult, StatsWindow } from "./types";

const enc = encodeURIComponent;

export const findingKeys = {
  all: ["findings"] as const,
  list: (filters: FindingFilters, limit: number, offset: number) => ["findings", "list", filters, limit, offset] as const,
  stats: (window: StatsWindow, includeSimulated: boolean) => ["findings", "stats", window, includeSimulated] as const,
  detail: (id: string) => ["findings", "detail", id] as const,
};

/** "Not found" is a definitive answer (another organisation's id, or a typo): never retry it. */
const retryUnlessMissing = (count: number, err: unknown) => !(err instanceof ApiError && (err.status === 404 || err.status === 403)) && count < 2;

export function isNotFound(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

export function useFindings(filters: FindingFilters, limit: number, offset: number) {
  return useQuery({
    queryKey: findingKeys.list(filters, limit, offset),
    queryFn: () => api.get<Page<FindingSummary>>("/findings", { ...filters, limit, offset }),
    placeholderData: keepPreviousData,
  });
}

export function useFindingStats(window: StatsWindow, includeSimulated: boolean) {
  return useQuery({
    queryKey: findingKeys.stats(window, includeSimulated),
    queryFn: () => api.get<FindingStats>("/findings/stats", { window, include_simulated: includeSimulated }),
    placeholderData: keepPreviousData,
  });
}

export function useFinding(id: string | undefined) {
  return useQuery({
    queryKey: findingKeys.detail(id ?? ""),
    queryFn: () => api.get<FindingDetail>(`/findings/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessMissing,
  });
}

function invalidateAround(qc: ReturnType<typeof useQueryClient>, extra: string[][] = []) {
  for (const key of [["findings"], ["overview"], ["incidents"], ["workspace", "remediation"], ...extra]) {
    void qc.invalidateQueries({ queryKey: key });
  }
}

/** Triage: change status and/or the resolution note. Returns the refreshed detail. */
export function useUpdateFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: FindingUpdate }) => api.patch<FindingDetail>(`/findings/${enc(id)}`, body),
    onSuccess: (detail, { body }) => {
      qc.setQueryData(findingKeys.detail(detail.id), detail);
      // Entering or leaving "false positive" changes the source's finding evidence (Trust Centre).
      invalidateAround(qc, body.status ? [["trust"], ["context"]] : []);
    },
  });
}

/** Attach to an existing incident (incident_id) or open a new one. */
export function useLinkIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: LinkIncidentInput }) => api.post<LinkIncidentResult>(`/findings/${enc(id)}/incident`, body),
    onSuccess: () => invalidateAround(qc),
  });
}

/**
 * Create the remediation task for a finding in the Engineering Workspace, or get the open one that
 * already exists (`created: false`). The workspace builds the task's description and acceptance
 * criteria from the finding's evidence.
 */
export function useCreateRemediationTask() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (findingId: string) => api.post<RemediationTaskResult>("/workspace/tasks/from-finding", { finding_id: findingId }),
    onSuccess: (_result, findingId) => {
      void qc.invalidateQueries({ queryKey: findingKeys.detail(findingId) });
      void qc.invalidateQueries({ queryKey: ["workspace"] });
      void qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}
