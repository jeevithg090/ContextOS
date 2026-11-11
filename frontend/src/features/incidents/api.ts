/**
 * Incident data hooks. Backend contract: backend/app/api/routes/incidents.py.
 *   GET   /incidents                     -> Page<IncidentSummary> (read; status[], severity[], q, assignee, sort)
 *   POST  /incidents                     -> IncidentDetail (write; {title, summary, severity, finding_ids})
 *   GET   /incidents/{id}                -> IncidentDetail
 *   PATCH /incidents/{id}                -> IncidentDetail (write; {status?, severity?, assignee_user_id?, resolution?})
 *   POST  /incidents/{id}/notes          -> Activity (write; {body}, redacted server-side)
 *   POST  /incidents/{id}/findings       -> LinkFindingsResult (write; {finding_ids})
 *   GET   /incidents/{id}/timeline       -> IncidentTimeline (?type[]&limit)
 *   GET   /incidents/{id}/export         -> evidence bundle JSON (download; audited)
 *   POST  /workspace/tasks/from-incident -> RemediationTasksResult (write; workspace package)
 *   GET   /org/members, GET /findings    -> assignee and finding pickers
 * Query keys start with "incidents" so incident.created / incident.updated live events refresh them.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { api, API_BASE, ApiError, downloadFile, type Page } from "@/lib/api";
import type {
  Activity,
  ExportResult,
  FindingOption,
  IncidentCreate,
  IncidentDetail,
  IncidentFilters,
  IncidentSummary,
  IncidentTimeline,
  IncidentUpdate,
  LinkFindingsResult,
  Member,
  RemediationTasksResult,
  TimelineEntryType,
} from "./types";

const enc = encodeURIComponent;

export const incidentKeys = {
  all: ["incidents"] as const,
  list: (filters: IncidentFilters, limit: number, offset: number) => ["incidents", "list", filters, limit, offset] as const,
  detail: (id: string) => ["incidents", "detail", id] as const,
  timeline: (id: string, types: TimelineEntryType[]) => ["incidents", "timeline", id, types] as const,
  members: ["incidents", "members"] as const,
  findingOptions: (includeSimulated: boolean) => ["findings", "incident-options", includeSimulated] as const,
};

const retryUnlessMissing = (count: number, err: unknown) => !(err instanceof ApiError && (err.status === 404 || err.status === 403)) && count < 2;

export function isNotFound(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  return err instanceof Error ? err.message : "Something went wrong";
}

export function useIncidents(filters: IncidentFilters, limit: number, offset: number) {
  return useQuery({
    queryKey: incidentKeys.list(filters, limit, offset),
    queryFn: () => api.get<Page<IncidentSummary>>("/incidents", { ...filters, limit, offset }),
    placeholderData: keepPreviousData,
  });
}

export function useIncident(id: string | undefined) {
  return useQuery({
    queryKey: incidentKeys.detail(id ?? ""),
    queryFn: () => api.get<IncidentDetail>(`/incidents/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessMissing,
  });
}

export function useIncidentTimeline(id: string | undefined, types: TimelineEntryType[]) {
  return useQuery({
    queryKey: incidentKeys.timeline(id ?? "", types),
    queryFn: () => api.get<IncidentTimeline>(`/incidents/${enc(id ?? "")}/timeline`, { type: types, limit: 2000 }),
    enabled: !!id,
    retry: retryUnlessMissing,
    placeholderData: keepPreviousData,
  });
}

/** Active members of the organisation (assignee picker). */
export function useMembers(enabled = true) {
  return useQuery({
    queryKey: incidentKeys.members,
    queryFn: () => api.get<Page<Member>>("/org/members", { limit: 500 }),
    enabled,
    staleTime: 60_000,
    select: (page) => page.items.filter((m) => m.is_active),
  });
}

/** Open or acknowledged findings not yet part of an incident (create / link pickers). */
export function useFindingOptions(includeSimulated: boolean, enabled: boolean) {
  return useQuery({
    queryKey: incidentKeys.findingOptions(includeSimulated),
    queryFn: () =>
      api.get<Page<FindingOption>>("/findings", { status: ["open", "acknowledged"], include_simulated: includeSimulated, sort: "severity", limit: 200 }),
    enabled,
    select: (page) => page.items.filter((f) => f.incident === null),
  });
}

function invalidate(qc: QueryClient, extra: string[][] = []) {
  for (const key of [["incidents"], ["overview"], ...extra]) void qc.invalidateQueries({ queryKey: key });
}

function storeDetail(qc: QueryClient, detail: IncidentDetail) {
  qc.setQueryData(incidentKeys.detail(detail.id), detail);
}

export function useCreateIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: IncidentCreate) => api.post<IncidentDetail>("/incidents", body),
    onSuccess: (detail) => {
      storeDetail(qc, detail);
      invalidate(qc, [["findings"]]);
    },
  });
}

export function useUpdateIncident(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: IncidentUpdate) => api.patch<IncidentDetail>(`/incidents/${enc(id)}`, body),
    onSuccess: (detail) => {
      storeDetail(qc, detail);
      invalidate(qc);
    },
  });
}

export function useAddNote(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: string) => api.post<Activity>(`/incidents/${enc(id)}/notes`, { body }),
    onSuccess: (activity) => {
      qc.setQueryData<IncidentDetail>(incidentKeys.detail(id), (old) => (old ? { ...old, activity: [...old.activity, activity] } : old));
      invalidate(qc);
    },
  });
}

export function useLinkFindings(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (findingIds: string[]) => api.post<LinkFindingsResult>(`/incidents/${enc(id)}/findings`, { finding_ids: findingIds }),
    onSuccess: (result) => {
      storeDetail(qc, result.incident);
      invalidate(qc, [["findings"]]);
    },
  });
}

export function useCreateRemediationTasks(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (mode: RemediationTasksResult["mode"]) =>
      api.post<RemediationTasksResult>("/workspace/tasks/from-incident", { incident_id: id, mode }),
    onSuccess: () => invalidate(qc, [["workspace"], ["findings"]]),
  });
}

function filenameFrom(header: string | null, fallback: string): string {
  const match = header ? /filename="?([^";]+)"?/i.exec(header) : null;
  return match?.[1] ?? fallback;
}

/**
 * Download the evidence bundle exactly as the server produced it (the bytes are kept as-is so the
 * bundle's sha256 can be re-verified), then refresh the incident (the export is recorded in its activity).
 */
export function useExportIncident(id: string, key: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (): Promise<ExportResult> => {
      let response: Response;
      try {
        response = await fetch(`${API_BASE}/incidents/${enc(id)}/export`, {
          headers: { "X-Requested-With": "contextos", Accept: "application/json" },
          credentials: "same-origin",
        });
      } catch {
        throw new ApiError(0, "network_error", "Cannot reach the ContextOS API. Is the backend running?");
      }
      const text = await response.text();
      if (!response.ok) {
        let err: { code?: string; message?: string; details?: unknown } | undefined;
        try {
          err = (JSON.parse(text) as { error?: typeof err }).error;
        } catch {
          err = undefined;
        }
        throw new ApiError(response.status, err?.code ?? "http_error", err?.message ?? `Export failed (${response.status})`, err?.details);
      }
      const filename = filenameFrom(response.headers.get("Content-Disposition"), `contextos-${key.toLowerCase()}-evidence.json`);
      downloadFile(filename, text);
      let sha256: string | null = null;
      try {
        sha256 = (JSON.parse(text) as { integrity?: { sha256?: string } }).integrity?.sha256 ?? null;
      } catch {
        sha256 = null;
      }
      return { filename, sha256 };
    },
    onSuccess: () => invalidate(qc, [["audit"]]),
  });
}
