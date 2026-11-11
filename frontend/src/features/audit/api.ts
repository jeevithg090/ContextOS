/**
 * Audit log hooks. Backend contract: backend/app/api/routes/audit.py (prefix /audit).
 *   GET /audit          -> Page<AuditEntry> (read; newest first; action prefix, actor, target, since/until)
 *   GET /audit/verify   -> AuditVerifyResult (read; recomputes the keyed hash chain)
 *   GET /audit/export   -> JSON Lines download (admin; recorded as "audit.exported")
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, API_BASE, ApiError, revokeSoon, type Page } from "@/lib/api";
import { useThrottledLiveRefresh } from "@/features/integrations/liveRefresh";
import type { AuditEntry, AuditExportResult, AuditFilters, AuditVerifyResult } from "./types";

export const auditKeys = {
  all: ["audit"] as const,
  list: (filters: AuditFilters, page: { limit: number; offset: number }) => ["audit", "list", filters, page] as const,
};

/**
 * Entries matching `filters`. While the newest page is shown it refreshes when other activity is
 * announced on the live stream (most state changes write an audit entry); older pages stay put so
 * rows do not shift under the reader.
 */
export function useAuditLog(filters: AuditFilters, page: { limit: number; offset: number }) {
  useThrottledLiveRefresh(["audit", "list"], { types: null, exclude: ["event.ingested"], enabled: page.offset === 0 });
  return useQuery({
    queryKey: auditKeys.list(filters, page),
    queryFn: () => api.get<Page<AuditEntry>>("/audit", { ...filters, ...page }),
    placeholderData: keepPreviousData,
  });
}

export function useVerifyChain() {
  return useMutation({ mutationFn: () => api.get<AuditVerifyResult>("/audit/verify") });
}

function filenameFrom(disposition: string | null): string {
  const match = disposition?.match(/filename="?([^";]+)"?/i);
  return match?.[1] ?? "contextos-audit.jsonl";
}

/** Downloads the full chain. Uses fetch (not a plain link) so errors surface in the UI. */
export async function downloadAuditExport(): Promise<AuditExportResult> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/audit/export`, {
      headers: { "X-Requested-With": "contextos", Accept: "application/x-ndjson" },
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError(0, "network_error", "Cannot reach the ContextOS API. Is the backend running?");
  }
  if (!response.ok) {
    let message = `Export failed (${response.status})`;
    let code = "http_error";
    try {
      const body = (await response.json()) as { error?: { code?: string; message?: string } };
      message = body.error?.message ?? message;
      code = body.error?.code ?? code;
    } catch {
      /* non-JSON error body: keep the status message */
    }
    throw new ApiError(response.status, code, message);
  }
  const blob = await response.blob();
  const filename = filenameFrom(response.headers.get("Content-Disposition"));
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  revokeSoon(url);
  return {
    filename,
    throughSeq: response.headers.get("X-ContextOS-Audit-Through-Seq"),
    headHash: response.headers.get("X-ContextOS-Audit-Head-Hash"),
  };
}

export function useAuditExport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: downloadAuditExport,
    onSuccess: () => void qc.invalidateQueries({ queryKey: auditKeys.all }), // the export wrote an entry
  });
}
