/**
 * Engineering analytics and remediation pipeline hooks.
 * Backend contract: backend/app/api/routes/workspace_analytics.py
 *
 *   GET /workspace/analytics?window=30d&board_id=&include_simulations=  -> EngineeringAnalytics
 *   GET /workspace/analytics/remediation?state=&severity=&q=&include_simulations=&limit=&offset= -> RemediationPage
 *
 * Keys start with "workspace" so `task.updated` refreshes them; remediation keys also sit under
 * ["workspace", "remediation"], which `finding.created` and the from-finding mutation invalidate.
 * Finding status changes (`finding.updated`) are subscribed to here because they move findings out
 * of (or back into) the open list.
 */
import { useEffect } from "react";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { onLiveMessage } from "@/hooks";
import type { AnalyticsParams, EngineeringAnalytics, RemediationFilters, RemediationPage } from "./types";

const ANALYTICS = "/workspace/analytics";

export const analyticsKeys = {
  analytics: (params: AnalyticsParams) => ["workspace", "analytics", params] as const,
  remediation: (filters: RemediationFilters) => ["workspace", "remediation", filters] as const,
};

const REFRESH_ON = new Set(["finding.created", "finding.updated", "incident.updated"]);

/** Refetch analytics and the remediation pipeline when findings change status. */
function useFindingRefresh() {
  const qc = useQueryClient();
  useEffect(
    () =>
      onLiveMessage((msg) => {
        if (!REFRESH_ON.has(msg.type)) return;
        void qc.invalidateQueries({ queryKey: ["workspace", "remediation"] });
        void qc.invalidateQueries({ queryKey: ["workspace", "analytics"] });
      }),
    [qc],
  );
}

export function useEngineeringAnalytics(params: AnalyticsParams) {
  useFindingRefresh();
  return useQuery({
    queryKey: analyticsKeys.analytics(params),
    queryFn: () => api.get<EngineeringAnalytics>(ANALYTICS, { ...params }),
    placeholderData: keepPreviousData,
  });
}

export function useRemediationPipeline(filters: RemediationFilters) {
  useFindingRefresh();
  return useQuery({
    queryKey: analyticsKeys.remediation(filters),
    queryFn: () => api.get<RemediationPage>(`${ANALYTICS}/remediation`, { ...filters }),
    placeholderData: keepPreviousData,
  });
}
