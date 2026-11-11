/**
 * Engineering analytics and remediation pipeline hooks.
 * Backend contract: backend/app/api/routes/workspace_analytics.py
 *
 *   GET /workspace/analytics?window=30d&board_id=&include_simulations=  -> EngineeringAnalytics
 *   GET /workspace/analytics/remediation?state=&severity=&q=&include_simulations=&limit=&offset= -> RemediationPage
 *
 * Keys start with "workspace" so `task.updated` refreshes them. `finding.created`, `finding.updated`
 * (status changes move findings out of, or back into, the open list) and `incident.updated` refresh
 * ["workspace", "remediation"] and ["workspace", "analytics"] through the shared live-event map
 * (src/hooks/useLiveEvents.ts, WORK_PIPELINE); the from-finding mutation invalidates them too.
 */
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { AnalyticsParams, EngineeringAnalytics, RemediationFilters, RemediationPage } from "./types";

const ANALYTICS = "/workspace/analytics";

export const analyticsKeys = {
  analytics: (params: AnalyticsParams) => ["workspace", "analytics", params] as const,
  remediation: (filters: RemediationFilters) => ["workspace", "remediation", filters] as const,
};

export function useEngineeringAnalytics(params: AnalyticsParams) {
  return useQuery({
    queryKey: analyticsKeys.analytics(params),
    queryFn: () => api.get<EngineeringAnalytics>(ANALYTICS, { ...params }),
    placeholderData: keepPreviousData,
  });
}

export function useRemediationPipeline(filters: RemediationFilters) {
  return useQuery({
    queryKey: analyticsKeys.remediation(filters),
    queryFn: () => api.get<RemediationPage>(`${ANALYTICS}/remediation`, { ...filters }),
    placeholderData: keepPreviousData,
  });
}
