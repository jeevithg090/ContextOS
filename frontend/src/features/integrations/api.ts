/**
 * Integration registry hooks. Backend contract: backend/app/api/routes/integrations.py.
 *   GET /integrations               -> IntegrationsOverview (read)
 *   GET /integrations/{kind}/setup  -> SetupGuide (read; 404 for kinds outside the catalog)
 * Health moves from "connected" to "stale" with time alone, so the overview also refetches on an
 * interval; new traffic refreshes it through the live stream.
 */
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import { useThrottledLiveRefresh } from "./liveRefresh";
import type { IntegrationsOverview, SetupGuide } from "./types";

export const integrationKeys = {
  all: ["integrations"] as const,
  overview: ["integrations", "overview"] as const,
  setup: (kind: string) => ["integrations", "setup", kind] as const,
};

const no404Retry = (count: number, err: unknown) => !(err instanceof ApiError && err.status === 404) && count < 2;

export function useIntegrations() {
  useThrottledLiveRefresh(integrationKeys.overview, { types: ["event.ingested", "decision.made"] });
  return useQuery({
    queryKey: integrationKeys.overview,
    queryFn: () => api.get<IntegrationsOverview>("/integrations"),
    refetchInterval: 60_000,
  });
}

export function useSetupGuide(kind: string | null) {
  return useQuery({
    queryKey: integrationKeys.setup(kind ?? ""),
    queryFn: () => api.get<SetupGuide>(`/integrations/${encodeURIComponent(kind ?? "")}/setup`),
    enabled: !!kind,
    staleTime: 5 * 60_000,
    retry: no404Retry,
  });
}
