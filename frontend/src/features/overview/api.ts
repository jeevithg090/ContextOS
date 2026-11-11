/**
 * Overview data hooks. Backend contract: backend/app/api/routes/overview.py.
 *   GET /overview/nav-counts  -> NavCounts (read; real rows only; also polled by the app shell)
 *   GET /overview             -> Overview (?window=24h|7d|30d&include_simulated=true|false)
 * Query keys start with "overview" so event / decision / finding / approval / incident live events
 * refresh them (hooks/useLiveEvents).
 */
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { NavCounts, Overview, OverviewWindow } from "./types";

export const overviewKeys = {
  all: ["overview"] as const,
  navCounts: ["overview", "nav-counts"] as const,
  overview: (window: OverviewWindow, includeSimulated: boolean) => ["overview", "summary", window, includeSimulated] as const,
};

export function useOverview(window: OverviewWindow, includeSimulated: boolean) {
  return useQuery({
    queryKey: overviewKeys.overview(window, includeSimulated),
    queryFn: () => api.get<Overview>("/overview", { window, include_simulated: includeSimulated }),
    placeholderData: keepPreviousData,
    // Live events invalidate this query; the interval only keeps relative times and integration
    // staleness honest when the stream is offline.
    refetchInterval: 60_000,
  });
}

export function useNavCounts() {
  return useQuery({
    queryKey: overviewKeys.navCounts,
    queryFn: () => api.get<NavCounts>("/overview/nav-counts"),
    refetchInterval: 30_000,
  });
}
