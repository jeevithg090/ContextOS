/** Presentation helpers for the Integrations page. */
import { pluralize } from "@/lib/format";
import type { IntegrationsOverview } from "./types";

/**
 * The staleness window in words ("24 hours", "15 minutes"). The server sends both units; whole hours
 * read better than "1440 minutes", and minutes are kept for windows shorter than an hour.
 */
export function staleWindowLabel(overview: Pick<IntegrationsOverview, "stale_after_minutes" | "stale_after_hours">): string {
  const minutes = overview.stale_after_minutes;
  const hours = overview.stale_after_hours ?? minutes / 60;
  if (minutes >= 60 && Number.isInteger(hours)) return pluralize(hours, "hour");
  return pluralize(minutes, "minute");
}
