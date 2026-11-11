/**
 * Browser-tab titles: "<page> · ContextOS".
 *
 * The app shell sets a title for every route from the route table (`handle.title` in
 * src/app/routes.tsx) in a layout effect. A page that knows something more specific (an agent's
 * name, a finding's title) calls `useDocumentTitle(...)`; its passive effect runs after the shell's
 * layout effect, so the more specific title wins and is replaced again on the next navigation.
 */
import { useEffect } from "react";

export const APP_NAME = "ContextOS";

export function formatDocumentTitle(title?: string | null): string {
  const trimmed = title?.trim();
  return trimmed ? `${trimmed} · ${APP_NAME}` : APP_NAME;
}

/** Set the tab title while the calling component is mounted. `null`/`undefined` leaves it alone. */
export function useDocumentTitle(title: string | null | undefined): void {
  useEffect(() => {
    if (title === null || title === undefined) return;
    document.title = formatDocumentTitle(title);
  }, [title]);
}
