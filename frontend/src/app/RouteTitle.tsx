/** Sets the browser-tab title from the deepest matched route's `handle.title`. */
import { useLayoutEffect } from "react";
import { useMatches } from "react-router-dom";
import { formatDocumentTitle } from "@/hooks/useDocumentTitle";
import type { RouteHandle } from "./routes";

function titleOf(handle: unknown): string | null {
  const title = (handle as Partial<RouteHandle> | undefined)?.title;
  return typeof title === "string" && title ? title : null;
}

export function RouteTitle() {
  const matches = useMatches();
  const title = matches.reduceRight<string | null>((found, match) => found ?? titleOf(match.handle), null);

  // A layout effect runs before any page's passive effect, so useDocumentTitle() in a page can
  // refine this title (e.g. with the agent's name) and wins.
  useLayoutEffect(() => {
    document.title = formatDocumentTitle(title);
  }, [title]);
  return null;
}
