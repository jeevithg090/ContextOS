/**
 * Route error boundary (React Router `errorElement`). Shown when a page throws while rendering or
 * its code chunk cannot be loaded — the most common cause after a deploy, when the open tab still
 * references chunk files that no longer exist. Inside the app shell the navigation stays usable.
 */
import { useEffect } from "react";
import { isRouteErrorResponse, Link, useRouteError } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui";
import { ApiError } from "@/lib/api";

const CHUNK_ERROR = /dynamically imported module|Importing a module script failed|error loading dynamically|Failed to fetch dynamically|ChunkLoadError|Loading chunk/i;

export interface ErrorDescription {
  title: string;
  detail: string;
  /** A stale or unreachable code chunk: reloading is the fix. */
  reload: boolean;
}

export function describeRouteError(error: unknown): ErrorDescription {
  if (isRouteErrorResponse(error)) {
    if (error.status === 404) return { title: "Page not found", detail: "This page doesn’t exist.", reload: false };
    return { title: `Request failed (${error.status})`, detail: error.statusText || "The page could not be loaded.", reload: true };
  }
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  if (CHUNK_ERROR.test(message) || (error instanceof Error && error.name === "ChunkLoadError")) {
    return {
      title: "This page could not be loaded",
      detail: "Its code could not be downloaded — usually because ContextOS was updated while this tab was open, or the connection dropped. Reload to get the current version.",
      reload: true,
    };
  }
  if (error instanceof ApiError) {
    return { title: "The server returned an error", detail: error.message, reload: true };
  }
  return {
    title: "Something went wrong on this page",
    detail: message ? `The page stopped with an unexpected error: ${message}` : "The page stopped with an unexpected error.",
    reload: true,
  };
}

export function RouteError() {
  const error = useRouteError();
  const info = describeRouteError(error);

  useEffect(() => {
    // Keep the original error visible to developers; it is a client-side render error, not user data.
    console.error("Route error", error);
  }, [error]);

  return (
    <div role="alert" className="mx-auto flex max-w-lg flex-col items-center px-6 py-16 text-center">
      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg border border-danger/30 bg-danger/10 text-danger">
        <AlertTriangle className="h-5 w-5" aria-hidden />
      </div>
      <h1 className="text-[15px] font-semibold text-fg">{info.title}</h1>
      <p className="mt-1.5 text-xs text-fg-muted">{info.detail}</p>
      <div className="mt-5 flex items-center gap-2">
        {info.reload && (
          <Button size="sm" variant="primary" onClick={() => window.location.reload()}>
            Reload page
          </Button>
        )}
        <Link to="/" reloadDocument={info.reload} className="inline-flex h-7 items-center rounded border border-border-strong px-2.5 text-xs text-fg hover:bg-surface-2">
          Back to overview
        </Link>
      </div>
    </div>
  );
}
