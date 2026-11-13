/**
 * Page-level test harness: renders a routed page with the providers the app mounts (query cache,
 * router, tooltips, toasts) and answers its API calls from a route function.
 *
 * - Calls are matched by path (the `/api/v1` prefix and the query string are stripped), so list
 *   parameters can be renamed without breaking fixtures; the parsed query is still recorded.
 * - A route that returns nothing gets a 404 error envelope naming the unexpected call.
 * - `hang` keeps a request pending forever, to assert the loading state.
 * - Retries run without delay, so hooks with their own `retry` rule still reach the error state
 *   inside the default `findBy*` timeout.
 */
import type { ReactElement } from "react";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Route, Routes, useLocation } from "react-router-dom";
import { vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import type { Me } from "@/features/auth/AuthProvider";
import { TestRouter } from "./router";

export interface ApiCall {
  path: string;
  query: URLSearchParams;
  method: string;
  body: unknown;
}

export interface Reply {
  status?: number;
  body?: unknown;
  /** Never resolve: the request stays in flight (loading state). */
  pending?: boolean;
}

export type ApiRoute = (call: ApiCall) => Reply | undefined;

export const hang: Reply = { pending: true };

export function errorReply(status: number, code: string, message: string): Reply {
  return { status, body: { error: { code, message } } };
}

/** A 500 with the uniform error envelope (app.core.errors). */
export const serverError = (message = "The server could not complete the request.") => errorReply(500, "internal_error", message);

/** A 404 with the uniform error envelope — what another organisation's id returns. */
export const notFound = (what = "Record") => errorReply(404, "not_found", `${what} not found`);

/** A `Page[T]` body. */
export function page<T>(items: T[], extra: { total?: number; limit?: number; offset?: number } = {}) {
  return { items, total: extra.total ?? items.length, limit: extra.limit ?? 50, offset: extra.offset ?? 0 };
}

/** Stubs `fetch` with `route`; returns the recorded calls. Undo with `vi.unstubAllGlobals()`. */
export function stubApi(route: ApiRoute) {
  const calls: ApiCall[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://app.test");
    const call: ApiCall = {
      path: url.pathname.replace(/^\/api\/v1/, ""),
      query: url.searchParams,
      method: (init?.method ?? "GET").toUpperCase(),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    };
    calls.push(call);
    const reply = route(call) ?? notFound(`No fixture for ${call.method} ${call.path}`);
    if (reply.pending) return new Promise<Response>(() => undefined);
    const status = reply.status ?? 200;
    return new Response(status === 204 ? null : JSON.stringify(reply.body ?? {}), { status, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock, gets: (path: string) => calls.filter((c) => c.method === "GET" && c.path === path) };
}

/** A signed-in user for `useAuth` mocks. */
export function makeMe(permissions: string[], role = "owner"): Me {
  return {
    user: { id: "usr_me", email: "me@acme.test", name: "Ada Analyst" },
    organization: { id: "org_test", name: "Acme Test Org", slug: "acme-test" },
    role,
    permissions,
    memberships: [{ organization_id: "org_test", organization_name: "Acme Test Org", role }],
  };
}

/** Records the current location so tests can assert navigation (hidden: not part of the page's accessibility tree). */
export function LocationProbe() {
  const location = useLocation();
  return (
    <div data-testid="location" hidden>
      {`${location.pathname}${location.search}`}
    </div>
  );
}

/**
 * Renders `element` at `routePath` with the router at `path`. Any other path renders only the
 * location probe, so a navigation away from the page is visible as `data-testid="location"`.
 */
export function renderPage(element: ReactElement, { path, routePath }: { path: string; routePath: string }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, retryDelay: 0 }, mutations: { retry: false } } });
  const result = render(
    <QueryClientProvider client={client}>
      <TestRouter initialEntries={[path]}>
        <TooltipProvider>
          <ToastProvider>
            <Routes>
              <Route path={routePath} element={element} />
              <Route path="*" element={null} />
            </Routes>
            <LocationProbe />
          </ToastProvider>
        </TooltipProvider>
      </TestRouter>
    </QueryClientProvider>,
  );
  return { client, ...result };
}

/** Text of the current location (pathname + search) rendered by `LocationProbe`. */
export function currentLocation(container: ParentNode = document): string {
  return container.querySelector('[data-testid="location"]')?.textContent ?? "";
}
