import type { ReactNode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryRouter, Outlet, RouterProvider, type RouteObject } from "react-router-dom";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { AuthProvider } from "@/features/auth/AuthProvider";
import { useDocumentTitle } from "@/hooks";
import { NAV } from "../nav";
import { describeRouteError, RouteError } from "../RouteError";
import { RouteTitle } from "../RouteTitle";
import { ROUTER_FUTURE, routeTree } from "../routeTree";
import { PAGE_MANIFEST } from "../routes";

const ME = {
  user: { id: "usr_1", email: "ada@example.com", name: "Ada" },
  organization: { id: "org_1", name: "Acme", slug: "acme" },
  role: "security_analyst",
  permissions: ["read"],
  memberships: [],
};

function stubApi(routes: Record<string, { status?: number; body: unknown }>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input), "http://localhost").pathname.replace(/^\/api\/v1/, "");
      const hit = routes[path];
      if (!hit) return new Response(JSON.stringify({ error: { code: "not_found", message: "not stubbed" } }), { status: 404 });
      return new Response(JSON.stringify(hit.body), { status: hit.status ?? 200, headers: { "Content-Type": "application/json" } });
    }),
  );
}

function renderApp(path: string, routes: RouteObject[] = routeTree) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createMemoryRouter(routes, { initialEntries: [path], future: ROUTER_FUTURE });
  const ui = (children: ReactNode) => (
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <ToastProvider>
          <AuthProvider>{children}</AuthProvider>
        </ToastProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
  render(ui(<RouterProvider router={router} future={{ v7_startTransition: true }} />));
  return router;
}

// React Router's data router builds a fetch `Request` with an AbortSignal on every navigation; under
// jsdom that signal is jsdom's, which Node's Request rejects. No route here has loaders, so the
// signal is not needed in these tests.
const NodeRequest = globalThis.Request;
class TestRequest extends NodeRequest {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(input, init ? { ...init, signal: undefined } : init);
  }
}
beforeEach(() => vi.stubGlobal("Request", TestRequest));

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  document.title = "";
});

describe("route table", () => {
  it("gives every navigation entry a route whose title matches its label", () => {
    for (const item of NAV.flatMap((s) => s.items)) {
      const entry = PAGE_MANIFEST.find((p) => `/${p.path}` === item.to);
      expect(entry, item.to).toBeDefined();
      expect(entry?.title, item.to).toBe(item.label);
    }
  });

  it("has unique paths", () => {
    const paths = PAGE_MANIFEST.map((p) => p.path);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it("resolves every route to a real page component", async () => {
    const modules = await Promise.all(PAGE_MANIFEST.map((p) => p.load()));
    PAGE_MANIFEST.forEach((p, i) => expect(typeof modules[i][p.exportName], `${p.path} → ${p.exportName}`).toBe("function"));
  }, 120_000);
});

describe("app shell routing", () => {
  it("renders the 404 page inside the shell and names the tab", async () => {
    stubApi({ "/auth/me": { body: ME }, "/overview/nav-counts": { body: { pending_approvals: 2, open_incidents: 0, open_findings: 5 } } });
    renderApp("/definitely/not/a/page");
    expect(await screen.findByText("Page not found")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main-content");
    await waitFor(() => expect(document.title).toBe("Page not found · ContextOS"));
    // Nav badges come from the shared overview nav-counts query.
    await waitFor(() => expect(screen.getByRole("link", { name: /^Approval Centre/ })).toHaveTextContent("(2)"));
  });

  it("titles a page from the route table while its code loads", async () => {
    stubApi({ "/auth/me": { body: ME } });
    renderApp("/settings");
    await waitFor(() => expect(document.title).toBe("Settings · ContextOS"));
  });

  it("sends signed-out users to the sign-in page", async () => {
    stubApi({ "/auth/me": { status: 401, body: { error: { code: "unauthenticated", message: "Sign in" } } }, "/auth/setup-status": { body: { needs_setup: false } } });
    const router = renderApp("/incidents?status=open");
    await waitFor(() => expect(router.state.location.pathname).toBe("/login"));
    expect(router.state.location.state).toEqual({ from: "/incidents?status=open" });
    await waitFor(() => expect(document.title).toBe("Sign in · ContextOS"));
  });
});

describe("error boundary", () => {
  function Boom(): ReactNode {
    throw new Error("columns is undefined");
  }

  it("shows what went wrong and offers a way out", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    renderApp("/", [{ path: "/", element: <Outlet />, errorElement: <RouteError />, children: [{ index: true, element: <Boom /> }] }]);
    expect(await screen.findByRole("alert")).toHaveTextContent("Something went wrong on this page");
    expect(screen.getByText(/columns is undefined/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reload page" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to overview" })).toHaveAttribute("href", "/");
  });

  it("explains a stale code chunk after a deploy", () => {
    const info = describeRouteError(new TypeError("Failed to fetch dynamically imported module: https://ctx.example.com/assets/TrustCentrePage-x.js"));
    expect(info).toMatchObject({ title: "This page could not be loaded", reload: true });
    expect(info.detail).toMatch(/updated while this tab was open/);
  });
});

describe("document title", () => {
  function AgentPage() {
    useDocumentTitle("payments-bot");
    return <p>agent</p>;
  }

  it("lets a page refine the route title", async () => {
    stubApi({});
    renderApp("/agents/agt_1", [
      { element: <><RouteTitle /><Outlet /></>, children: [{ path: "/agents/:agentId", element: <AgentPage />, handle: { title: "Agent" } }] },
    ]);
    await screen.findByText("agent");
    expect(document.title).toBe("payments-bot · ContextOS");
  });
});
