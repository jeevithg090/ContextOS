import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { act, fireEvent, render, renderHook, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { TestRouter } from "@/test/router";
import { useStartRun } from "../api";
import { SimulationLabPage } from "../SimulationLabPage";
import { AGENTS, COMPARE, PASSING_RUN, RUN, SCENARIO_LIST, SUITE_RESULT, SUITES, page } from "./fixtures";

let permissions: string[] = ["read", "write"];

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

type Reply = { status?: number; body?: unknown };
type Handler = (path: string, query: URLSearchParams, method: string, body: unknown) => Reply | undefined;
const calls: Array<{ path: string; query: URLSearchParams; method: string; body: unknown }> = [];
let override: Handler = () => undefined;

function defaults(path: string, query: URLSearchParams, method: string): Reply {
  if (method === "POST" && path === "/api/v1/simulations/runs") return { status: 201, body: RUN };
  if (method === "POST" && path === "/api/v1/simulations/suites") return { status: 201, body: SUITE_RESULT };
  if (path === "/api/v1/simulations/scenarios") return { body: SCENARIO_LIST };
  if (path === "/api/v1/simulations/runs") return { body: page([RUN, PASSING_RUN]) };
  if (path.startsWith("/api/v1/simulations/runs/")) {
    const id = decodeURIComponent(path.split("/").pop() ?? "");
    if (id === RUN.id) return { body: RUN };
    if (id === PASSING_RUN.id) return { body: PASSING_RUN };
    return { status: 404, body: { error: { code: "not_found", message: "Simulation run not found" } } };
  }
  if (path === "/api/v1/simulations/suites/compare") return { body: COMPARE };
  if (path === "/api/v1/simulations/suites") return { body: page(SUITES) };
  if (path === "/api/v1/agents") return { body: AGENTS };
  return { status: 500, body: { error: { code: "unexpected", message: `unexpected ${method} ${path}?${query}` } } };
}

beforeEach(() => {
  permissions = ["read", "write"];
  calls.length = 0;
  override = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      const parsed = new URL(url, "http://test.invalid");
      calls.push({ path: parsed.pathname, query: parsed.searchParams, method, body });
      const reply = override(parsed.pathname, parsed.searchParams, method, body) ?? defaults(parsed.pathname, parsed.searchParams, method);
      return new Response(JSON.stringify(reply.body ?? {}), { status: reply.status ?? 200, headers: { "Content-Type": "application/json" } });
    }),
  );
});

afterEach(() => vi.unstubAllGlobals());

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.search}</output>;
}

function search(): URLSearchParams {
  return new URLSearchParams(screen.getByTestId("location").textContent ?? "");
}

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <TestRouter initialEntries={[path]}>
        <TooltipProvider>
          <ToastProvider>
            <Routes>
              <Route path="/simulation" element={<SimulationLabPage />} />
            </Routes>
            <LocationProbe />
          </ToastProvider>
        </TooltipProvider>
      </TestRouter>
    </QueryClientProvider>,
  );
  return qc;
}

const posts = (path: string) => calls.filter((c) => c.method === "POST" && c.path === path);

describe("Simulation Lab — catalogue", () => {
  it("shows the simulation banner and the catalogue grouped by category with checks and steps", async () => {
    renderAt("/simulation");
    expect(await screen.findByRole("heading", { name: "Malicious README" })).toBeInTheDocument();
    const banner = screen.getByRole("note", { name: "About simulations" });
    expect(banner).toHaveTextContent(/synthetic, inert events/);
    expect(banner).toHaveTextContent(/Nothing is executed/);
    expect(banner).toHaveTextContent(/excluded from real metrics by default/);

    const injection = screen.getByRole("region", { name: /Prompt injection/ });
    expect(within(injection).getByRole("heading", { name: "Malicious website" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: /Baseline \(false-positive guard\)/ })).toBeInTheDocument();
    expect(screen.getByText("Reading an SSH private key after a prompt injection is denied before it runs.")).toBeInTheDocument();
    expect(screen.getAllByText("read ssh key").length).toBeGreaterThan(0);
  });

  it("runs one scenario and opens its result (checks, steps, evidence, honest wording) in the drawer", async () => {
    renderAt("/simulation");
    fireEvent.click(await screen.findByRole("button", { name: "Run Malicious README" }));

    await waitFor(() => expect(posts("/api/v1/simulations/runs")).toHaveLength(1));
    expect(posts("/api/v1/simulations/runs")[0].body).toEqual({ scenario_id: "malicious-readme", agent_id: null, agent_version: null });
    await waitFor(() => expect(search().get("run")).toBe(RUN.id));

    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText(RUN.summary)).toBeInTheDocument();
    expect(within(drawer).getByText("1 of 2 checks passed")).toBeInTheDocument();
    expect(within(drawer).getByText("Simulation")).toBeInTheDocument();
    // Expected vs actual, with the redaction marker shown as returned.
    expect(within(drawer).getByText("DENY (enforced)")).toBeInTheDocument();
    expect(drawer.querySelector('[data-redacted="true"]')).toHaveTextContent("[REDACTED:github_token]");
    // Steps: decision + enforcement badges and the honest outcome wording.
    expect(within(drawer).getByText("Denied before it ran.")).toBeInTheDocument();
    expect(within(drawer).getByText(/Allowed and recorded for review/)).toBeInTheDocument();
    expect(within(drawer).getAllByText("Enforced").length).toBe(2);
    expect(within(drawer).getByText(/Matched policies: Audit file reads/)).toBeInTheDocument();
    expect(drawer.textContent).not.toMatch(/\bblocked\b/i);

    const href = (name: string) => within(drawer).getByRole("link", { name }).getAttribute("href");
    expect(href("Finding fnd_01F")).toBe("/intelligence/fnd_01F");
    expect(href("Policy decision pdc_01D")).toBe("/replay/ses_01MAIN?decision=pdc_01D");
    expect(href("Source src_01S")).toBe("/trust?source=src_01S");
    expect(href("Tool call inv_01R")).toBe("/sessions/ses_01MAIN?invocation=inv_01R");
    expect(href("Approval apr_01A")).toBe("/approvals?approval=apr_01A");
    expect(href("Session ses_01MAIN")).toBe("/sessions/ses_01MAIN");
    expect(within(drawer).getByRole("link", { name: /Provenance graph/ })).toHaveAttribute("href", "/provenance?session=ses_01MAIN");
    expect(within(drawer).getByText(/observed relationships between records, not causes/)).toBeInTheDocument();

    // Policy snapshot is collapsed by default.
    const snapshot = within(drawer).getByText(/^Policy snapshot/).closest("details");
    expect(snapshot).not.toHaveAttribute("open");
  });

  it("runs the whole catalogue as a suite against a registered agent and version, then shows its runs", async () => {
    renderAt("/simulation");
    const agentSelect = await screen.findByLabelText("Run against");
    await screen.findByRole("option", { name: /payments-coder/ });
    fireEvent.change(agentSelect, { target: { value: "agt_01A" } });
    fireEvent.change(screen.getByLabelText("Agent version (optional)"), { target: { value: " 2.0.0 " } });
    fireEvent.click(screen.getByRole("button", { name: "Run all as suite" }));

    await waitFor(() => expect(posts("/api/v1/simulations/suites")).toHaveLength(1));
    expect(posts("/api/v1/simulations/suites")[0].body).toEqual({ agent_id: "agt_01A", agent_version: "2.0.0" });
    await waitFor(() => expect(search().get("tab")).toBe("history"));
    expect(search().get("suite")).toBe("suite_02NEW");
    await waitFor(() => expect(calls.some((c) => c.path === "/api/v1/simulations/runs" && c.method === "GET" && c.query.get("suite_run_id") === "suite_02NEW")).toBe(true));
  });

  it("disables runs for viewers with the reason and never posts", async () => {
    permissions = ["read"];
    renderAt("/simulation");
    const run = await screen.findByRole("button", { name: "Run Malicious README" });
    expect(run).toBeDisabled();
    expect(screen.getByRole("button", { name: "Run all as suite" })).toBeDisabled();
    expect(screen.getByText(/cannot start runs/)).toBeInTheDocument();
    expect(run).toHaveAccessibleDescription(/needs the write permission/);
    fireEvent.click(run);
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);
    expect(calls.some((c) => c.path === "/api/v1/agents")).toBe(false);
  });

  it("shows an error with retry when the catalogue cannot load", async () => {
    let failures = 1;
    override = (path) => (path === "/api/v1/simulations/scenarios" && failures-- > 0 ? { status: 500, body: { error: { code: "boom", message: "Server error" } } } : undefined);
    renderAt("/simulation");
    expect(await screen.findByText("Couldn’t load this view")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "Malicious README" })).toBeInTheDocument();
  });

  it("shows a loading state while the catalogue loads", () => {
    renderAt("/simulation");
    expect(screen.getAllByLabelText("Loading").length).toBeGreaterThan(0);
  });
});

describe("Simulation Lab — run deep links", () => {
  it("opens ?run=<id> directly and closing removes it from the URL", async () => {
    renderAt("/simulation?run=simrun_02PASS");
    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByText("All 1 checks passed.")).toBeInTheDocument();
    expect(within(drawer).getByText("This run recorded no check results.")).toBeInTheDocument();
    fireEvent.click(within(drawer).getByRole("button", { name: "Close panel" }));
    await waitFor(() => expect(search().get("run")).toBeNull());
  });

  it("says 'not found' (without retrying) for an unknown or foreign run id", async () => {
    renderAt("/simulation?run=simrun_foreign");
    expect(await screen.findByText("Simulation run not found")).toBeInTheDocument();
    expect(calls.filter((c) => c.path === "/api/v1/simulations/runs/simrun_foreign")).toHaveLength(1);
  });
});

describe("Simulation Lab — history", () => {
  it("lists runs and suites, filters by verdict and jumps to a comparison", async () => {
    renderAt("/simulation?tab=history");
    const runs = await screen.findByRole("table", { name: "Simulation runs" });
    expect(await within(runs).findByText("Malicious README")).toBeInTheDocument();
    expect(within(runs).getByText("1/2")).toBeInTheDocument();
    expect(within(runs).getByText("Failed")).toBeInTheDocument();
    expect(within(runs).getByText("Passed")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Verdict"), { target: { value: "failed" } });
    await waitFor(() => expect(search().get("verdict")).toBe("failed"));
    await waitFor(() => expect(calls.some((c) => c.path === "/api/v1/simulations/runs" && c.query.get("passed") === "false")).toBe(true));

    const suites = await screen.findByRole("table", { name: "Regression suites" });
    expect(await within(suites).findByText("67%")).toBeInTheDocument();
    expect(within(suites).getByText("100%")).toBeInTheDocument();
    fireEvent.click(within(suites).getByRole("button", { name: /Compare suite suite_02NEW with the previous suite suite_01OLD/ }));
    await waitFor(() => expect(search().get("tab")).toBe("compare"));
    expect(search().get("base")).toBe("suite_01OLD");
    expect(search().get("head")).toBe("suite_02NEW");
  });

  it("opens a run from the table", async () => {
    renderAt("/simulation?tab=history");
    const runs = await screen.findByRole("table", { name: "Simulation runs" });
    fireEvent.click(await within(runs).findByText("Benign coding session"));
    await waitFor(() => expect(search().get("run")).toBe(PASSING_RUN.id));
  });

  it("explains how runs appear when there are none", async () => {
    override = (path, _q, method) =>
      method === "GET" && (path === "/api/v1/simulations/runs" || path === "/api/v1/simulations/suites") ? { body: page([]) } : undefined;
    renderAt("/simulation?tab=history");
    expect(await screen.findByText("No simulation runs yet")).toBeInTheDocument();
    expect(await screen.findByText("No suites yet")).toBeInTheDocument();
  });
});

describe("Simulation Lab — compare", () => {
  it("defaults to the two newest suites and shows regressions first with their changes", async () => {
    renderAt("/simulation?tab=compare");
    await waitFor(() => {
      const call = calls.find((c) => c.path === "/api/v1/simulations/suites/compare");
      expect(call?.query.get("base")).toBe("suite_01OLD");
      expect(call?.query.get("head")).toBe("suite_02NEW");
    });
    const list = await screen.findByRole("list", { name: "Scenario changes" });
    const items = Array.from(list.children) as HTMLElement[];
    expect(items[0]).toHaveTextContent("Malicious README");
    expect(items[0]).toHaveTextContent("Regressed");
    expect(items[1]).toHaveTextContent("Still passing");
    expect(within(items[0]).getByText("DENY (enforced)")).toBeInTheDocument();
    expect(within(items[0]).getByText("AUDIT (enforced)")).toBeInTheDocument();
    expect(within(items[0]).getByText("Credential access")).toBeInTheDocument();
    expect(within(items[0]).getByText("Deny")).toBeInTheDocument();
    expect(within(items[0]).getByText("Audit")).toBeInTheDocument();

    expect(screen.getByText("enabled: True → False")).toBeInTheDocument();
    expect(screen.getAllByRole("note").some((n) => /not proof of causation/.test(n.textContent ?? ""))).toBe(true);

    fireEvent.click(within(items[0]).getByRole("button", { name: "Open head run of Malicious README" }));
    await waitFor(() => expect(search().get("run")).toBe("simrun_h2"));
    expect(search().get("tab")).toBe("compare");
  });

  it("asks for two suites when fewer exist", async () => {
    override = (path) => (path === "/api/v1/simulations/suites" ? { body: page([SUITES[0]]) } : undefined);
    renderAt("/simulation?tab=compare");
    expect(await screen.findByText("One suite so far")).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/api/v1/simulations/suites/compare")).toBe(false);
  });

  it("does not compare a suite with itself", async () => {
    renderAt("/simulation?tab=compare&base=suite_02NEW&head=suite_02NEW");
    expect(await screen.findByText("Pick two different suites")).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/api/v1/simulations/suites/compare")).toBe(false);
  });
});

describe("Simulation Lab — data hooks", () => {
  it("a run refreshes every view the simulated rows appear in", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const spy = vi.spyOn(qc, "invalidateQueries");
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
    const { result } = renderHook(() => useStartRun(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync({ scenario_id: "malicious-readme" });
    });
    const keys = spy.mock.calls.map(([arg]) => JSON.stringify(arg?.queryKey));
    for (const key of [["simulations"], ["findings"], ["sessions"], ["approvals"], ["incidents"], ["overview"]]) {
      expect(keys).toContain(JSON.stringify(key));
    }
    expect(qc.getQueryData(["simulations", "run", RUN.id])).toEqual(RUN);
  });
});

describe("Simulation Lab — design rules", () => {
  it("uses semantic colour tokens only (no raw palette classes or colour literals)", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "..");
    const sources = (readdirSync(root, { recursive: true }) as string[]).filter((f) => /\.tsx?$/.test(f) && !f.includes("__tests__"));
    expect(sources.length).toBeGreaterThan(5);
    const palette = /\b(?:text|bg|border|ring|fill|stroke)-(?:red|green|blue|yellow|gray|slate|zinc|neutral|stone|orange|amber|lime|emerald|teal|cyan|sky|indigo|violet|purple|fuchsia|pink|rose|white|black)(?:-\d{2,3})?\b/;
    const literal = /#[0-9a-fA-F]{3,8}\b|rgba?\(\s*\d/;
    const offenders = sources.filter((f) => {
      const text = readFileSync(join(root, f), "utf8");
      return palette.test(text) || literal.test(text);
    });
    expect(offenders).toEqual([]);
  });
});
