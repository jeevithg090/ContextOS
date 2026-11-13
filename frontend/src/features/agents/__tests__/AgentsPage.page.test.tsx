import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, renderPage, serverError, stubApi, type ApiRoute } from "@/test/pageHarness";
import { AgentsPage } from "../AgentsPage";
import { AGENT_SUMMARY, SIM_AGENT, agentPage } from "./pageFixtures";

let permissions: string[] = ["read", "write"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => {
  permissions = ["read", "write"];
});
afterEach(() => vi.unstubAllGlobals());

const onlyAgents = (reply: ReturnType<ApiRoute>): ApiRoute => (c) => (c.path === "/agents" ? reply : undefined);
const renderAgents = (path = "/agents") => renderPage(<AgentsPage />, { path, routePath: "/agents" });

describe("AgentsPage", () => {
  it("shows a busy table while the inventory loads", () => {
    stubApi(onlyAgents(hang));
    renderAgents();
    expect(screen.getByRole("heading", { name: "Agents" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Agents" })).toHaveAttribute("aria-busy", "true");
  });

  it("shows the error envelope's message and recovers on retry", async () => {
    let fail = true;
    stubApi((c) => (c.path === "/agents" ? (fail ? serverError("Agent inventory is unavailable") : { body: agentPage([AGENT_SUMMARY]) }) : undefined));
    renderAgents();
    expect(await screen.findByText("Couldn’t load this view")).toBeInTheDocument();
    expect(screen.getByText("Agent inventory is unavailable")).toBeInTheDocument();
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("payments-coder")).toBeInTheDocument();
  });

  it("explains how agents appear and offers registration when there are none", async () => {
    stubApi(onlyAgents({ body: agentPage([]) }));
    renderAgents();
    expect(await screen.findByText("No agents yet")).toBeInTheDocument();
    expect(screen.getByText(/Agents appear when an integration reports its first event/)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Register agent" }).length).toBe(2);
  });

  it("says how many simulated agents are hidden and reveals them on request", async () => {
    const api = stubApi((c) =>
      c.path === "/agents" ? { body: c.query.get("include_simulated") === "true" ? agentPage([SIM_AGENT], 1) : agentPage([], 1) } : undefined,
    );
    renderAgents();
    expect(await screen.findByText(/1 Simulation Lab agent hidden/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show simulated agents" }));
    expect(await screen.findByText("sim-researcher")).toBeInTheDocument();
    expect(currentLocation()).toContain("sim=1");
    expect(api.gets("/agents").at(-1)?.query.get("include_simulated")).toBe("true");
    const row = screen.getByText("sim-researcher").closest("tr") as HTMLElement;
    expect(within(row).getByText("Simulation")).toBeInTheDocument();
  });

  it("lists agents with owner, environment, findings and session counts, and opens one", async () => {
    stubApi(onlyAgents({ body: agentPage([AGENT_SUMMARY, { ...SIM_AGENT, is_simulation: false, name: "docs-writer", id: "agt_docs" }]) }));
    renderAgents();
    const table = screen.getByRole("table", { name: "Agents" });
    const row = (await within(table).findByText("payments-coder")).closest("tr") as HTMLElement;
    expect(within(row).getByText(/Owner platform-team · Maintains the payments service/)).toBeInTheDocument();
    expect(within(row).getByText("Production")).toBeInTheDocument();
    expect(within(row).getByText("Claude Code")).toBeInTheDocument();
    expect(within(row).getByText("Critical")).toBeInTheDocument();
    expect(within(row).getByText("3")).toBeInTheDocument();
    expect(within(row).getByText(/1 active ·/)).toBeInTheDocument();
    expect(within(row).getByLabelText(/Risk of payments-coder/)).toBeInTheDocument();
    const other = within(table).getByText("docs-writer").closest("tr") as HTMLElement;
    expect(within(other).getByText("No active session")).toBeInTheDocument();
    expect(within(other).getByText("Never reported")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Inventory/ })).toHaveTextContent("Inventory2");

    fireEvent.click(row);
    await waitFor(() => expect(currentLocation()).toBe("/agents/agt_payments"));
  });

  it("hides registration from read-only users", async () => {
    permissions = ["read"];
    stubApi(onlyAgents({ body: agentPage([]) }));
    renderAgents();
    expect(await screen.findByText("No agents yet")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register agent" })).not.toBeInTheDocument();
  });
});
