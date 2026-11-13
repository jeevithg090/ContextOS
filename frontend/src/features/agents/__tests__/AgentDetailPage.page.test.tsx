import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, notFound, page, renderPage, serverError, stubApi, type ApiRoute } from "@/test/pageHarness";
import { AgentDetailPage } from "../AgentDetailPage";
import type { AgentDetail } from "../types";
import { AGENT_DETAIL, POSTURE, SESSION_SUMMARY } from "./pageFixtures";

let permissions: string[] = ["read", "write", "policy:manage"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => {
  permissions = ["read", "write", "policy:manage"];
});
afterEach(() => vi.unstubAllGlobals());

function routes(agent: AgentDetail = AGENT_DETAIL, sessions = [SESSION_SUMMARY]): ApiRoute {
  return (c) => {
    if (c.path === `/agents/${agent.id}`) return { body: agent };
    if (c.path === `/agents/${agent.id}/posture`) return { body: POSTURE };
    if (c.path === `/agents/${agent.id}/sessions`) return { body: page(sessions, { limit: 25 }) };
    return undefined;
  };
}

const renderAgent = (id = "agt_payments", query = "") => renderPage(<AgentDetailPage />, { path: `/agents/${id}${query}`, routePath: "/agents/:agentId" });

describe("AgentDetailPage", () => {
  it("shows a loading state while the profile loads", () => {
    stubApi(() => hang);
    renderAgent();
    expect(screen.getByLabelText("Loading")).toHaveAttribute("aria-busy", "true");
  });

  it("says the agent was not found for an unknown or foreign id, without retrying", async () => {
    const api = stubApi((c) => (c.path === "/agents/agt_foreign" ? notFound("Agent 'agt_foreign'") : undefined));
    renderAgent("agt_foreign");
    expect(await screen.findByText("Agent not found")).toBeInTheDocument();
    expect(screen.getByText(/may belong to another organisation/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to agents" })).toHaveAttribute("href", "/agents");
    expect(api.gets("/agents/agt_foreign")).toHaveLength(1);
  });

  it("shows the server's error for other failures", async () => {
    stubApi((c) => (c.path === "/agents/agt_payments" ? serverError("Agent store unavailable") : undefined));
    renderAgent();
    expect(await screen.findByText("Couldn’t load this view")).toBeInTheDocument();
    expect(screen.getByText("Agent store unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("shows identity, integration, posture, risk, relationships and sessions from the API", async () => {
    stubApi(routes());
    renderAgent();
    expect(await screen.findByRole("heading", { name: /payments-coder/ })).toBeInTheDocument();
    expect(screen.getByText("Maintains the payments service")).toBeInTheDocument();
    expect(screen.getByText("platform-team")).toBeInTheDocument();
    expect(screen.getByText("1.4.0")).toBeInTheDocument();
    expect(screen.getByText("Claude Code hooks")).toBeInTheDocument();
    expect(screen.getAllByText("Production").length).toBeGreaterThan(0);
    expect(screen.getByText("pci")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Quarantine" })).toBeEnabled();

    // Posture with its basis and per-dimension explanation.
    expect(await screen.findByText(POSTURE.summary)).toBeInTheDocument();
    const dimensions = screen.getByRole("list", { name: "Posture dimensions" });
    expect(within(dimensions).getByText("High-risk tool policies")).toBeInTheDocument();
    expect(within(dimensions).getByText("5/25")).toBeInTheDocument();
    expect(within(dimensions).getByText("Add a policy that requires approval for outbound HTTP with secrets.")).toBeInTheDocument();

    // Decisions are reported by how they were enforced; nothing claims to have blocked an advisory decision.
    const risk = screen.getByRole("region", { name: "Current risk" });
    expect(within(risk).getByText("Enforced").closest("li")).toHaveTextContent("Enforced9");
    expect(within(risk).getByText("Advisory").closest("li")).toHaveTextContent("Advisory2");
    expect(within(risk).getByText("Critical").parentElement).toHaveTextContent("Critical1");
    expect(document.body.textContent).not.toMatch(/\bblocked\b/i);
    expect(screen.getByText("Observed delegations and messages, not causation.")).toBeInTheDocument();
    expect(screen.getByText("Delegates to")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Agent code-reviewer" })).toHaveAttribute("href", "/agents/agt_reviewer");
    expect(screen.getByRole("link", { name: "Session Latest code-reviewer session" })).toHaveAttribute("href", "/sessions/ses_child");
    expect(screen.getByText("Crosses trust boundary")).toBeInTheDocument();

    const sessions = screen.getByRole("table", { name: "Sessions" });
    const row = (await within(sessions).findByText("sess-7f3a")).closest("tr") as HTMLElement;
    expect(within(row).getByText("Active")).toBeInTheDocument();
    expect(within(row).getByText(/1 sub-session/)).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Sessions/ })).toHaveTextContent("12");
    fireEvent.click(row);
    await waitFor(() => expect(currentLocation()).toBe("/sessions/ses_main"));
  });

  it("explains empty sessions, findings and relationships", async () => {
    const quiet: AgentDetail = { ...AGENT_DETAIL, session_count: 0, active_session_count: 0, open_findings: 0, findings_by_severity: {}, recent_findings: [], relationships: [], decisions_by_enforcement: {} };
    stubApi(routes(quiet, []));
    renderAgent();
    expect(await screen.findByText("No sessions yet")).toBeInTheDocument();
    expect(screen.getByText("Sessions appear when the integration reports events for this agent.")).toBeInTheDocument();
    expect(screen.getByText("No delegation or messaging with other agents has been observed.")).toBeInTheDocument();
    expect(screen.getByText("No tool call has been evaluated yet.")).toBeInTheDocument();
    expect(screen.getByText(/No active session\. Ended sessions keep their own risk scores\./)).toBeInTheDocument();
  });

  it("opens the findings tab from the URL", async () => {
    stubApi(routes());
    renderAgent("agt_payments", "?tab=findings");
    expect(await screen.findByRole("link", { name: "Finding Credential sent to an unclassified host" })).toHaveAttribute("href", "/intelligence/fnd_exfil");
    expect(screen.getByText(/most severe of 3 unresolved findings/)).toBeInTheDocument();
  });

  it("offers no edit or quarantine actions to read-only users", async () => {
    permissions = ["read"];
    stubApi(routes());
    renderAgent();
    expect(await screen.findByRole("heading", { name: /payments-coder/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Quarantine" })).not.toBeInTheDocument();
  });
});
