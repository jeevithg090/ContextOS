import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import type { RemediationPage as RemediationPageData } from "../analytics/types";
import { RemediationPage } from "../RemediationPage";
import { REMEDIATION } from "./pageFixtures";

let permissions: string[] = ["read", "write"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => {
  permissions = ["read", "write"];
});
afterEach(() => vi.unstubAllGlobals());

const EMPTY: RemediationPageData = { items: [], total: 0, limit: 50, offset: 0, counts: { no_task: 0, task_open: 0, task_done_unverified: 0, verified: 0 } };

const routes = (reply: Reply = { body: REMEDIATION }): ApiRoute => (c) => (c.path === "/workspace/analytics/remediation" ? reply : undefined);
const renderRemediation = (query = "") => renderPage(<RemediationPage />, { path: `/work/remediation${query}`, routePath: "/work/remediation" });

describe("RemediationPage", () => {
  it("shows a busy table while the pipeline loads", () => {
    stubApi(routes(hang));
    renderRemediation();
    expect(screen.getByRole("heading", { name: "Security Remediation" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Open findings and their remediation state" })).toHaveAttribute("aria-busy", "true");
  });

  it("shows the server's error with a retry", async () => {
    stubApi(routes(serverError("Remediation pipeline unavailable")));
    renderRemediation();
    expect(await screen.findByText("Remediation pipeline unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("says when every finding is resolved", async () => {
    stubApi(routes({ body: EMPTY }));
    renderRemediation();
    expect(await screen.findByText("No open findings")).toBeInTheDocument();
    expect(screen.getByText(/Every finding is resolved or marked a false positive/)).toBeInTheDocument();
  });

  it("says when filters hide every finding", async () => {
    stubApi(routes({ body: EMPTY }));
    renderRemediation("?severity=critical");
    expect(await screen.findByText("No findings match these filters")).toBeInTheDocument();
  });

  it("shows stage counts and each finding with where its fix stands", async () => {
    stubApi(routes());
    renderRemediation();
    const table = screen.getByRole("table", { name: "Open findings and their remediation state" });
    const tracked = (await within(table).findByRole("link", { name: "Finding Credential sent to an unclassified host" })).closest("tr") as HTMLElement;
    expect(within(tracked).getByText("Critical")).toBeInTheDocument();
    expect(within(tracked).getByText("seen 2×")).toBeInTheDocument();
    expect(within(tracked).getByRole("link", { name: "Incident Incident" })).toHaveAttribute("href", "/incidents/inc_3");
    expect(within(tracked).getByRole("link", { name: "Agent payments-coder" })).toHaveAttribute("href", "/agents/agt_payments");
    expect(within(tracked).getByTitle("A linked task exists and is not in a done column yet.")).toHaveTextContent("In progress");
    expect(within(tracked).getByText("CTX-7 is in progress.")).toBeInTheDocument();
    expect(within(tracked).getByRole("link", { name: "CTX-7" })).toHaveAttribute("href", "/work/tasks/tsk_rotate");

    const untracked = within(table).getByRole("link", { name: "Finding Instruction override in fetched page" }).closest("tr") as HTMLElement;
    expect(within(untracked).getByTitle("No remediation task tracks this finding yet.")).toHaveTextContent("No task");
    expect(within(untracked).getByRole("button", { name: "Create a remediation task for Instruction override in fetched page" })).toBeInTheDocument();

    const stages = screen.getByRole("group", { name: "Remediation stages" });
    expect(within(stages).getByRole("button", { name: /No task/ })).toHaveTextContent("1");
    expect(within(stages).getByRole("button", { name: /Verified/ })).toHaveTextContent("0");
    expect(screen.getByText(/a fix attempt marked complete is a claim, not proof/)).toBeInTheDocument();
  });

  it("filters by stage through the URL", async () => {
    const api = stubApi(routes());
    renderRemediation();
    await screen.findByText("CTX-7 is in progress.");
    fireEvent.click(within(screen.getByRole("group", { name: "Remediation stages" })).getByRole("button", { name: /No task/ }));
    await waitFor(() => expect(currentLocation()).toContain("state=no_task"));
    await waitFor(() => expect(api.gets("/workspace/analytics/remediation").at(-1)?.query.get("state")).toBe("no_task"));
  });

  it("offers no task creation to read-only users", async () => {
    permissions = ["read"];
    stubApi(routes());
    renderRemediation();
    await screen.findByText("CTX-7 is in progress.");
    expect(screen.queryByRole("button", { name: /Create a remediation task/ })).not.toBeInTheDocument();
  });
});
