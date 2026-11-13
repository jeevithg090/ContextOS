import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, notFound, page, renderPage, serverError, stubApi, type ApiCall, type ApiRoute, type Reply } from "@/test/pageHarness";
import { ApprovalCentrePage } from "../ApprovalCentrePage";
import type { Approval } from "../types";
import { DECIDED, PENDING, detailOf } from "./pageFixtures";

let permissions: string[] = ["read", "approve"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

const originalScrollIntoView = Element.prototype.scrollIntoView;
beforeEach(() => {
  permissions = ["read", "approve"];
  // jsdom has no layout: the queue scrolls the selected request into view.
  Element.prototype.scrollIntoView = vi.fn();
});
afterEach(() => {
  Element.prototype.scrollIntoView = originalScrollIntoView;
  vi.unstubAllGlobals();
});

/** The queue asks for pending requests; the history tab (and its count badge) for decided ones. */
const isQueue = (c: ApiCall) => c.query.getAll("status").includes("pending");

function routes({ queue = [PENDING], history = [DECIDED], queueReply }: { queue?: Approval[]; history?: Approval[]; queueReply?: Reply } = {}): ApiRoute {
  return (c) => {
    if (c.path === "/approvals") return isQueue(c) ? (queueReply ?? { body: page(queue, { limit: 100 }) }) : { body: page(history, { limit: 25 }) };
    const known = [...queue, ...history].find((a) => c.path === `/approvals/${a.id}`);
    if (known) return { body: detailOf(known) };
    if (c.path.startsWith("/approvals/")) return notFound("Approval");
    return undefined;
  };
}

const renderCentre = (query = "") => renderPage(<ApprovalCentrePage />, { path: `/approvals${query}`, routePath: "/approvals" });

describe("ApprovalCentrePage", () => {
  it("shows the queue loading", () => {
    stubApi(routes({ queueReply: hang }));
    renderCentre();
    expect(screen.getByRole("heading", { name: "Approval Centre" })).toBeInTheDocument();
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    expect(screen.getAllByLabelText("Loading").length).toBeGreaterThan(0);
  });

  it("shows the server's error when the queue cannot load", async () => {
    stubApi(routes({ queueReply: serverError("Approval queue unavailable") }));
    renderCentre();
    expect(await screen.findByText("Couldn’t load this view")).toBeInTheDocument();
    expect(screen.getByText("Approval queue unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("explains how requests arise when nothing is waiting", async () => {
    stubApi(routes({ queue: [] }));
    renderCentre();
    expect(await screen.findByText("Nothing is waiting for a human")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Review approval policies" })).toHaveAttribute("href", "/policies");
    // The history badge counts decided requests from the server's total.
    expect(screen.getByRole("tab", { name: /History/ })).toHaveTextContent("1");
    fireEvent.click(screen.getByRole("button", { name: "See past decisions" }));
    await waitFor(() => expect(currentLocation()).toContain("tab=history"));
  });

  it("selects the oldest request and shows what it wants, why it was paused and the decision controls", async () => {
    stubApi(routes());
    renderCentre();
    expect(await screen.findByText("1 waiting · oldest first")).toBeInTheDocument();
    const queue = screen.getByRole("listbox", { name: "Requests waiting for a decision" });
    expect(within(queue).getByText("send POST to collector.example")).toBeInTheDocument();
    expect(within(queue).getByText("Approve outbound requests from production")).toBeInTheDocument();
    await waitFor(() => expect(currentLocation()).toContain("approval=apr_pending"));
    expect(within(queue).getByRole("option")).toHaveAttribute("aria-selected", "true");

    expect(await screen.findByRole("heading", { name: "payments-coder wants to send POST to collector.example" })).toBeInTheDocument();
    expect(screen.getByText(/approving lets it run, rejecting makes the hook deny it/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Approve/ })).toBeEnabled();
    expect(screen.getByRole("button", { name: /Reject/ })).toBeEnabled();
    const why = screen.getByRole("region", { name: "Why ContextOS paused it" });
    expect(within(why).getByText("Needs approval")).toBeInTheDocument();
    expect(within(why).getByText("Enforced")).toBeInTheDocument();
    expect(within(why).getByText(/agent\.environment is production/)).toBeInTheDocument();
    // Redacted arguments are shown exactly as stored.
    expect(screen.getByText(/\[REDACTED:github_token:1a2b3c4d\]/)).toBeInTheDocument();
  });

  it("explains the missing permission instead of offering decision buttons", async () => {
    permissions = ["read"];
    stubApi(routes());
    renderCentre();
    expect(await screen.findByRole("heading", { name: /wants to send POST to collector\.example/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Approve/ })).not.toBeInTheDocument();
    expect(screen.getByText(/needs the/)).toBeInTheDocument();
  });

  it("says a linked request does not exist for an unknown or foreign id", async () => {
    stubApi(routes());
    renderCentre("?approval=apr_foreign");
    expect(await screen.findByText("Request not found")).toBeInTheDocument();
    expect(screen.getByText(/may belong to another organisation/)).toBeInTheDocument();
  });

  it("lists past decisions with who decided and opens one in a side panel", async () => {
    stubApi(routes());
    renderCentre("?tab=history");
    const table = screen.getByRole("table", { name: "Decided and expired approval requests" });
    const row = (await within(table).findByText("run curl upload.example")).closest("tr") as HTMLElement;
    expect(within(row).getByText("Rejected")).toBeInTheDocument();
    expect(within(row).getByText("Ada Analyst")).toBeInTheDocument();
    expect(within(row).getByText("“Not an expected destination”")).toBeInTheDocument();
    expect(within(row).getByText("waited 30s")).toBeInTheDocument();

    fireEvent.click(row);
    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByRole("heading", { name: "payments-coder wants to run curl upload.example" })).toBeInTheDocument();
    expect(within(drawer).queryByRole("button", { name: /Approve/ })).not.toBeInTheDocument();
    expect(currentLocation()).toContain("approval=apr_decided");
  });

  it("explains an empty history", async () => {
    stubApi(routes({ history: [] }));
    renderCentre("?tab=history");
    expect(await screen.findByText("No decisions yet")).toBeInTheDocument();
    expect(screen.getByText(/Approved, rejected and expired requests are listed here/)).toBeInTheDocument();
  });
});
