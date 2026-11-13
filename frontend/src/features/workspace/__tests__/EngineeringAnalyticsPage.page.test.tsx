import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, page, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { EngineeringAnalyticsPage } from "../EngineeringAnalyticsPage";
import { ANALYTICS, EMPTY_ANALYTICS, boardSummary, stubResizeObserver } from "./pageFixtures";

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: () => true, refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => stubResizeObserver());
afterEach(() => vi.unstubAllGlobals());

function routes(analytics: Reply = { body: ANALYTICS }): ApiRoute {
  return (c) => {
    if (c.path === "/workspace/analytics") return analytics;
    if (c.path === "/workspace/boards") return { body: page([boardSummary()], { limit: 500 }) };
    return undefined;
  };
}

const renderAnalytics = (query = "") => renderPage(<EngineeringAnalyticsPage />, { path: `/work/analytics${query}`, routePath: "/work/analytics" });

/** The KPI tile whose label is `label`. */
function tile(label: string): HTMLElement {
  return screen.getByRole("button", { name: new RegExp(`^How "${label}" is calculated`) }).closest(".panel") as HTMLElement;
}

describe("EngineeringAnalyticsPage", () => {
  it("shows the KPI tiles loading", () => {
    stubApi(routes(hang));
    renderAnalytics();
    expect(screen.getByRole("heading", { name: "Engineering Analytics" })).toBeInTheDocument();
    // Tiles render skeletons inside a busy region until the numbers arrive.
    expect(tile("Open tasks").closest("[aria-busy]")).toHaveAttribute("aria-busy", "true");
    expect(within(tile("Open tasks")).queryByRole("link", { name: /All tasks/ })).not.toBeInTheDocument();
    expect(screen.queryByText(/^Computed /)).not.toBeInTheDocument();
  });

  it("shows the server's error with a retry", async () => {
    stubApi(routes(serverError("Analytics unavailable")));
    renderAnalytics();
    expect(await screen.findByText("Analytics unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("shows every metric with what was counted and links to the list behind it", async () => {
    stubApi(routes());
    renderAnalytics();
    expect(await within(tile("Open tasks")).findByText("6")).toBeInTheDocument();
    expect(within(tile("Open tasks")).getByText("1 overdue task")).toBeInTheDocument();
    expect(within(tile("Open tasks")).getByRole("link", { name: /All tasks/ })).toHaveAttribute("href", "/work/tasks");
    expect(within(tile("Median time to complete")).getByText("7.3 h")).toBeInTheDocument();
    expect(within(tile("Median time to complete")).getByText("mean 30 h · p90 3.0 d · 4 tasks")).toBeInTheDocument();
    expect(within(tile("Remediation completion")).getByText("50%")).toBeInTheDocument();
    expect(within(tile("Remediation completion")).getByText("2 of 4 findings with a linked task")).toBeInTheDocument();
    expect(within(tile("Awaiting remediation")).getByText("1 without a task · 2 in progress · 5 open")).toBeInTheDocument();
    expect(within(tile("Failed verification runs")).getByText("of 5 runs recorded in 30 days")).toBeInTheDocument();
    expect(within(tile("Reopened")).getByText("1 task reopened at least once")).toBeInTheDocument();
    expect(within(tile("Outstanding critical")).getByText("1 finding · 0 open tasks")).toBeInTheDocument();

    expect(screen.getByRole("link", { name: "Finding Credential sent to an unclassified host" })).toHaveAttribute("href", "/intelligence/fnd_exfil");
    expect(screen.getByText(/over the 30 days since/)).toBeInTheDocument();
  });

  it("explains empty breakdowns and an empty critical list", async () => {
    stubApi(routes({ body: EMPTY_ANALYTICS }));
    renderAnalytics();
    expect(await screen.findByText("Nothing critical is outstanding")).toBeInTheDocument();
    expect(within(tile("Remediation completion")).getByText("—")).toBeInTheDocument();
    expect(within(tile("Median time to complete")).getByText("—")).toBeInTheDocument();
    expect(screen.getAllByText("No open tasks.").length).toBe(3);
  });

  it("scopes task metrics to a board and changes the window through the URL", async () => {
    const api = stubApi(routes());
    renderAnalytics("?board_id=brd_1");
    expect(await screen.findByText("Task metrics are limited to this board; finding metrics always cover every board.")).toBeInTheDocument();
    expect(api.gets("/workspace/analytics")[0].query.get("board_id")).toBe("brd_1");
    fireEvent.click(screen.getByRole("radio", { name: "90d" }));
    await waitFor(() => expect(currentLocation()).toContain("window=90d"));
    await waitFor(() => expect(api.gets("/workspace/analytics").at(-1)?.query.get("window")).toBe("90d"));
  });
});
