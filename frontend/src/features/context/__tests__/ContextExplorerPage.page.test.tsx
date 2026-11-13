import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, notFound, page, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { ContextExplorerPage } from "../ContextExplorerPage";
import type { ContextItemSummary, ContextSourceSummary } from "../types";
import { ITEM, SECRET_ITEM, SOURCE, facets } from "./pageFixtures";

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: () => true, refresh: async () => undefined, logout: async () => undefined }),
}));

afterEach(() => vi.unstubAllGlobals());

function routes({ items = [ITEM, SECRET_ITEM], simulated = 0, sources = [SOURCE], itemsReply }: { items?: ContextItemSummary[]; simulated?: number; sources?: ContextSourceSummary[]; itemsReply?: Reply } = {}): ApiRoute {
  return (c) => {
    if (c.path === "/context/items") return itemsReply ?? { body: page(items) };
    if (c.path === "/context/facets") return { body: facets(items, simulated) };
    if (c.path === "/context/sources") return { body: page(sources) };
    if (c.path.startsWith("/context/items/")) return notFound("Context item");
    return undefined;
  };
}

const renderExplorer = (query = "") => renderPage(<ContextExplorerPage />, { path: `/context${query}`, routePath: "/context" });

describe("ContextExplorerPage — items", () => {
  it("shows a busy table while context loads", () => {
    stubApi(routes({ itemsReply: hang }));
    renderExplorer();
    expect(screen.getByRole("heading", { name: "What information entered my agents?" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Context items" })).toHaveAttribute("aria-busy", "true");
  });

  it("shows the server's error with a retry", async () => {
    stubApi(routes({ itemsReply: serverError("Context store unavailable") }));
    renderExplorer();
    expect(await screen.findByText("Context store unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("explains where context comes from when nothing was recorded", async () => {
    stubApi(routes({ items: [] }));
    renderExplorer();
    expect(await screen.findByText("No context has been recorded yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Connect an integration" })).toHaveAttribute("href", "/integrations");
  });

  it("says simulated items are hidden and shows them on request", async () => {
    const api = stubApi(routes({ items: [], simulated: 3 }));
    renderExplorer();
    expect(await screen.findByText("No real agent activity recorded yet")).toBeInTheDocument();
    expect(screen.getByText(/3 simulated items from the Simulation Lab are hidden/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show simulated items" }));
    await waitFor(() => expect(currentLocation()).toContain("sim=1"));
    await waitFor(() => expect(api.gets("/context/items").at(-1)?.query.get("include_simulated")).toBe("true"));
  });

  it("lists items with trust at ingest, detections, sensitivity and their agent and session", async () => {
    stubApi(routes());
    renderExplorer();
    const table = screen.getByRole("table", { name: "Context items" });
    const row = (await within(table).findByText("Vendor setup guide")).closest("tr") as HTMLElement;
    expect(within(row).getByText("External")).toBeInTheDocument();
    expect(within(row).getByText("High")).toBeInTheDocument();
    expect(within(row).getByText("2 hits")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: "Agent payments-coder" })).toHaveAttribute("href", "/agents/agt_payments");
    expect(within(row).getByRole("link", { name: "Session sess-7f3a" })).toHaveAttribute("href", "/sessions/ses_main");

    const secret = within(table).getByText("/work/payments/.env").closest("tr") as HTMLElement;
    expect(within(secret).getByText("Trusted")).toBeInTheDocument();
    expect(within(secret).getByLabelText("Contains secrets")).toBeInTheDocument();
    expect(within(secret).getByText("None")).toBeInTheDocument();
    expect(screen.getByText("2 items")).toBeInTheDocument();

    const chips = screen.getByRole("group", { name: "Filter by trust at ingest" });
    expect(within(chips).getByRole("button", { name: /All/ })).toHaveAttribute("aria-pressed", "true");
  });

  it("opens an item drawer from a row and says when the item no longer exists", async () => {
    stubApi(routes());
    renderExplorer();
    fireEvent.click((await screen.findByText("Vendor setup guide")).closest("tr") as HTMLElement);
    await waitFor(() => expect(currentLocation()).toContain("item=ctx_readme"));
    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByText("Context item not found")).toBeInTheDocument();
  });
});

describe("ContextExplorerPage — sources", () => {
  it("lists where context came from with current trust and reach", async () => {
    stubApi(routes());
    renderExplorer("?view=sources");
    const table = screen.getByRole("table", { name: "Context sources" });
    const row = (await within(table).findByText("Vendor setup guide")).closest("tr") as HTMLElement;
    expect(within(row).getByText("Suspicious")).toBeInTheDocument();
    expect(within(row).getByText("Manual")).toBeInTheDocument();
    expect(within(row).getByText("2 agents · 3 sessions")).toBeInTheDocument();
    expect(within(row).getByText("1 open / 2")).toBeInTheDocument();
    expect(screen.getByText("1 sources")).toBeInTheDocument();
  });

  it("explains that simulation-only sources are hidden when there are none", async () => {
    stubApi(routes({ sources: [] }));
    renderExplorer("?view=sources");
    expect(await screen.findByText("No sources from real agent activity yet")).toBeInTheDocument();
    expect(screen.getByText(/Sources seen only by Simulation Lab runs are hidden/)).toBeInTheDocument();
  });

  it("shows the server's error for the sources list", async () => {
    stubApi((c) => (c.path === "/context/sources" ? serverError("Source index unavailable") : routes()(c)));
    renderExplorer("?view=sources");
    expect(await screen.findByText("Source index unavailable")).toBeInTheDocument();
  });
});
