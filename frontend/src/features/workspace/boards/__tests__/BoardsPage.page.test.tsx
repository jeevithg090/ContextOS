import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, page, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { boardSummary } from "../../__tests__/pageFixtures";
import { BoardsPage } from "../BoardsPage";

let permissions: string[] = ["read", "write"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => {
  permissions = ["read", "write"];
});
afterEach(() => vi.unstubAllGlobals());

const DEFAULT_BOARD = boardSummary();
const BUG_BOARD = boardSummary({ id: "brd_bugs", name: "Agent bugs", description: null, template: "bug_tracking", is_default: false, column_count: 4, task_count: 4, open_task_count: 1 });
const ARCHIVED_BOARD = boardSummary({ id: "brd_old", name: "Q3 hardening", template: "technical_debt", is_default: false, archived_at: "2026-10-01T00:00:00Z", task_count: 0, open_task_count: 0 });

function routes(reply?: Reply): ApiRoute {
  return (c) => {
    if (c.path !== "/workspace/boards") return undefined;
    if (reply) return reply;
    const archived = c.query.get("include_archived") === "true";
    return { body: page(archived ? [BUG_BOARD, ARCHIVED_BOARD, DEFAULT_BOARD] : [BUG_BOARD, DEFAULT_BOARD], { limit: 500 }) };
  };
}

const renderBoards = (query = "") => renderPage(<BoardsPage />, { path: `/work/boards${query}`, routePath: "/work/boards" });

describe("BoardsPage", () => {
  it("shows placeholder tiles while boards load", () => {
    stubApi(routes(hang));
    renderBoards();
    expect(screen.getByRole("heading", { name: "Kanban boards" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Loading boards" })).toHaveAttribute("aria-busy", "true");
  });

  it("shows the server's error with a retry", async () => {
    stubApi(routes(serverError("Board store unavailable")));
    renderBoards();
    expect(await screen.findByText("Board store unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("explains how to start when there are no active boards", async () => {
    stubApi(routes({ body: page([]) }));
    renderBoards();
    expect(await screen.findByText("No active boards")).toBeInTheDocument();
    expect(screen.getByText("Create a board from a template to start tracking engineering and remediation work.")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "New board" }).length).toBe(2);
  });

  it("shows each board with its template, open and total counts, default board first", async () => {
    stubApi(routes());
    renderBoards();
    const grid = await screen.findByRole("list", { name: "Boards" });
    const tiles = within(grid).getAllByRole("listitem");
    expect(tiles[0]).toHaveTextContent("Security remediation");
    expect(within(tiles[0]).getByText("Default")).toBeInTheDocument();
    expect(within(tiles[0]).getByText("6")).toBeInTheDocument();
    expect(within(tiles[0]).getByText("open of 8")).toBeInTheDocument();
    expect(within(tiles[0]).getByText("2/8 done")).toBeInTheDocument();
    expect(within(tiles[0]).getByRole("link", { name: "Security remediation" })).toHaveAttribute("href", "/work/boards/brd_1");
    expect(within(tiles[1]).getByText("Bug tracking")).toBeInTheDocument();
    expect(within(tiles[1]).getByText("No description.")).toBeInTheDocument();
    expect(screen.getByText("2 boards")).toBeInTheDocument();
  });

  it("switches to the list layout and includes archived boards on request", async () => {
    const api = stubApi(routes());
    renderBoards();
    await screen.findByRole("list", { name: "Boards" });
    fireEvent.click(screen.getByRole("radio", { name: /List/ }));
    await waitFor(() => expect(currentLocation()).toContain("view=list"));
    const row = screen.getByRole("link", { name: "Agent bugs" }).closest("tr") as HTMLElement;
    expect(within(row).getByText("Bug tracking")).toBeInTheDocument();
    expect(within(row).getByText("3/4 done")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("checkbox", { name: "Show archived" }));
    const archived = await screen.findByRole("link", { name: "Q3 hardening" });
    expect(within(archived.closest("tr") as HTMLElement).getByText("Archived")).toBeInTheDocument();
    expect(api.gets("/workspace/boards").at(-1)?.query.get("include_archived")).toBe("true");
    // Archived boards sort after active ones.
    const names = screen.getAllByRole("link").map((l) => l.textContent);
    expect(names.indexOf("Q3 hardening")).toBeGreaterThan(names.indexOf("Security remediation"));
  });

  it("hides board creation from read-only users", async () => {
    permissions = ["read"];
    stubApi(routes({ body: page([]) }));
    renderBoards();
    expect(await screen.findByText("No active boards")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New board" })).not.toBeInTheDocument();
  });
});
