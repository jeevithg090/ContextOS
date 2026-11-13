import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, makeMe, notFound, page, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { DOCS_TASK, LABEL, MEMBERS, ROTATE_TASK, makeBoard, makeColumn, makeTaskDetail } from "../../__tests__/pageFixtures";
import type { BoardDetail } from "../../types";
import { BoardPage } from "../BoardPage";

let permissions: string[] = ["read", "write"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: makeMe(permissions), loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => {
  permissions = ["read", "write"];
});
afterEach(() => vi.unstubAllGlobals());

const BOARD: BoardDetail = makeBoard(
  [
    makeColumn({ id: "col_todo", name: "To do", position: 0, tasks: [DOCS_TASK] }),
    makeColumn({ id: "col_progress", name: "In progress", position: 1, status_key: "in_progress", wip_limit: 1, tasks: [ROTATE_TASK] }),
    makeColumn({ id: "col_done", name: "Done", position: 2, status_key: "done", is_done_column: true, requires_verification: true, tasks: [] }),
  ],
  { description: "Fixes for findings raised by ContextOS." },
);

function routes(board: Reply = { body: BOARD }): ApiRoute {
  return (c) => {
    if (c.path === "/workspace/boards/brd_1") return board;
    if (c.path === "/workspace/boards/brd_foreign") return notFound("Board");
    if (c.path === "/workspace/tasks/labels") return { body: [LABEL] };
    if (c.path === "/workspace/tasks/tsk_docs") return { body: makeTaskDetail({ ...DOCS_TASK, column: makeColumn({ id: "col_todo", name: "To do" }) }) };
    if (c.path === "/org/members") return { body: page(MEMBERS, { limit: 500 }) };
    return undefined;
  };
}

const renderBoard = (id = "brd_1", query = "") => renderPage(<BoardPage />, { path: `/work/boards/${id}${query}`, routePath: "/work/boards/:boardId" });

describe("BoardPage", () => {
  it("shows a board skeleton while it loads", () => {
    stubApi(routes(hang));
    renderBoard();
    expect(screen.getByLabelText("Loading board")).toHaveAttribute("aria-busy", "true");
  });

  it("says the board was not found for an unknown or foreign id, without retrying", async () => {
    const api = stubApi(routes());
    renderBoard("brd_foreign");
    expect(await screen.findByText("Board not found")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to boards" })).toHaveAttribute("href", "/work/boards");
    expect(api.gets("/workspace/boards/brd_foreign")).toHaveLength(1);
  });

  it("shows the server's error for other failures", async () => {
    stubApi(routes(serverError("Board store unavailable")));
    renderBoard();
    expect(await screen.findByText("Board store unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("shows the board's columns, WIP limits, verification gate and cards", async () => {
    stubApi(routes());
    renderBoard();
    expect(await screen.findByRole("heading", { name: /Security remediation/ })).toBeInTheDocument();
    expect(screen.getByText("Fixes for findings raised by ContextOS.")).toBeInTheDocument();
    expect(screen.getByText("Open").nextSibling).toHaveTextContent("2");
    expect(screen.getByText("Columns").nextSibling).toHaveTextContent("3");

    const progress = screen.getByRole("region", { name: "Column In progress" });
    expect(within(progress).getByLabelText("1 of 1 (WIP limit) — at the limit")).toHaveTextContent("1/1");
    const card = within(progress).getByRole("button", { name: "CTX-7: Rotate the leaked deploy key" });
    expect(within(card).getByText("Priority: Urgent")).toBeInTheDocument();
    expect(within(card).getByText("(overdue)")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open the finding linked to CTX-7" })).toHaveAttribute("href", "/intelligence/fnd_exfil");
    expect(within(screen.getByRole("region", { name: "Column Done" })).getByLabelText("Requires passed verification")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Board settings" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New task" })).toBeInTheDocument();
  });

  it("opens a task in the drawer through the URL", async () => {
    stubApi(routes());
    renderBoard();
    fireEvent.click(await screen.findByRole("button", { name: "CTX-9: Treat fetched vendor docs as data" }));
    await waitFor(() => expect(currentLocation()).toBe("/work/boards/brd_1?task=tsk_docs"));
    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByRole("link", { name: "Generate Fix Context" })).toHaveAttribute("href", "/work/fix-context/tsk_docs");
    expect(within(drawer).getByRole("button", { name: /Treat fetched vendor docs as data/ })).toBeInTheDocument();
  });

  it("explains a board without columns", async () => {
    stubApi(routes({ body: makeBoard([]) }));
    renderBoard();
    expect(await screen.findByText("This board has no columns")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add column" })).toBeInTheDocument();
  });

  it("marks an archived board read-only and offers to restore it", async () => {
    stubApi(routes({ body: { ...BOARD, archived_at: "2026-11-01T00:00:00Z" } }));
    renderBoard();
    expect(await screen.findByText(/This board is archived/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Restore board" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New task" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add task" })).not.toBeInTheDocument();
  });
});
