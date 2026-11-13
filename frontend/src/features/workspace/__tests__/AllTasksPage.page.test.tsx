import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, page, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { AllTasksPage } from "../AllTasksPage";
import type { TaskCard } from "../types";
import { DOCS_TASK, LABEL, MEMBERS, ROTATE_TASK, boardSummary } from "./pageFixtures";

let permissions: string[] = ["read", "write"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => {
  permissions = ["read", "write"];
});
afterEach(() => vi.unstubAllGlobals());

function routes({ tasks = [ROTATE_TASK, DOCS_TASK], list }: { tasks?: TaskCard[]; list?: Reply } = {}): ApiRoute {
  return (c) => {
    if (c.path === "/workspace/tasks") return list ?? { body: page(tasks) };
    if (c.path === "/workspace/tasks/labels") return { body: [LABEL] };
    if (c.path === "/workspace/boards") return { body: page([boardSummary()], { limit: 500 }) };
    if (c.path === "/org/members") return { body: page(MEMBERS, { limit: 500 }) };
    return undefined;
  };
}

const renderTasks = (query = "") => renderPage(<AllTasksPage />, { path: `/work/tasks${query}`, routePath: "/work/tasks" });

describe("AllTasksPage", () => {
  it("shows a busy table while tasks load", () => {
    stubApi(routes({ list: hang }));
    renderTasks();
    expect(screen.getByRole("heading", { name: "All Tasks" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Tasks" })).toHaveAttribute("aria-busy", "true");
  });

  it("shows the server's error with a retry", async () => {
    stubApi(routes({ list: serverError("Task index unavailable") }));
    renderTasks();
    expect(await screen.findByText("Task index unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("explains how tasks appear when there are none", async () => {
    stubApi(routes({ tasks: [] }));
    renderTasks();
    expect(await screen.findByText("No open tasks yet")).toBeInTheDocument();
    expect(screen.getByText(/turn a security finding into a remediation task/)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Create task" }).length).toBe(2);
  });

  it("says when filters hide everything, and that done tasks are hidden", async () => {
    stubApi(routes({ tasks: [] }));
    renderTasks("?priority=urgent");
    expect(await screen.findByText("No tasks match these filters")).toBeInTheDocument();
    expect(screen.getByText(/Done tasks are hidden/)).toBeInTheDocument();
  });

  it("lists tasks with key, labels, progress, blockers, stage, board and priority, and opens one", async () => {
    stubApi(routes());
    renderTasks();
    const table = screen.getByRole("table", { name: "Tasks" });
    const row = (await within(table).findByText("Rotate the leaked deploy key")).closest("tr") as HTMLElement;
    expect(within(row).getByText("CTX-7")).toBeInTheDocument();
    expect(within(row).getByText("Critical")).toBeInTheDocument();
    expect(within(row).getByText("security")).toBeInTheDocument();
    expect(within(row).getByText("1/3 subtasks")).toBeInTheDocument();
    expect(within(row).getByText("Blocked by 1")).toBeInTheDocument();
    expect(within(row).getByText("In progress")).toBeInTheDocument();
    expect(within(row).getByText("Urgent")).toBeInTheDocument();
    expect(await within(row).findByText("Security remediation")).toBeInTheDocument();
    expect(within(row).getByText("(overdue)")).toBeInTheDocument();

    const docs = within(table).getByText("Treat fetched vendor docs as data").closest("tr") as HTMLElement;
    expect(within(docs).getByText("Failed")).toBeInTheDocument();

    fireEvent.click(row);
    await waitFor(() => expect(currentLocation()).toBe("/work/tasks/tsk_rotate"));
  });

  it("sends URL filters to the API and keeps them shareable", async () => {
    const api = stubApi(routes());
    renderTasks("?assignee=me&status=done");
    await screen.findByText("Rotate the leaked deploy key");
    const query = api.gets("/workspace/tasks").at(-1)!.query;
    expect(query.get("assignee")).toBe("me");
    expect(query.get("status_key")).toBe("done");
    expect(query.get("include_done")).toBe("true");
    expect(screen.getByRole("checkbox", { name: "Include done" })).toBeDisabled();
  });

  it("hides task creation from read-only users", async () => {
    permissions = ["read"];
    stubApi(routes({ tasks: [] }));
    renderTasks();
    expect(await screen.findByText("No open tasks yet")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create task" })).not.toBeInTheDocument();
  });
});
