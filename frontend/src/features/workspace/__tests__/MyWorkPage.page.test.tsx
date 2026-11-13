import { screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hang, page, renderPage, serverError, stubApi, type ApiCall, type ApiRoute, type Reply } from "@/test/pageHarness";
import { MyWorkPage } from "../MyWorkPage";
import type { TaskCard } from "../types";
import { DOCS_TASK, DONE_TASK, ROTATE_TASK } from "./pageFixtures";

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: () => true, refresh: async () => undefined, logout: async () => undefined }),
}));

afterEach(() => vi.unstubAllGlobals());

/**
 * The page asks /workspace/tasks four times for the signed-in user: open work (by priority), open
 * work by due date, the overdue count, and recent changes including done tasks.
 */
const isOverdueCount = (c: ApiCall) => c.query.get("overdue") === "true";
const isRecent = (c: ApiCall) => c.query.get("include_done") === "true";

function routes({ open = [ROTATE_TASK, DOCS_TASK], recent = [DONE_TASK, ROTATE_TASK], openReply }: { open?: TaskCard[]; recent?: TaskCard[]; openReply?: Reply } = {}): ApiRoute {
  return (c) => {
    if (c.path !== "/workspace/tasks") return undefined;
    if (isOverdueCount(c)) return { body: page(open.filter((t) => t.is_overdue).slice(0, 1), { total: open.filter((t) => t.is_overdue).length, limit: 1 }) };
    if (isRecent(c)) return { body: page(recent, { limit: 8 }) };
    return openReply ?? { body: page(open) };
  };
}

const renderMyWork = () => renderPage(<MyWorkPage />, { path: "/work/me", routePath: "/work/me" });

describe("MyWorkPage", () => {
  it("shows placeholders while my tasks load", () => {
    stubApi(routes({ openReply: hang }));
    renderMyWork();
    expect(screen.getByRole("heading", { name: "My Work" })).toBeInTheDocument();
    expect(screen.getByText("Assigned, open").nextSibling).toHaveTextContent("…");
    expect(screen.getAllByLabelText("Loading").length).toBeGreaterThan(0);
  });

  it("shows the server's error when my open tasks cannot load", async () => {
    stubApi(routes({ openReply: serverError("Task index unavailable") }));
    renderMyWork();
    expect(await screen.findByText("Task index unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("explains an empty queue and where to find work", async () => {
    stubApi(routes({ open: [], recent: [] }));
    renderMyWork();
    expect(await screen.findByText("Nothing open is assigned to you")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Untracked findings" })).toHaveAttribute("href", "/work/remediation?state=no_task");
    expect(screen.getByText("Nothing due this week")).toBeInTheDocument();
    expect(screen.getByText("No recent activity on your tasks")).toBeInTheDocument();
  });

  it("groups my open tasks by stage and counts what is overdue, due soon and blocked", async () => {
    const api = stubApi(routes());
    renderMyWork();
    const inProgress = await screen.findByRole("list", { name: "In progress tasks" });
    expect(within(inProgress).getByRole("link", { name: /CTX-7/ })).toHaveAttribute("href", "/work/tasks/tsk_rotate");
    expect(screen.getByRole("list", { name: "To do tasks" })).toHaveTextContent("Treat fetched vendor docs as data");

    expect(screen.getByText("Assigned, open").nextSibling).toHaveTextContent("2");
    expect(screen.getByText("Overdue").nextSibling).toHaveTextContent("1");
    expect(screen.getByText("Due in 7 days").nextSibling).toHaveTextContent("1");
    expect(screen.getByTitle("Open tasks waiting on another open task")).toHaveTextContent("Blocked1");

    const due = screen.getByRole("list", { name: "Tasks due soon" });
    expect(within(due).getAllByRole("link")).toHaveLength(2);
    expect(screen.getByRole("list", { name: "Recently updated tasks" })).toHaveTextContent("Restrict Bash uploads");
    expect(api.gets("/workspace/tasks").every((c) => c.query.get("assignee") === "me")).toBe(true);
  });
});
