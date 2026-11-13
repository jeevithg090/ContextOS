import { screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hang, makeMe, notFound, page, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { MEMBERS, ROTATE_TASK, makeBoard, makeColumn, makeTaskDetail } from "../../__tests__/pageFixtures";
import type { TaskDetail } from "../../types";
import { TaskPage } from "../TaskPage";

let permissions: string[] = ["read", "write"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: makeMe(permissions), loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => {
  permissions = ["read", "write"];
});
afterEach(() => vi.unstubAllGlobals());

const TASK: TaskDetail = makeTaskDetail({
  ...ROTATE_TASK,
  column: makeColumn({ id: "col_progress", name: "In progress", status_key: "in_progress" }),
  description: "The deploy key was read from .env and sent towards collector.example.",
  related_files: ["deploy/keys.tf"],
  acceptance_criteria: [
    { text: "Old key revoked", done: true },
    { text: "New key stored in the vault", done: false },
  ],
});

function routes(task: Reply = { body: TASK }): ApiRoute {
  return (c) => {
    if (c.path === "/workspace/tasks/tsk_rotate") return task;
    if (c.path === "/workspace/tasks/tsk_foreign") return notFound("Task");
    if (c.path === "/workspace/boards/brd_1") return { body: makeBoard([makeColumn({ id: "col_progress", name: "In progress", status_key: "in_progress" }), makeColumn({ id: "col_done", name: "Done", position: 1, is_done_column: true, status_key: "done" })]) };
    if (c.path === "/workspace/tasks/labels") return { body: [] };
    if (c.path === "/org/members") return { body: page(MEMBERS, { limit: 500 }) };
    return undefined;
  };
}

const renderTask = (id = "tsk_rotate") => renderPage(<TaskPage />, { path: `/work/tasks/${id}`, routePath: "/work/tasks/:taskId" });

describe("TaskPage", () => {
  it("shows a loading state while the task loads", () => {
    stubApi(routes(hang));
    renderTask();
    expect(screen.getByLabelText("Loading")).toHaveAttribute("aria-busy", "true");
  });

  it("says the task was not found for an unknown or foreign id, without retrying", async () => {
    const api = stubApi(routes());
    renderTask("tsk_foreign");
    expect(await screen.findByText("Task not found")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to all tasks" })).toHaveAttribute("href", "/work/tasks");
    expect(api.gets("/workspace/tasks/tsk_foreign")).toHaveLength(1);
  });

  it("shows the server's error for other failures", async () => {
    stubApi(routes(serverError("Task store unavailable")));
    renderTask();
    expect(await screen.findByText("Task store unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("shows the task with a breadcrumb back to its board and its definition", async () => {
    stubApi(routes());
    renderTask();
    const crumb = await screen.findByRole("navigation", { name: "Breadcrumb" });
    expect(crumb).toHaveTextContent("Security remediation/CTX-7");
    expect(screen.getByRole("link", { name: "Security remediation" })).toHaveAttribute("href", "/work/boards/brd_1");
    expect(screen.getByRole("button", { name: /Rotate the leaked deploy key/ })).toBeInTheDocument();
    expect(screen.getByText("The deploy key was read from .env and sent towards collector.example.")).toBeInTheDocument();
    expect(screen.getByText("deploy/keys.tf")).toBeInTheDocument();
    expect(screen.getByText("1/2 met")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Generate Fix Context" })).toHaveAttribute("href", "/work/fix-context/tsk_rotate");
    expect(await screen.findByRole("combobox", { name: "Move to column" })).toHaveValue("col_progress");
  });

  it("is read-only for viewers", async () => {
    permissions = ["read"];
    stubApi(routes());
    renderTask();
    expect(await screen.findByRole("heading", { name: "Rotate the leaked deploy key" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Break down" })).not.toBeInTheDocument();
  });
});
