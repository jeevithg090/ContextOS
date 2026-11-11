import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { AuthProvider } from "@/features/auth/AuthProvider";
import { makeBoard, makeColumn, makeTaskDetail } from "../../boards/__tests__/fixtures";
import { renderWithProviders, stubFetch } from "../../boards/__tests__/testUtils";
import { TaskDetailView } from "../TaskDetailView";
import type { TaskDetail } from "../../types";

const me = {
  user: { id: "usr_1", email: "ada@example.com", name: "Ada Analyst" },
  organization: { id: "org_1", name: "Acme", slug: "acme" },
  role: "security_analyst",
  permissions: ["read", "write"],
  memberships: [],
};

function setup(task: TaskDetail = makeTaskDetail(), permissions = me.permissions) {
  const stub = stubFetch({
    "GET /auth/me": { ...me, permissions },
    "GET /workspace/boards/brd_1": makeBoard([makeColumn({ id: "col_todo", name: "To do" }), makeColumn({ id: "col_done", name: "Done", position: 1, is_done_column: true, status_key: "done" })]),
    "GET /org/members": { items: [{ id: "mem_1", user_id: "usr_1", name: "Ada Analyst", email: "ada@example.com", role: "security_analyst", is_active: true, created_at: "", last_login_at: null }], total: 1, limit: 500, offset: 0 },
    "GET /workspace/tasks/labels": [],
    "POST /workspace/tasks/tsk_1/verifications": (body: unknown) => ({
      status: 201,
      body: { id: "ver_1", task_id: "tsk_1", fix_attempt_id: null, ...(body as object), evidence: {}, simulation_run_id: null, created_by: null, created_at: "2026-11-10T12:00:00Z", task_verification_status: "passed" },
    }),
  });
  renderWithProviders(
    <AuthProvider>
      <TaskDetailView task={task} variant="page" />
    </AuthProvider>,
  );
  return stub;
}

afterEach(() => vi.unstubAllGlobals());

describe("TaskDetailView", () => {
  it("shows the task, its definition and the primary actions", async () => {
    setup();
    expect(await screen.findByRole("button", { name: /Treat fetched web content as data/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Generate Fix Context" })).toHaveAttribute("href", "/work/fix-context/tsk_1");
    expect(screen.getByRole("button", { name: "Break down" })).toBeInTheDocument();
    expect(screen.getByText("1/2 met")).toBeInTheDocument();
    expect(screen.getByText("backend/app/engines/detection/injection.py")).toBeInTheDocument();
    expect(await screen.findByRole("combobox", { name: "Move to column" })).toHaveValue("col_todo");
  });

  it("separates claims from verification and records a verification run", async () => {
    const { calls } = setup();
    await screen.findByRole("link", { name: "Generate Fix Context" });
    fireEvent.mouseDown(screen.getByRole("tab", { name: /Fix & verify/ }));
    const verification = await screen.findByRole("region", { name: /Verification/ });
    expect(within(verification).getByText("Not verified")).toBeInTheDocument();
    expect(screen.getAllByText(/It is a claim, not verification/).length).toBeGreaterThan(0);

    fireEvent.click(within(verification).getByRole("button", { name: "Record run" }));
    fireEvent.change(screen.getByLabelText("What was checked"), { target: { value: "Ran the injection regression suite: 14 passed." } });
    fireEvent.change(screen.getByLabelText("Command (optional)"), { target: { value: "pytest -q tests/security" } });
    fireEvent.click(screen.getByRole("button", { name: "Record verification" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/workspace/tasks/tsk_1/verifications")).toBe(true));
    const body = calls.find((c) => c.path === "/workspace/tasks/tsk_1/verifications")?.body;
    expect(body).toMatchObject({ kind: "test_run", status: "passed", summary: "Ran the injection regression suite: 14 passed.", command: "pytest -q tests/security" });
  });

  it("is read-only for viewers", async () => {
    setup(makeTaskDetail(), ["read"]);
    await screen.findByRole("link", { name: "Generate Fix Context" });
    expect(screen.queryByRole("button", { name: "Break down" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /edit title/ })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Treat fetched web content as data" })).toBeInTheDocument();
  });

  it("links each saved fix prompt to the Prompt Library", async () => {
    setup(makeTaskDetail({ generated_prompt_ids: ["gpr_01HZXAAAAAAAAAAAAAAAAAAAAB", "gpr_01HZXAAAAAAAAAAAAAAAAAAAAC"] }));
    await screen.findByRole("link", { name: "Generate Fix Context" });
    expect(screen.getByText("2 saved fix prompts:")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open saved prompt gpr_01HZXAAAAAAAAAAAAAAAAAAAAB" })).toHaveAttribute(
      "href",
      "/work/prompts?tab=prompts&prompt=gpr_01HZXAAAAAAAAAAAAAAAAAAAAB",
    );
    expect(screen.getByRole("link", { name: "Open saved prompt gpr_01HZXAAAAAAAAAAAAAAAAAAAAC" })).toHaveAttribute(
      "href",
      "/work/prompts?tab=prompts&prompt=gpr_01HZXAAAAAAAAAAAAAAAAAAAAC",
    );
  });

  it("shows no saved-prompt row when nothing was generated", async () => {
    setup();
    await screen.findByRole("link", { name: "Generate Fix Context" });
    expect(screen.queryByText(/saved fix prompt/)).not.toBeInTheDocument();
  });

  it("links recorded security context to the original records", async () => {
    setup(
      makeTaskDetail({
        refs: [
          { id: "tcr_1", task_id: "tsk_1", ref_type: "finding", ref_id: "fnd_1", note: "Origin", label: "Prompt injection in fetched page", detail: "high · open", exists: true, created_at: "2026-11-10T12:00:00Z" },
          { id: "tcr_2", task_id: "tsk_1", ref_type: "context_item", ref_id: "ctx_1", note: null, label: "docs page", detail: null, exists: false, created_at: "2026-11-10T12:00:00Z" },
        ],
      }),
    );
    await screen.findByRole("link", { name: "Generate Fix Context" });
    fireEvent.mouseDown(screen.getByRole("tab", { name: /Security context/ }));
    expect(await screen.findByRole("link", { name: "Finding Prompt injection in fetched page" })).toHaveAttribute("href", "/intelligence/fnd_1");
    expect(screen.getByText("Record deleted")).toBeInTheDocument();
  });
});
