import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { TestRouter } from "@/test/router";
import { ContextPacksPage } from "../ContextPacksPage";
import { FixContextPage } from "../FixContextPage";
import { PromptLibraryPage } from "../PromptLibraryPage";
import { CATALOGUE, DRAFT, PACK, page, SAVED, TASK, TASK_CATALOGUE, TEMPLATES } from "./fixtures";

let permissions = ["read", "write"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

type Call = { path: string; query: URLSearchParams; method: string; body?: Record<string, unknown> };
const calls: Call[] = [];
let override: (call: Call) => { status?: number; body?: unknown } | undefined;

function route(call: Call): { status?: number; body?: unknown } {
  const custom = override(call);
  if (custom) return custom;
  const { path, method } = call;
  if (path === "/workspace/ai/modes") return { body: call.query.get("task_id") === "tsk_1" ? TASK_CATALOGUE : CATALOGUE };
  if (path === "/workspace/ai/templates" && method === "GET") return { body: TEMPLATES };
  if (path === "/workspace/tasks" && method === "GET") return { body: page([TASK]) };
  if (path === "/workspace/tasks/tsk_1") return { body: TASK };
  if (path === "/workspace/ai/context-packs" && method === "GET") return { body: page([]) };
  if (path === "/workspace/ai/context-packs/cpk_1" && method === "GET") return { body: PACK };
  if (path === "/workspace/ai/fix-context") {
    return call.body?.save
      ? { status: 201, body: { ...DRAFT, prompt_id: "gpr_1", saved: true, version: 1, context_pack: PACK } }
      : { body: { ...DRAFT, mode: call.body?.mode, may_modify_files: call.body?.mode === "implement_fix" } };
  }
  if (path === "/workspace/ai/prompts" && method === "GET") return { body: page([SAVED]) };
  if (path === "/workspace/ai/prompts/gpr_1" && method === "GET") return { body: SAVED };
  if (path === "/workspace/tasks/tsk_1/fix-attempts") {
    return { status: 201, body: { id: "fat_1", task_id: "tsk_1", generated_prompt_id: "gpr_1", agent_tool: "other", status: "in_progress", is_claim_only: false } };
  }
  return { status: 404, body: { error: { code: "not_found", message: `No fixture for ${method} ${path}` } } };
}

beforeEach(() => {
  permissions = ["read", "write"];
  calls.length = 0;
  override = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input, "http://localhost");
      const call: Call = {
        path: url.pathname.replace(/^\/api\/v1/, ""),
        query: url.searchParams,
        method: init?.method ?? "GET",
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      };
      calls.push(call);
      const { status = 200, body } = route(call);
      return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <TestRouter initialEntries={[path]}>
        <TooltipProvider>
          <ToastProvider>
            <Routes>
              <Route path="/work/fix-context" element={<FixContextPage />} />
              <Route path="/work/fix-context/:taskId" element={<FixContextPage />} />
              <Route path="/work/prompts" element={<PromptLibraryPage />} />
              <Route path="/work/context-packs" element={<ContextPacksPage />} />
              <Route path="/work/tasks/:taskId" element={<div>Task page</div>} />
            </Routes>
          </ToastProvider>
        </TooltipProvider>
      </TestRouter>
    </QueryClientProvider>,
  );
}

const generateButton = async () => within(await screen.findByRole("complementary", { name: "Prompt configuration" })).getByRole("button", { name: /Generate/ });
const posts = (path: string) => calls.filter((c) => c.method === "POST" && c.path === path);

describe("FixContextPage", () => {
  it("starts by choosing a task and keeps the privacy note visible", async () => {
    renderAt("/work/fix-context");
    expect(screen.getByRole("note", { name: "Privacy" })).toHaveTextContent("Nothing is sent to an external AI provider. You copy the prompt into your coding agent.");
    fireEvent.click(await screen.findByRole("button", { name: /CTX-12/ }));
    expect(await screen.findByRole("heading", { name: TASK.title })).toBeInTheDocument();
  });

  it("generates a preview from the configuration, then saves it to the task", async () => {
    renderAt("/work/fix-context/tsk_1");
    fireEvent.click(await screen.findByRole("radio", { name: /Investigate only/ }));
    fireEvent.click(await generateButton());
    await waitFor(() => expect(posts("/workspace/ai/fix-context")).toHaveLength(1));
    const preview = posts("/workspace/ai/fix-context")[0].body!;
    expect(preview).toMatchObject({ task_id: "tsk_1", mode: "investigate_only", preset: "generic", profile: "standard" });
    expect(preview.save).toBeUndefined();
    expect((preview.options as Record<string, unknown>).allow_code_changes).toBe(false);

    expect(await screen.findByText("Unsaved preview")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Task summary" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Save to task/ }));
    await waitFor(() => expect(posts("/workspace/ai/fix-context")).toHaveLength(2));
    expect(posts("/workspace/ai/fix-context")[1].body).toMatchObject({ ...preview, save: true });
    expect(await screen.findByText("Saved to task · v1")).toBeInTheDocument();
    expect(screen.queryByText(/changed since this prompt was generated/)).not.toBeInTheDocument();
  });

  it("asks the server which pack profile suits the task and sends that profile", async () => {
    // The server, not a client-side rule, decides the suggestion (here: deep for implementing this task).
    override = (call) =>
      call.path === "/workspace/ai/modes" && call.query.get("task_id") === "tsk_1"
        ? { body: { ...TASK_CATALOGUE, suggested_profile: "deep", suggested_profiles: { ...TASK_CATALOGUE.suggested_profiles, implement_fix: "deep" } } }
        : undefined;
    renderAt("/work/fix-context/tsk_1");
    fireEvent.click(await generateButton());
    await waitFor(() => expect(posts("/workspace/ai/fix-context")).toHaveLength(1));
    expect(posts("/workspace/ai/fix-context")[0].body).toMatchObject({ mode: "implement_fix", profile: "deep" });
    expect(calls.some((c) => c.path === "/workspace/ai/modes" && c.query.get("task_id") === "tsk_1")).toBe(true);
  });

  it("saves a draft and records a fix attempt linked to the prompt", async () => {
    renderAt("/work/fix-context/tsk_1");
    fireEvent.click(await generateButton());
    fireEvent.click(await screen.findByRole("button", { name: /Save & start fix attempt/ }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByLabelText("Who runs the prompt")).toHaveValue("other");
    fireEvent.click(within(dialog).getByRole("button", { name: "Save prompt and start" }));
    await waitFor(() => expect(posts("/workspace/tasks/tsk_1/fix-attempts")).toHaveLength(1));
    expect(posts("/workspace/ai/fix-context").at(-1)!.body).toMatchObject({ save: true });
    expect(posts("/workspace/tasks/tsk_1/fix-attempts")[0].body).toMatchObject({ generated_prompt_id: "gpr_1", agent_tool: "other", status: "in_progress" });
    const banner = (await screen.findByText(/Fix attempt recorded \(in progress\) and linked to this prompt/)).closest("[role=status]") as HTMLElement;
    expect(within(banner).getByRole("link", { name: "Open task" })).toHaveAttribute("href", "/work/tasks/tsk_1");
  });

  it("opens a saved prompt with its stored pack and shows the pack's items", async () => {
    renderAt("/work/fix-context/tsk_1?prompt=gpr_1");
    expect(await screen.findByText("Saved to task · v1")).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByRole("tab", { name: /Context pack/ }));
    expect(await screen.findByText(/Excluded for safety/)).toBeInTheDocument();
    expect(screen.getByText("webhooks.py")).toBeInTheDocument();
  });

  it("explains a generation refusal in plain language", async () => {
    override = (c) => (c.path === "/workspace/ai/fix-context" ? { status: 422, body: { error: { code: "validation_failed", message: "Invalid", details: { errors: ["constraints: At most 30 constraints are allowed"] } } } } : undefined);
    renderAt("/work/fix-context/tsk_1");
    fireEvent.click(await generateButton());
    expect(await screen.findByText("The prompt could not be generated")).toBeInTheDocument();
    expect(screen.getByText("constraints: At most 30 constraints are allowed")).toBeInTheDocument();
  });

  it("says when the task does not exist", async () => {
    renderAt("/work/fix-context/tsk_missing");
    expect(await screen.findByText("Task not found")).toBeInTheDocument();
  });
});

describe("PromptLibraryPage", () => {
  it("lists built-in and organisation templates and deletes an organisation template after confirmation", async () => {
    override = (c) => (c.method === "DELETE" && c.path === "/workspace/ai/templates/pt_1" ? { status: 204 } : undefined);
    renderAt("/work/prompts");
    const org = await screen.findByRole("table", { name: "Organisation templates" });
    expect(await within(org).findByText("Strict security fix")).toBeInTheDocument();
    const builtin = screen.getByRole("table", { name: "Built-in templates" });
    expect(within(builtin).getAllByText("Investigate only").length).toBeGreaterThan(0);
    expect(within(builtin).queryByRole("button", { name: /Delete/ })).not.toBeInTheDocument();
    expect(within(builtin).getByRole("link", { name: "Use" })).toHaveAttribute("href", "/work/fix-context?template=builtin%3Ainvestigate_only");

    fireEvent.click(within(org).getByRole("button", { name: "Delete Strict security fix" }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete template" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.path === "/workspace/ai/templates/pt_1")).toBe(true));
  });

  it("shows saved prompts and opens one in a drawer with a link back to Fix Context", async () => {
    renderAt("/work/prompts?tab=prompts");
    const table = await screen.findByRole("table", { name: "Saved prompts" });
    fireEvent.click(await within(table).findByText(TASK.title));
    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByRole("link", { name: /Open in Fix Context/ })).toHaveAttribute("href", "/work/fix-context/tsk_1?prompt=gpr_1");
    expect(within(drawer).getByRole("note", { name: "Privacy" })).toBeInTheDocument();
  });

  it("hides template editing for read-only users", async () => {
    permissions = ["read"];
    renderAt("/work/prompts");
    await screen.findByRole("table", { name: "Organisation templates" });
    expect(screen.queryByRole("button", { name: "New template" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Delete Strict security fix/ })).not.toBeInTheDocument();
  });
});

describe("ContextPacksPage", () => {
  it("lists stored packs and opens one to inspect its items", async () => {
    override = (c) => (c.path === "/workspace/ai/context-packs" && c.method === "GET" ? { body: page([PACK]) } : undefined);
    renderAt("/work/context-packs");
    const table = await screen.findByRole("table", { name: "Context packs" });
    fireEvent.click(await within(table).findByText("Standard"));
    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByText("webhooks.py")).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: /Use in Fix Context/ })).toHaveAttribute("href", "/work/fix-context/tsk_1?pack=cpk_1");
  });

  it("shows an empty state with a way to build the first pack", async () => {
    renderAt("/work/context-packs");
    expect(await screen.findByText("No context packs yet")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Build pack" }).length).toBeGreaterThan(0);
  });
});
