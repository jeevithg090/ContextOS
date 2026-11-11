import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { makeTaskDetail } from "../../boards/__tests__/fixtures";
import { renderWithProviders, stubFetch } from "../../boards/__tests__/testUtils";
import { BreakdownDialog } from "../BreakdownDialog";

const drafts = [
  { title: "Reproduce the injection", description: "Write a failing test.", task_type: "prompt_injection", acceptance_criteria: ["Test fails before the fix"], testing_requirements: ["pytest"], depends_on: [] },
  { title: "Add content trust boundary", description: "Treat fetched text as data.", task_type: "backend", acceptance_criteria: ["Test passes"], testing_requirements: [], depends_on: [0] },
  { title: "Add regression scenario", description: "Simulation Lab scenario.", task_type: "task", acceptance_criteria: [], testing_requirements: [], depends_on: [0, 1] },
];

afterEach(() => vi.unstubAllGlobals());

describe("BreakdownDialog", () => {
  it("lets the user edit and remove drafts, then applies them with re-indexed dependencies", async () => {
    const { calls } = stubFetch({
      "POST /workspace/ai/breakdown": { task_id: "tsk_1", task_key: "CTX-1", plan: "security_fix", plans: ["security_fix", "generic"], drafts, existing_subtasks: 0, note: "Drafted from the task's acceptance criteria.", external_transfer: false },
      "POST /workspace/ai/breakdown/apply": () => ({ status: 201, body: { parent_task_id: "tsk_1", created: [{}, {}], dependencies: [{ task_id: "a", depends_on_task_id: "b" }] } }),
    });
    const onOpenChange = vi.fn();
    renderWithProviders(<BreakdownDialog task={makeTaskDetail()} open onOpenChange={onOpenChange} />);

    const title1 = await screen.findByLabelText("Subtask 1 title");
    expect(screen.getByText("Drafted from the task's acceptance criteria.")).toBeInTheDocument();
    expect(screen.getByText(/nothing is sent to an external AI provider/)).toBeInTheDocument();

    fireEvent.change(title1, { target: { value: "Reproduce the injection with a failing test" } });
    fireEvent.click(screen.getByRole("button", { name: "Remove subtask 2" }));
    expect(screen.queryByDisplayValue("Add content trust boundary")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Create 2 subtasks" }));
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
    const applied = calls.find((c) => c.path === "/workspace/ai/breakdown/apply")?.body as { drafts: Array<{ title: string; depends_on: number[] }>; task_id: string };
    expect(applied.task_id).toBe("tsk_1");
    expect(applied.drafts.map((d) => d.title)).toEqual(["Reproduce the injection with a failing test", "Add regression scenario"]);
    expect(applied.drafts[1].depends_on).toEqual([0]);
  });

  it("blocks applying while drafts depend on each other in a cycle", async () => {
    stubFetch({
      "POST /workspace/ai/breakdown": { task_id: "tsk_1", task_key: "CTX-1", plan: "generic", plans: ["generic"], drafts: drafts.slice(0, 2), existing_subtasks: 1, note: "", external_transfer: false },
    });
    renderWithProviders(<BreakdownDialog task={makeTaskDetail()} open onOpenChange={() => undefined} />);
    await screen.findByLabelText("Subtask 1 title");
    expect(screen.getByText(/already has 1 subtask/)).toBeInTheDocument();
    const first = screen.getByRole("group", { name: "Subtask 1 depends on" });
    fireEvent.click(within(first).getByRole("checkbox"));
    expect(screen.getByRole("alert")).toHaveTextContent("Subtasks 1, 2 depend on each other in a cycle");
    expect(screen.getByRole("button", { name: "Create 2 subtasks" })).toBeDisabled();
  });
});
