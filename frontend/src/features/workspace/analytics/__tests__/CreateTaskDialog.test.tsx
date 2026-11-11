import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes, useLocation } from "react-router-dom";
import { makeBoard, makeColumn, makeTaskDetail } from "../../boards/__tests__/fixtures";
import { renderWithProviders, stubFetch } from "../../boards/__tests__/testUtils";
import { CreateTaskDialog } from "../CreateTaskDialog";

const board = makeBoard([makeColumn({ id: "col_todo", name: "To do" })]);

function stub() {
  return stubFetch({
    "GET /workspace/boards": { items: [board], total: 1, limit: 500, offset: 0 },
    "GET /workspace/boards/brd_1": board,
    "POST /workspace/tasks": (body: unknown) => ({ status: 201, body: makeTaskDetail({ id: "tsk_new", key: "SEC-9", ...(body as object) }) }),
  });
}

function Where() {
  const location = useLocation();
  return <output aria-label="location">{location.pathname}</output>;
}

async function fillAndSubmit() {
  fireEvent.change(await screen.findByLabelText("Title"), { target: { value: "Rotate leaked token" } });
  await waitFor(() => expect(screen.getByLabelText("Column")).toHaveValue("col_todo"));
  fireEvent.click(screen.getByRole("button", { name: "Create task" }));
}

afterEach(() => vi.unstubAllGlobals());

describe("CreateTaskDialog", () => {
  it("hands the new task id to onCreated instead of navigating", async () => {
    const { calls } = stub();
    const onCreated = vi.fn();
    const onOpenChange = vi.fn();
    renderWithProviders(
      <Routes>
        <Route path="*" element={<><CreateTaskDialog open onOpenChange={onOpenChange} boardId="brd_1" onCreated={onCreated} /><Where /></>} />
      </Routes>,
      { route: "/work/boards/brd_1" },
    );
    await fillAndSubmit();
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith("tsk_new"));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(screen.getByLabelText("location")).toHaveTextContent("/work/boards/brd_1");
    expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ title: "Rotate leaked token", board_id: "brd_1", column_id: "col_todo" });
  });

  it("opens the task page when no onCreated callback is given", async () => {
    stub();
    renderWithProviders(
      <Routes>
        <Route path="*" element={<><CreateTaskDialog open onOpenChange={() => undefined} boardId="brd_1" /><Where /></>} />
      </Routes>,
      { route: "/work/tasks" },
    );
    await fillAndSubmit();
    await waitFor(() => expect(screen.getByLabelText("location")).toHaveTextContent("/work/tasks/tsk_new"));
  });
});
