import { fireEvent, screen, within } from "@testing-library/react";
import { KanbanBoard, type KanbanBoardProps } from "../KanbanBoard";
import { EMPTY_FILTERS } from "../boardMeta";
import { makeBoard, makeCard, makeColumn } from "./fixtures";
import { renderWithProviders } from "./testUtils";

function board() {
  return makeBoard([
    makeColumn({
      id: "col_todo",
      name: "To do",
      position: 0,
      tasks: [
        makeCard({ id: "tsk_1", key: "CTX-1", title: "Treat fetched web content as data", related_finding_id: "fnd_9" }),
        makeCard({ id: "tsk_2", key: "CTX-2", title: "Rotate leaked staging key", position: 1, priority: "urgent", is_overdue: true, due_date: "2026-11-01T23:59:59Z", blocked_by_open: 1 }),
      ],
    }),
    makeColumn({ id: "col_doing", name: "Fixing", position: 1, wip_limit: 1, tasks: [makeCard({ id: "tsk_3", key: "CTX-3", title: "Pin MCP server versions", column_id: "col_doing" })] }),
    makeColumn({ id: "col_verify", name: "Verified", position: 2, requires_verification: true, tasks: [] }),
    makeColumn({ id: "col_done", name: "Done", position: 3, is_done_column: true, status_key: "done", tasks: [] }),
  ]);
}

function renderBoard(overrides: Partial<KanbanBoardProps> = {}) {
  const props: KanbanBoardProps = {
    board: board(),
    filters: EMPTY_FILTERS,
    meId: "usr_1",
    canWrite: true,
    onOpenTask: vi.fn(),
    onAddColumn: vi.fn(),
    onEditColumn: vi.fn(),
    onDeleteColumn: vi.fn(),
    report: vi.fn(),
    ...overrides,
  };
  renderWithProviders(<KanbanBoard {...props} />);
  return props;
}

describe("KanbanBoard", () => {
  it("renders columns with counts against WIP limits and the verification gates", () => {
    renderBoard();
    const fixing = screen.getByRole("region", { name: "Column Fixing" });
    expect(within(fixing).getByLabelText("1 of 1 (WIP limit) — at the limit")).toHaveTextContent("1/1");
    // The gate column and the done column after it both refuse unverified work.
    expect(screen.getAllByLabelText("Requires passed verification")).toHaveLength(2);
    expect(screen.getByLabelText("Done column")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Column Verified" })).getByText("Tasks arrive here once a verification run has passed.")).toBeInTheDocument();
  });

  it("shows card evidence: key, priority, overdue date, blocked marker and the finding link", () => {
    renderBoard();
    const card = screen.getByRole("button", { name: "CTX-2: Rotate leaked staging key" });
    expect(within(card).getByText("CTX-2")).toBeInTheDocument();
    expect(within(card).getByText("Priority: Urgent")).toBeInTheDocument();
    expect(within(card).getByText("(overdue)")).toBeInTheDocument();
    expect(within(card).getByText("open blocking task")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open the finding linked to CTX-1" })).toHaveAttribute("href", "/intelligence/fnd_9");
  });

  it("opens a task on click and on Enter", () => {
    const props = renderBoard();
    fireEvent.click(screen.getByRole("button", { name: "CTX-1: Treat fetched web content as data" }));
    expect(props.onOpenTask).toHaveBeenCalledWith("tsk_1");
    fireEvent.keyDown(screen.getByRole("button", { name: "CTX-3: Pin MCP server versions" }), { key: "Enter", code: "Enter" });
    expect(props.onOpenTask).toHaveBeenCalledWith("tsk_3");
  });

  it("filters cards locally and says when a column's cards are hidden by the filters", () => {
    renderBoard({ filters: { ...EMPTY_FILTERS, q: "rotate" } });
    expect(screen.queryByText("Treat fetched web content as data")).not.toBeInTheDocument();
    expect(screen.getByText("Rotate leaked staging key")).toBeInTheDocument();
    const fixing = screen.getByRole("region", { name: "Column Fixing" });
    expect(within(fixing).getByText("No tasks here match the filters.")).toBeInTheDocument();
    expect(within(fixing).getByText("· 0 shown")).toBeInTheDocument();
  });

  it("hides editing controls for read-only users", () => {
    renderBoard({ canWrite: false });
    expect(screen.queryByRole("button", { name: "Add task" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add column" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Actions for column/ })).not.toBeInTheDocument();
  });

  it("offers quick-add and add-column to writers", () => {
    const props = renderBoard();
    expect(screen.getAllByRole("button", { name: "Add task" })).toHaveLength(4);
    fireEvent.click(screen.getByRole("button", { name: "Add column" }));
    expect(props.onAddColumn).toHaveBeenCalled();
  });
});
