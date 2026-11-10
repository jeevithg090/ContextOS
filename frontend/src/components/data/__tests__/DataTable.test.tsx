import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { DataTable, type DataTableColumn } from "../DataTable";
import { EntityLink } from "../EntityLink";
import { compareValues, sortRows } from "../sorting";

interface Row {
  id: string;
  name: string;
  score: number | null;
  severity: "low" | "high" | "critical";
}

const ROWS: Row[] = [
  { id: "agt_b", name: "beta", score: 40, severity: "high" },
  { id: "agt_a", name: "Alpha", score: null, severity: "low" },
  { id: "agt_c", name: "gamma 10", score: 90, severity: "critical" },
  { id: "agt_d", name: "gamma 9", score: 5, severity: "low" },
];

const RANK = { low: 1, high: 3, critical: 4 } as const;

const COLUMNS: Array<DataTableColumn<Row>> = [
  { key: "name", header: "Name", sortable: true, render: (r) => <EntityLink type="agent" id={r.id} label={r.name} showIcon={false} /> },
  { key: "score", header: "Score", sortable: true, align: "right" },
  { key: "severity", header: "Severity", sortable: true, sortValue: (r) => RANK[r.severity] },
];

const names = () =>
  screen
    .getAllByRole("row")
    .slice(1)
    .map((row) => within(row).getAllByRole("cell")[0].textContent);

const renderTable = (props: Partial<React.ComponentProps<typeof DataTable<Row>>> = {}) =>
  render(
    <MemoryRouter>
      <DataTable<Row> columns={COLUMNS} rows={ROWS} rowKey={(r) => r.id} aria-label="Agents" {...props} />
    </MemoryRouter>,
  );

describe("DataTable sorting", () => {
  it("keeps API order until a header is clicked, then cycles asc → desc → none", () => {
    renderTable();
    expect(names()).toEqual(["beta", "Alpha", "gamma 10", "gamma 9"]);
    const header = screen.getByRole("columnheader", { name: /Name/ });
    const button = within(header).getByRole("button");

    fireEvent.click(button);
    expect(header).toHaveAttribute("aria-sort", "ascending");
    // Case-insensitive, numeric-aware collation: "gamma 9" before "gamma 10".
    expect(names()).toEqual(["Alpha", "beta", "gamma 9", "gamma 10"]);

    fireEvent.click(button);
    expect(header).toHaveAttribute("aria-sort", "descending");
    expect(names()).toEqual(["gamma 10", "gamma 9", "beta", "Alpha"]);

    fireEvent.click(button);
    expect(header).toHaveAttribute("aria-sort", "none");
    expect(names()).toEqual(["beta", "Alpha", "gamma 10", "gamma 9"]);
  });

  it("sorts numbers numerically and keeps empty values last in both directions", () => {
    renderTable();
    const button = within(screen.getByRole("columnheader", { name: /Score/ })).getByRole("button");
    fireEvent.click(button);
    expect(names()).toEqual(["gamma 9", "beta", "gamma 10", "Alpha"]);
    fireEvent.click(button);
    expect(names()).toEqual(["gamma 10", "beta", "gamma 9", "Alpha"]);
  });

  it("uses sortValue for ranked enums", () => {
    renderTable({ defaultSort: { key: "severity", direction: "desc" } });
    expect(names()[0]).toBe("gamma 10");
    expect(names().slice(-2).sort()).toEqual(["Alpha", "gamma 9"]);
  });

  it("does not reorder rows in manualSort mode but reports the requested sort", () => {
    const onSortChange = vi.fn();
    renderTable({ manualSort: true, sort: null, onSortChange });
    fireEvent.click(within(screen.getByRole("columnheader", { name: /Name/ })).getByRole("button"));
    expect(onSortChange).toHaveBeenCalledWith({ key: "name", direction: "asc" });
    expect(names()).toEqual(["beta", "Alpha", "gamma 10", "gamma 9"]);
  });
});

describe("DataTable states and interaction", () => {
  it("renders skeleton rows while loading without data", () => {
    renderTable({ rows: undefined, loading: true, skeletonRows: 3 });
    expect(screen.getByRole("table")).toHaveAttribute("aria-busy", "true");
    expect(screen.getAllByRole("row", { hidden: true })).toHaveLength(4);
  });

  it("renders the empty state", () => {
    renderTable({ rows: [], empty: { title: "No agents yet", description: "Connect an integration." } });
    expect(screen.getByText("No agents yet")).toBeInTheDocument();
    expect(screen.getByText("Connect an integration.")).toBeInTheDocument();
  });

  it("renders the error state with retry", () => {
    const onRetry = vi.fn();
    renderTable({ rows: undefined, error: new Error("boom"), onRetry });
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalled();
  });

  it("activates rows by click and keyboard, but not when an inner link is clicked", () => {
    const onRowClick = vi.fn();
    renderTable({ onRowClick, selectedKey: "agt_c" });
    const rows = screen.getAllByRole("row").slice(1);
    fireEvent.click(within(rows[0]).getByRole("cell", { name: "40" }));
    expect(onRowClick).toHaveBeenLastCalledWith(ROWS[0]);
    fireEvent.keyDown(rows[1], { key: "Enter" });
    expect(onRowClick).toHaveBeenLastCalledWith(ROWS[1]);
    expect(rows[2]).toHaveAttribute("aria-current", "true");
    onRowClick.mockClear();
    fireEvent.click(within(rows[3]).getByRole("link"));
    expect(onRowClick).not.toHaveBeenCalled();
  });
});

describe("sorting helpers", () => {
  it("is stable and does not mutate input", () => {
    const input = [
      { k: 1, v: "b" },
      { k: 2, v: "a" },
      { k: 3, v: "b" },
    ];
    const out = sortRows(input, (r) => r.v, "asc");
    expect(out.map((r) => r.k)).toEqual([2, 1, 3]);
    expect(input.map((r) => r.k)).toEqual([1, 2, 3]);
  });

  it("orders dates and booleans", () => {
    expect(compareValues(new Date("2024-01-02"), new Date("2024-01-01"), "asc")).toBeGreaterThan(0);
    expect(compareValues(false, true, "asc")).toBeLessThan(0);
    expect(compareValues(null, 1, "desc")).toBeGreaterThan(0);
  });
});
