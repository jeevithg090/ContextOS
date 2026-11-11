import { boardToItems, findContainer, moveToContainer, placementChanged, placementOf, reorderWithin, type ColumnItems } from "../dnd";
import { makeCard, makeColumn } from "./fixtures";

const items = (): ColumnItems => ({ todo: ["a", "b", "c"], doing: ["d"], done: [] });

describe("board drag-and-drop helpers", () => {
  it("orders each column's ids by card position", () => {
    const columns = [
      makeColumn({ id: "todo", tasks: [makeCard({ id: "b", position: 1 }), makeCard({ id: "a", position: 0 })] }),
      makeColumn({ id: "done", tasks: [] }),
    ];
    expect(boardToItems({ columns })).toEqual({ todo: ["a", "b"], done: [] });
  });

  it("finds the column of a card or a column id", () => {
    expect(findContainer(items(), "c")).toBe("todo");
    expect(findContainer(items(), "done")).toBe("done");
    expect(findContainer(items(), "missing")).toBeNull();
  });

  it("appends when dropped on a column and inserts before or after a card", () => {
    expect(moveToContainer(items(), "a", "done")).toEqual({ todo: ["b", "c"], doing: ["d"], done: ["a"] });
    expect(moveToContainer(items(), "b", "d")).toEqual({ todo: ["a", "c"], doing: ["b", "d"], done: [] });
    expect(moveToContainer(items(), "b", "d", true)).toEqual({ todo: ["a", "c"], doing: ["d", "b"], done: [] });
  });

  it("does not change anything for a move within the same column", () => {
    const before = items();
    expect(moveToContainer(before, "a", "c")).toBe(before);
  });

  it("reorders within a column using sortable semantics", () => {
    expect(reorderWithin(items(), "a", "c").todo).toEqual(["b", "c", "a"]);
    expect(reorderWithin(items(), "c", "a").todo).toEqual(["c", "a", "b"]);
    const before = items();
    expect(reorderWithin(before, "a", "d")).toBe(before);
    expect(reorderWithin(before, "a", "todo")).toBe(before);
  });

  it("reports the index the move API expects and whether anything changed", () => {
    const before = items();
    const after = moveToContainer(before, "c", "d");
    expect(placementOf(after, "c")).toEqual({ columnId: "doing", index: 0 });
    expect(placementChanged(before, after, "c")).toBe(true);
    expect(placementChanged(before, before, "c")).toBe(false);
    expect(placementChanged(before, reorderWithin(before, "a", "b"), "a")).toBe(true);
  });

  it("keeps hidden (filtered-out) cards in place so positions stay real", () => {
    // Only "a" and "c" are visible; dropping "c" onto "a" must account for hidden "b".
    const next = reorderWithin(items(), "c", "a");
    expect(placementOf(next, "c")).toEqual({ columnId: "todo", index: 0 });
    expect(next.todo).toEqual(["c", "a", "b"]);
  });
});
