/**
 * Pure helpers for multi-column drag and drop. Columns hold the FULL ordered list of task ids (not
 * just the cards visible under the current filters) so the index sent to the server is the card's
 * real position in its column.
 */
import type { BoardDetail } from "../types";

/** columnId → ordered task ids. */
export type ColumnItems = Record<string, string[]>;

export function boardToItems(board: Pick<BoardDetail, "columns">): ColumnItems {
  const items: ColumnItems = {};
  for (const column of board.columns) {
    items[column.id] = [...column.tasks].sort((a, b) => a.position - b.position).map((t) => t.id);
  }
  return items;
}

/** The column an id belongs to: the id itself when it is a column, else the column holding it. */
export function findContainer(items: ColumnItems, id: string): string | null {
  if (id in items) return id;
  for (const [columnId, ids] of Object.entries(items)) if (ids.includes(id)) return columnId;
  return null;
}

/**
 * Move `activeId` into the column of `overId` (a card or a column). Dropping on a column appends;
 * dropping on a card inserts before it, or after it when `placeBelow` is true.
 * Returns the same object when nothing changes.
 */
export function moveToContainer(items: ColumnItems, activeId: string, overId: string, placeBelow = false): ColumnItems {
  const from = findContainer(items, activeId);
  const to = findContainer(items, overId);
  if (!from || !to || from === to) return items;
  const source = items[from].filter((id) => id !== activeId);
  const target = items[to].filter((id) => id !== activeId);
  let index = target.length;
  if (overId !== to) {
    const overIndex = target.indexOf(overId);
    if (overIndex >= 0) index = overIndex + (placeBelow ? 1 : 0);
  }
  return { ...items, [from]: source, [to]: [...target.slice(0, index), activeId, ...target.slice(index)] };
}

/** Reorder within one column so `activeId` takes `overId`'s place (dnd-kit sortable semantics). */
export function reorderWithin(items: ColumnItems, activeId: string, overId: string): ColumnItems {
  const column = findContainer(items, activeId);
  if (!column || findContainer(items, overId) !== column || overId === column) return items;
  const ids = items[column];
  const from = ids.indexOf(activeId);
  const to = ids.indexOf(overId);
  if (from < 0 || to < 0 || from === to) return items;
  const next = [...ids];
  next.splice(from, 1);
  next.splice(to, 0, activeId);
  return { ...items, [column]: next };
}

/** Where a task ended up: its column and index (the index the move API expects). */
export function placementOf(items: ColumnItems, taskId: string): { columnId: string; index: number } | null {
  const columnId = findContainer(items, taskId);
  if (!columnId || columnId === taskId) return null;
  return { columnId, index: items[columnId].indexOf(taskId) };
}

/** Whether two placements differ (same column and index means the drop was a no-op). */
export function placementChanged(before: ColumnItems, after: ColumnItems, taskId: string): boolean {
  const a = placementOf(before, taskId);
  const b = placementOf(after, taskId);
  return !a || !b || a.columnId !== b.columnId || a.index !== b.index;
}
