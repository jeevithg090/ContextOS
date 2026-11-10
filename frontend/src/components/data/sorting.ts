export type SortDirection = "asc" | "desc";
export interface SortState {
  key: string;
  direction: SortDirection;
}

export type SortValue = string | number | boolean | Date | null | undefined;

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

/**
 * Compare two cell values. Empty values (null, undefined, "") always sort last regardless of
 * direction, so "missing" never masquerades as the top result.
 */
export function compareValues(a: SortValue, b: SortValue, direction: SortDirection): number {
  const aEmpty = a === null || a === undefined || a === "";
  const bEmpty = b === null || b === undefined || b === "";
  if (aEmpty || bEmpty) return aEmpty === bEmpty ? 0 : aEmpty ? 1 : -1;
  let result: number;
  if (a instanceof Date || b instanceof Date) {
    result = new Date(a as Date).getTime() - new Date(b as Date).getTime();
  } else if (typeof a === "number" && typeof b === "number") {
    result = a - b;
  } else if (typeof a === "boolean" && typeof b === "boolean") {
    result = Number(a) - Number(b);
  } else {
    result = collator.compare(String(a), String(b));
  }
  return direction === "asc" ? result : -result;
}

/** Stable sort that never mutates the input. */
export function sortRows<T>(rows: readonly T[], getValue: (row: T) => SortValue, direction: SortDirection): T[] {
  return rows
    .map((row, index) => ({ row, index, value: getValue(row) }))
    .sort((x, y) => compareValues(x.value, y.value, direction) || x.index - y.index)
    .map((entry) => entry.row);
}

/** Header click cycle: unsorted → ascending → descending → unsorted. */
export function nextSort(current: SortState | null, key: string): SortState | null {
  if (!current || current.key !== key) return { key, direction: "asc" };
  if (current.direction === "asc") return { key, direction: "desc" };
  return null;
}
