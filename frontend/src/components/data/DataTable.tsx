import { useMemo, useState, type KeyboardEvent, type MouseEvent, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui";
import { cn } from "@/lib/format";
import { nextSort, sortRows, type SortState, type SortValue } from "./sorting";

export interface DataTableColumn<T> {
  key: string;
  header: ReactNode;
  /** Cell renderer. Without one, `row[key]` is shown as text. */
  render?: (row: T, index: number) => ReactNode;
  width?: string | number;
  align?: "left" | "right" | "center";
  sortable?: boolean;
  /** Value used for sorting; defaults to `row[key]`. */
  sortValue?: (row: T) => SortValue;
  /** Hide the column below a breakpoint to keep narrow screens readable. */
  hideBelow?: "sm" | "md" | "lg";
  className?: string;
  headerClassName?: string;
}

export interface DataTableProps<T> {
  columns: Array<DataTableColumn<T>>;
  rows: T[] | undefined | null;
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  loading?: boolean;
  skeletonRows?: number;
  error?: unknown;
  onRetry?: () => void;
  empty?: { title: string; description?: ReactNode; icon?: ReactNode; action?: ReactNode };
  defaultSort?: SortState | null;
  /** Controlled sort state (pair with onSortChange). */
  sort?: SortState | null;
  onSortChange?: (sort: SortState | null) => void;
  /** The server already sorted the rows (use with controlled sort for server-side ordering). */
  manualSort?: boolean;
  dense?: boolean;
  rowClassName?: (row: T) => string | undefined;
  "aria-label"?: string;
  className?: string;
}

const ALIGN = { left: "text-left", right: "text-right", center: "text-center" } as const;
const HIDE = { sm: "hidden sm:table-cell", md: "hidden md:table-cell", lg: "hidden lg:table-cell" } as const;
const INTERACTIVE = "a,button,input,select,textarea,label,[role=button],[role=link],[role=checkbox]";

function defaultValue<T>(row: T, key: string): unknown {
  return row && typeof row === "object" ? (row as Record<string, unknown>)[key] : undefined;
}

function toSortValue(value: unknown): SortValue {
  if (value === null || value === undefined) return value;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value instanceof Date) return value;
  return String(value);
}

/**
 * Typed table with client-side sorting, skeleton loading, error and empty states and keyboard
 * row activation. Use `manualSort` when the API orders the rows. The header row stays visible
 * when the table is given a height cap via `className` (e.g. "max-h-[60vh]").
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  selectedKey,
  loading = false,
  skeletonRows = 6,
  error,
  onRetry,
  empty,
  defaultSort = null,
  sort: controlledSort,
  onSortChange,
  manualSort = false,
  dense = false,
  rowClassName,
  "aria-label": ariaLabel,
  className,
}: DataTableProps<T>) {
  const [internalSort, setInternalSort] = useState<SortState | null>(defaultSort);
  const sort = controlledSort !== undefined ? controlledSort : internalSort;

  const sorted = useMemo(() => {
    const list = rows ?? [];
    if (!sort || manualSort) return list;
    const column = columns.find((c) => c.key === sort.key);
    if (!column) return list;
    const get = column.sortValue ?? ((row: T) => toSortValue(defaultValue(row, column.key)));
    return sortRows(list, get, sort.direction);
  }, [rows, sort, manualSort, columns]);

  const changeSort = (key: string) => {
    const next = nextSort(sort, key);
    if (controlledSort === undefined) setInternalSort(next);
    onSortChange?.(next);
  };

  const cellPad = dense ? "px-3 py-1.5" : "px-4 py-2.5";
  const hasRows = sorted.length > 0;
  const showSkeleton = loading && !hasRows;
  const showError = !loading && !hasRows && error != null;
  const showEmpty = !loading && !hasRows && error == null;

  const activate = (row: T) => onRowClick?.(row);
  const onRowMouse = (e: MouseEvent<HTMLTableRowElement>, row: T) => {
    const target = e.target as HTMLElement;
    const interactive = target.closest(INTERACTIVE);
    if (interactive && e.currentTarget.contains(interactive)) return;
    activate(row);
  };
  const onRowKey = (e: KeyboardEvent<HTMLTableRowElement>, row: T) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      activate(row);
    }
  };

  return (
    // `relative`: absolutely positioned cell content (sr-only status text) is clipped by this scroller
    // instead of extending the page sideways.
    <div className={cn("relative overflow-x-auto", className)}>
      <table className="w-full border-collapse text-left text-[13px]" aria-label={ariaLabel} aria-busy={loading || undefined}>
        <thead className="sticky top-0 z-[1] border-b border-border bg-surface text-2xs uppercase tracking-[0.06em] text-fg-faint">
          <tr>
            {columns.map((col) => {
              const active = sort?.key === col.key;
              const ariaSort = col.sortable ? (active ? (sort!.direction === "asc" ? "ascending" : "descending") : "none") : undefined;
              return (
                <th
                  key={col.key}
                  scope="col"
                  aria-sort={ariaSort}
                  style={col.width !== undefined ? { width: col.width } : undefined}
                  className={cn("whitespace-nowrap font-medium", dense ? "px-3 py-1.5" : "px-4 py-2", ALIGN[col.align ?? "left"], col.hideBelow && HIDE[col.hideBelow], col.headerClassName)}
                >
                  {col.sortable ? (
                    <button
                      type="button"
                      onClick={() => changeSort(col.key)}
                      className={cn("-mx-1 inline-flex items-center gap-1 rounded px-1 uppercase tracking-[0.06em] hover:text-fg", active && "text-fg-muted", col.align === "right" && "flex-row-reverse")}
                    >
                      {col.header}
                      {active ? (
                        sort!.direction === "asc" ? (
                          <ArrowUp className="h-3 w-3" aria-hidden />
                        ) : (
                          <ArrowDown className="h-3 w-3" aria-hidden />
                        )
                      ) : (
                        <ChevronsUpDown className="h-3 w-3 opacity-50" aria-hidden />
                      )}
                    </button>
                  ) : (
                    col.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {showSkeleton &&
            Array.from({ length: skeletonRows }).map((_, r) => (
              <tr key={`skeleton-${r}`} className="border-b border-border/70 last:border-0" aria-hidden>
                {columns.map((col, c) => (
                  <td key={col.key} className={cn(cellPad, col.hideBelow && HIDE[col.hideBelow])}>
                    <Skeleton className={cn("h-3.5", c === 0 ? "w-3/4" : (r + c) % 3 === 0 ? "w-1/2" : "w-2/3", col.align === "right" && "ml-auto")} />
                  </td>
                ))}
              </tr>
            ))}
          {showError && (
            <tr>
              <td colSpan={columns.length}>
                <ErrorState error={error} onRetry={onRetry} />
              </td>
            </tr>
          )}
          {showEmpty && (
            <tr>
              <td colSpan={columns.length}>
                <EmptyState title={empty?.title ?? "Nothing to show"} description={empty?.description} icon={empty?.icon} action={empty?.action} />
              </td>
            </tr>
          )}
          {sorted.map((row, index) => {
            const key = rowKey(row);
            const selected = selectedKey != null && key === selectedKey;
            return (
              <tr
                key={key}
                onClick={onRowClick ? (e) => onRowMouse(e, row) : undefined}
                onKeyDown={onRowClick ? (e) => onRowKey(e, row) : undefined}
                tabIndex={onRowClick ? 0 : undefined}
                aria-current={selected ? "true" : undefined}
                className={cn(
                  "border-b border-border/70 last:border-0 focus-visible:outline-offset-[-2px]",
                  onRowClick && "cursor-pointer hover:bg-surface-2/70",
                  selected && "bg-accent/[0.06]",
                  rowClassName?.(row),
                )}
              >
                {columns.map((col) => (
                  <td key={col.key} className={cn(cellPad, "align-middle", ALIGN[col.align ?? "left"], col.align === "right" && "num", col.hideBelow && HIDE[col.hideBelow], col.className)}>
                    {col.render ? col.render(row, index) : renderDefault(defaultValue(row, col.key))}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function renderDefault(value: unknown): ReactNode {
  if (value === null || value === undefined || value === "") return <span className="text-fg-faint">—</span>;
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return <span className="font-mono text-xs text-fg-muted">{JSON.stringify(value)}</span>;
  return String(value);
}
