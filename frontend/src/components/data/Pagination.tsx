import { useId, type ReactNode } from "react";
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";
import { cn, formatNumber } from "@/lib/format";

export interface PaginationProps {
  total: number;
  limit: number;
  offset: number;
  /** Receives the new row offset. */
  onChange: (offset: number) => void;
  /** Enables the page-size selector. */
  onLimitChange?: (limit: number) => void;
  pageSizeOptions?: number[];
  /** Noun for the count, e.g. "findings". */
  itemLabel?: string;
  className?: string;
}

/** Offset pagination for `Page[T]` responses: "26–50 of 312" plus first/prev/next/last. */
export function Pagination({ total, limit, offset, onChange, onLimitChange, pageSizeOptions = [25, 50, 100], itemLabel = "results", className }: PaginationProps) {
  const sizeId = useId();
  if (total <= 0) return null;

  const safeLimit = Math.max(1, limit);
  const pageCount = Math.max(1, Math.ceil(total / safeLimit));
  const page = Math.min(pageCount, Math.floor(Math.max(0, offset) / safeLimit) + 1);
  const start = Math.min(total, Math.max(0, offset) + 1);
  const end = Math.min(total, Math.max(0, offset) + safeLimit);
  const lastOffset = (pageCount - 1) * safeLimit;
  const atStart = offset <= 0;
  const atEnd = offset + safeLimit >= total;

  const go = (next: number) => onChange(Math.min(lastOffset, Math.max(0, next)));

  return (
    <nav aria-label="Pagination" className={cn("flex flex-wrap items-center justify-between gap-3 px-1 py-2 text-xs text-fg-muted", className)}>
      <div className="num" aria-live="polite">
        <span className="text-fg">
          {formatNumber(start)}–{formatNumber(end)}
        </span>{" "}
        of <span className="text-fg">{formatNumber(total)}</span> {itemLabel}
      </div>
      <div className="flex items-center gap-3">
        {onLimitChange && (
          <div className="flex items-center gap-1.5">
            <label htmlFor={sizeId} className="text-fg-faint">
              Rows
            </label>
            <select
              id={sizeId}
              value={safeLimit}
              onChange={(e) => onLimitChange(Number(e.target.value))}
              className="h-6 rounded border border-border-strong bg-surface-2 px-1.5 text-xs text-fg focus:border-accent/60 focus:outline-none"
            >
              {Array.from(new Set([...pageSizeOptions, safeLimit]))
                .sort((a, b) => a - b)
                .map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
            </select>
          </div>
        )}
        <span className="num">
          Page {page} of {pageCount}
        </span>
        <div className="flex items-center gap-0.5">
          <PageButton label="First page" disabled={atStart} onClick={() => go(0)}>
            <ChevronsLeft className="h-3.5 w-3.5" aria-hidden />
          </PageButton>
          <PageButton label="Previous page" disabled={atStart} onClick={() => go(offset - safeLimit)}>
            <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
          </PageButton>
          <PageButton label="Next page" disabled={atEnd} onClick={() => go(offset + safeLimit)}>
            <ChevronRight className="h-3.5 w-3.5" aria-hidden />
          </PageButton>
          <PageButton label="Last page" disabled={atEnd} onClick={() => go(lastOffset)}>
            <ChevronsRight className="h-3.5 w-3.5" aria-hidden />
          </PageButton>
        </div>
      </div>
    </nav>
  );
}

function PageButton({ label, disabled, onClick, children }: { label: string; disabled: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={onClick}
      className="inline-flex h-6 w-6 items-center justify-center rounded border border-border-strong text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent"
    >
      {children}
    </button>
  );
}
