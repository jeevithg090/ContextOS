import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { Tone } from "@/lib/domain";
import { cn, formatNumber } from "@/lib/format";
import { toneColor } from "./chartTheme";

export interface BarListItem {
  key: string;
  label: ReactNode;
  value: number;
  tone?: Tone;
  /** Secondary text under the label. */
  hint?: ReactNode;
  /** Makes the row a link (preferred over onSelect for navigation). */
  href?: string;
}

export interface BarListProps {
  items: BarListItem[];
  /** Makes rows buttons, e.g. to apply a filter. */
  onSelect?: (key: string) => void;
  selectedKey?: string | null;
  /** Scale maximum; defaults to the largest value so the top row fills the width. */
  max?: number;
  valueFormat?: (value: number) => string;
  /** Show only the first N rows (sorted as given). */
  limit?: number;
  emptyLabel?: ReactNode;
  "aria-label"?: string;
  className?: string;
}

/** Ranked horizontal bars with counts — "top N" breakdowns that link to the underlying list. */
export function BarList({ items, onSelect, selectedKey, max, valueFormat = formatNumber, limit, emptyLabel = "No data.", "aria-label": ariaLabel, className }: BarListProps) {
  const shown = limit ? items.slice(0, limit) : items;
  if (shown.length === 0) return <p className={cn("py-4 text-center text-xs text-fg-muted", className)}>{emptyLabel}</p>;
  const scale = Math.max(max ?? 0, ...shown.map((i) => i.value), 0);

  return (
    <ul className={cn("space-y-1", className)} aria-label={ariaLabel}>
      {shown.map((item) => {
        const pct = scale > 0 ? Math.max(item.value > 0 ? 2 : 0, (item.value / scale) * 100) : 0;
        const selected = selectedKey != null && selectedKey === item.key;
        const inner = (
          <>
            <span className="absolute inset-y-0 left-0 rounded-[4px]" style={{ width: `${pct}%`, background: toneColor(item.tone ?? "accent", selected ? 0.28 : 0.16) }} aria-hidden />
            <span className="relative flex min-w-0 flex-1 flex-col">
              <span className="truncate text-[13px] text-fg">{item.label}</span>
              {item.hint && <span className="truncate text-2xs text-fg-muted">{item.hint}</span>}
            </span>
            <span className="num relative shrink-0 font-mono text-xs text-fg">{valueFormat(item.value)}</span>
          </>
        );
        const rowClass = cn(
          "relative flex w-full items-center gap-3 overflow-hidden rounded-[4px] px-2 py-1.5 text-left",
          (item.href || onSelect) && "transition-colors hover:bg-surface-2",
          selected && "ring-1 ring-inset ring-accent/40",
        );
        return (
          <li key={item.key}>
            {item.href ? (
              <Link to={item.href} className={rowClass}>
                {inner}
              </Link>
            ) : onSelect ? (
              <button type="button" className={rowClass} onClick={() => onSelect(item.key)} aria-pressed={selected}>
                {inner}
              </button>
            ) : (
              <div className={rowClass}>{inner}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
