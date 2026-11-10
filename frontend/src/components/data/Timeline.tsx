import type { ReactNode } from "react";
import { TONE_CLASSES, type Tone } from "@/lib/domain";
import { cn, formatDateTime, formatTime, timeAgo } from "@/lib/format";

export interface TimelineItem {
  id: string;
  /** ISO timestamp. */
  time?: string | null;
  /** Overrides the formatted time. */
  timeLabel?: ReactNode;
  icon?: ReactNode;
  tone?: Tone;
  title: ReactNode;
  description?: ReactNode;
  badges?: ReactNode;
  children?: ReactNode;
}

export interface TimelineProps {
  items: TimelineItem[];
  dense?: boolean;
  selectedId?: string | null;
  /** Makes items selectable (keyboard and pointer); the selected item is highlighted. */
  onSelect?: (id: string) => void;
  /** "time" = HH:mm:ss.SSS (default), "relative" = "3 min ago", "datetime" = full date. */
  timeFormat?: "time" | "relative" | "datetime";
  showTime?: boolean;
  emptyLabel?: ReactNode;
  className?: string;
  "aria-label"?: string;
}

/** Vertical, chronological list of events (session activity, incident history, audit trail). */
export function Timeline({
  items,
  dense = false,
  selectedId,
  onSelect,
  timeFormat = "time",
  showTime = true,
  emptyLabel = "Nothing recorded yet.",
  className,
  "aria-label": ariaLabel = "Timeline",
}: TimelineProps) {
  if (items.length === 0) return <p className={cn("px-1 py-6 text-center text-xs text-fg-muted", className)}>{emptyLabel}</p>;

  return (
    <ol className={cn("relative", className)} aria-label={ariaLabel}>
      {items.map((item, index) => {
        const selected = selectedId != null && item.id === selectedId;
        const first = index === 0;
        const last = index === items.length - 1;
        const tone = TONE_CLASSES[item.tone ?? "neutral"];
        const nodeTop = dense ? "top-[7px]" : "top-[10px]";

        const body = (
          <>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className={cn("min-w-0 font-medium text-fg", dense ? "text-xs" : "text-[13px]")}>{item.title}</span>
              {item.badges && <span className="flex flex-wrap items-center gap-1">{item.badges}</span>}
            </div>
            {item.description && <div className={cn("mt-0.5 text-fg-muted", dense ? "text-2xs" : "text-xs")}>{item.description}</div>}
          </>
        );

        return (
          <li key={item.id} className="relative flex gap-3" aria-current={selected ? "true" : undefined}>
            {showTime && (
              <div className={cn("w-[88px] shrink-0 text-right font-mono text-2xs text-fg-faint num", dense ? "pt-0.5" : "pt-1.5")}>
                {item.timeLabel ?? (item.time ? <time dateTime={item.time} title={formatDateTime(item.time)}>{formatStamp(item.time, timeFormat)}</time> : "—")}
              </div>
            )}
            <div className="relative w-5 shrink-0" aria-hidden>
              {items.length > 1 && (
                <span
                  className={cn("absolute left-1/2 w-px -translate-x-1/2 bg-border", first ? nodeTop : "top-0", last ? (dense ? "h-[7px]" : "h-[10px]") : "bottom-0")}
                />
              )}
              {item.icon ? (
                <span
                  className={cn(
                    "absolute left-1/2 flex -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border bg-surface [&>svg]:h-3 [&>svg]:w-3",
                    dense ? "h-4 w-4" : "h-5 w-5",
                    nodeTop,
                    tone.text,
                    tone.border,
                  )}
                >
                  {item.icon}
                </span>
              ) : (
                <span className={cn("absolute left-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-surface", nodeTop, tone.dot)} />
              )}
            </div>
            <div className={cn("min-w-0 flex-1", last ? "pb-0" : dense ? "pb-2" : "pb-4")}>
              {onSelect ? (
                <button
                  type="button"
                  onClick={() => onSelect(item.id)}
                  aria-pressed={selected}
                  className={cn(
                    "-mx-2 block w-[calc(100%+16px)] rounded px-2 text-left transition-colors",
                    dense ? "py-0.5" : "py-1",
                    selected ? "bg-accent/[0.08] ring-1 ring-inset ring-accent/40" : "hover:bg-surface-2",
                  )}
                >
                  {body}
                </button>
              ) : (
                <div className={cn(dense ? "py-0.5" : "py-1", selected && "-mx-2 rounded bg-accent/[0.08] px-2 ring-1 ring-inset ring-accent/40")}>{body}</div>
              )}
              {item.children && <div className="mt-1.5">{item.children}</div>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function formatStamp(iso: string, mode: "time" | "relative" | "datetime"): string {
  if (mode === "relative") return timeAgo(iso);
  if (mode === "datetime") return formatDateTime(iso);
  return formatTime(iso);
}
