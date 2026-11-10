/**
 * Chart styling shared by every recharts-based component, derived from the CSS design tokens in
 * src/styles/index.css so charts follow the same status semantics as badges.
 */
import type { ReactNode } from "react";
import type { Tone } from "@/lib/domain";
import { formatNumber } from "@/lib/format";

/** CSS variable backing each tone (see tailwind.config.js). */
const TONE_VARS: Record<Tone, string> = {
  neutral: "fg-faint",
  accent: "accent",
  trusted: "trust-trusted",
  approved: "trust-approved",
  external: "trust-external",
  unknown: "trust-unknown",
  suspicious: "trust-suspicious",
  blocked: "trust-blocked",
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
  allow: "dec-allow",
  deny: "dec-deny",
  approval: "dec-approval",
  restrict: "dec-restrict",
  audit: "dec-audit",
  ok: "ok",
  warn: "warn",
  danger: "danger",
};

/** `rgb(var(--sev-critical))` (optionally with alpha) for use in SVG fill/stroke and inline styles. */
export function toneColor(tone: Tone = "accent", alpha?: number): string {
  const v = TONE_VARS[tone] ?? "accent";
  return alpha === undefined ? `rgb(var(--${v}))` : `rgb(var(--${v}) / ${alpha})`;
}

/**
 * Fallback colours for series without a semantic tone: shades of the accent and neutral greys,
 * so un-toned series never borrow a status colour and imply meaning they do not have.
 */
const NEUTRAL_SERIES = ["rgb(var(--accent))", "rgb(var(--fg-muted))", "rgb(var(--accent) / 0.55)", "rgb(var(--fg-faint))", "rgb(var(--accent) / 0.3)"];

export function seriesColor(tone: Tone | undefined, index: number): string {
  return tone ? toneColor(tone) : NEUTRAL_SERIES[index % NEUTRAL_SERIES.length];
}

export const AXIS_TICK = { fill: "rgb(var(--fg-faint))", fontSize: 11, fontFamily: "'JetBrains Mono', ui-monospace, monospace" } as const;
export const GRID_STROKE = "rgb(var(--border))";
export const CURSOR_FILL = "rgb(var(--surface-3) / 0.5)";
export const CURSOR_STROKE = "rgb(var(--border-strong))";

export interface TooltipRow {
  name: ReactNode;
  value: number | string;
  color?: string;
}

/** Tooltip body styled as surface-3 with mono tabular numbers. */
export function ChartTooltipCard({ title, rows, total }: { title?: ReactNode; rows: TooltipRow[]; total?: number }) {
  return (
    <div className="min-w-[140px] rounded-md border border-border-strong bg-surface-3 px-2.5 py-2 text-xs shadow-pop">
      {title && <div className="mb-1.5 font-mono text-2xs text-fg-muted">{title}</div>}
      <ul className="space-y-1">
        {rows.map((row, i) => (
          <li key={i} className="flex items-center justify-between gap-4">
            <span className="flex min-w-0 items-center gap-1.5 text-fg-muted">
              {row.color && <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: row.color }} aria-hidden />}
              <span className="truncate">{row.name}</span>
            </span>
            <span className="num font-mono text-fg">{typeof row.value === "number" ? formatNumber(row.value) : row.value}</span>
          </li>
        ))}
      </ul>
      {total !== undefined && rows.length > 1 && (
        <div className="mt-1.5 flex justify-between border-t border-border pt-1.5 text-fg-muted">
          <span>Total</span>
          <span className="num font-mono text-fg">{formatNumber(total)}</span>
        </div>
      )}
    </div>
  );
}

export function ChartEmpty({ height, children }: { height: number; children: ReactNode }) {
  return (
    <div className="flex items-center justify-center rounded border border-dashed border-border text-xs text-fg-muted" style={{ height }}>
      {children}
    </div>
  );
}
