import { useId } from "react";
import type { Tone } from "@/lib/domain";
import { cn } from "@/lib/format";
import { toneColor } from "./chartTheme";

export interface SparklineProps {
  /** Values in chronological order. */
  data: Array<number | null | undefined>;
  tone?: Tone;
  variant?: "line" | "area" | "bar";
  height?: number;
  /** Fixed pixel width; fills the container when omitted. */
  width?: number;
  /** Required: what the trend shows, e.g. "Findings per day, last 14 days". */
  "aria-label": string;
  className?: string;
}

const VIEW_W = 100;

/**
 * Tiny trend line drawn as plain SVG (no chart runtime), suitable for table cells and stat
 * tiles. Missing values are treated as zero; a flat series draws a midline.
 */
export function Sparkline({ data, tone = "accent", variant = "line", height = 28, width, "aria-label": ariaLabel, className }: SparklineProps) {
  const gradientId = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const values = data.map((v) => (typeof v === "number" && Number.isFinite(v) ? v : 0));
  const color = toneColor(tone);
  const last = values.length ? values[values.length - 1] : null;
  const label = last === null ? `${ariaLabel}: no data` : `${ariaLabel}: latest ${last}, ${values.length} points`;

  if (values.length === 0) {
    return <span className={cn("inline-block text-2xs text-fg-faint", className)} role="img" aria-label={label}>—</span>;
  }

  const min = Math.min(0, ...values);
  const max = Math.max(...values);
  const range = max - min;
  const pad = 2;
  const y = (v: number) => (range === 0 ? height / 2 : pad + (1 - (v - min) / range) * (height - pad * 2));
  const step = values.length > 1 ? VIEW_W / (values.length - 1) : 0;
  const x = (i: number) => (values.length > 1 ? i * step : VIEW_W / 2);

  let shape;
  if (variant === "bar") {
    const barW = VIEW_W / values.length;
    shape = values.map((v, i) => {
      const top = range === 0 ? height - pad : y(v);
      return <rect key={i} x={i * barW + barW * 0.15} width={barW * 0.7} y={top} height={Math.max(v > 0 ? 1 : 0, height - top)} fill={color} opacity={0.85} />;
    });
  } else {
    const points = values.map((v, i) => `${x(i).toFixed(2)},${y(v).toFixed(2)}`);
    const line = `M${points.join(" L")}`;
    shape = (
      <>
        {variant === "area" && (
          <>
            <defs>
              <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity={0.3} />
                <stop offset="100%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <path d={`${line} L${x(values.length - 1).toFixed(2)},${height} L${x(0).toFixed(2)},${height} Z`} fill={`url(#${gradientId})`} />
          </>
        )}
        <path d={line} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
      </>
    );
  }

  return (
    <svg
      role="img"
      aria-label={label}
      className={cn("block overflow-visible", !width && "w-full", className)}
      width={width}
      height={height}
      viewBox={`0 0 ${VIEW_W} ${height}`}
      preserveAspectRatio="none"
    >
      {shape}
    </svg>
  );
}
