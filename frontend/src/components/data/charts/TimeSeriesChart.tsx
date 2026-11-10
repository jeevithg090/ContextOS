import { useId, useMemo, type ReactNode } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { format } from "date-fns";
import { Skeleton } from "@/components/ui";
import type { Tone } from "@/lib/domain";
import { formatNumber } from "@/lib/format";
import { AXIS_TICK, CURSOR_FILL, CURSOR_STROKE, ChartEmpty, ChartTooltipCard, GRID_STROKE, seriesColor } from "./chartTheme";

export interface TimeSeries {
  key: string;
  label: string;
  /** Semantic colour (e.g. "critical", "deny"). Un-toned series use neutral accent shades. */
  tone?: Tone;
}

export type TimeSeriesDatum = Record<string, string | number | null | undefined>;

export interface TimeSeriesChartProps {
  data: TimeSeriesDatum[];
  series: TimeSeries[];
  /** Key holding the bucket timestamp (ISO) or label. */
  xKey?: string;
  variant?: "area" | "bar";
  stacked?: boolean;
  height?: number;
  xFormat?: (value: string) => string;
  yFormat?: (value: number) => string;
  loading?: boolean;
  emptyLabel?: ReactNode;
  /** Describes the chart for screen readers, e.g. "Findings per day by severity". */
  "aria-label": string;
  className?: string;
}

function autoXFormat(data: TimeSeriesDatum[], xKey: string): (value: string) => string {
  const first = Date.parse(String(data[0]?.[xKey] ?? ""));
  const last = Date.parse(String(data[data.length - 1]?.[xKey] ?? ""));
  if (Number.isNaN(first) || Number.isNaN(last)) return (v) => v;
  const spanHours = Math.abs(last - first) / 3_600_000;
  const pattern = spanHours <= 48 ? "HH:mm" : "d MMM";
  return (v) => {
    const t = Date.parse(v);
    return Number.isNaN(t) ? v : format(new Date(t), pattern);
  };
}

function tooltipTitle(value: string): string {
  const t = Date.parse(value);
  return Number.isNaN(t) ? value : format(new Date(t), "d MMM yyyy, HH:mm");
}

/** Counts over time: stacked areas (trend) or stacked bars (discrete buckets). */
export function TimeSeriesChart({
  data,
  series,
  xKey = "t",
  variant = "area",
  stacked = true,
  height = 200,
  xFormat,
  yFormat = (v) => formatNumber(v),
  loading = false,
  emptyLabel = "No activity in this period.",
  "aria-label": ariaLabel,
  className,
}: TimeSeriesChartProps) {
  const gradientBase = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const fmtX = useMemo(() => xFormat ?? autoXFormat(data, xKey), [xFormat, data, xKey]);
  const totals = useMemo(
    () => series.map((s) => ({ ...s, total: data.reduce((sum, d) => sum + (typeof d[s.key] === "number" ? (d[s.key] as number) : 0), 0) })),
    [data, series],
  );

  if (loading) {
    return (
      <div className={className} style={{ height }} aria-busy="true" aria-label={`Loading ${ariaLabel}`}>
        <Skeleton className="h-full w-full" />
      </div>
    );
  }
  if (data.length === 0 || totals.every((t) => t.total === 0)) return <ChartEmpty height={height}>{emptyLabel}</ChartEmpty>;

  const colors = series.map((s, i) => seriesColor(s.tone, i));
  const stackId = stacked ? "stack" : undefined;

  const axes = (
    <>
      <CartesianGrid stroke={GRID_STROKE} vertical={false} />
      <XAxis dataKey={xKey} tick={AXIS_TICK} tickLine={false} axisLine={{ stroke: GRID_STROKE }} tickFormatter={(v) => fmtX(String(v))} minTickGap={24} />
      <YAxis tick={AXIS_TICK} tickLine={false} axisLine={false} width={40} allowDecimals={false} tickFormatter={(v) => yFormat(Number(v))} />
      <Tooltip
        cursor={variant === "bar" ? { fill: CURSOR_FILL } : { stroke: CURSOR_STROKE }}
        isAnimationActive={false}
        content={({ active, payload, label }) => {
          if (!active || !payload?.length) return null;
          const rows = payload.map((p) => ({
            name: series.find((s) => s.key === p.dataKey)?.label ?? String(p.name),
            value: typeof p.value === "number" ? yFormat(p.value) : String(p.value ?? "—"),
            color: colors[series.findIndex((s) => s.key === p.dataKey)],
          }));
          const total = stacked ? payload.reduce((sum, p) => sum + (typeof p.value === "number" ? p.value : 0), 0) : undefined;
          return <ChartTooltipCard title={tooltipTitle(String(label))} rows={rows.reverse()} total={total} />;
        }}
      />
    </>
  );

  return (
    <figure className={className} aria-label={ariaLabel}>
      <div style={{ height }} aria-hidden>
        <ResponsiveContainer width="100%" height="100%">
          {variant === "bar" ? (
            <BarChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: -8 }} barCategoryGap="18%">
              {axes}
              {series.map((s, i) => (
                <Bar
                  key={s.key}
                  dataKey={s.key}
                  name={s.label}
                  stackId={stackId}
                  fill={colors[i]}
                  radius={!stacked || i === series.length - 1 ? [2, 2, 0, 0] : 0}
                  isAnimationActive={false}
                  maxBarSize={28}
                />
              ))}
            </BarChart>
          ) : (
            <AreaChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: -8 }}>
              <defs>
                {series.map((s, i) => (
                  <linearGradient key={s.key} id={`${gradientBase}-${i}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={colors[i]} stopOpacity={0.32} />
                    <stop offset="100%" stopColor={colors[i]} stopOpacity={0.04} />
                  </linearGradient>
                ))}
              </defs>
              {axes}
              {series.map((s, i) => (
                <Area
                  key={s.key}
                  type="monotoneX"
                  dataKey={s.key}
                  name={s.label}
                  stackId={stackId}
                  stroke={colors[i]}
                  strokeWidth={1.5}
                  fill={`url(#${gradientBase}-${i})`}
                  isAnimationActive={false}
                  activeDot={{ r: 3, strokeWidth: 0 }}
                />
              ))}
            </AreaChart>
          )}
        </ResponsiveContainer>
      </div>
      <figcaption className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-2xs text-fg-muted">
        <span className="sr-only">{ariaLabel}. Totals: </span>
        {totals.map((t, i) => (
          <span key={t.key} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm" style={{ background: colors[i] }} aria-hidden />
            {t.label}
            <span className="num font-mono text-fg">{yFormat(t.total)}</span>
          </span>
        ))}
      </figcaption>
    </figure>
  );
}
