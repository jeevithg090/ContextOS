import type { ReactNode } from "react";
import { Cell, Pie, PieChart, Tooltip } from "recharts";
import type { Tone } from "@/lib/domain";
import { cn, formatNumber } from "@/lib/format";
import { ChartTooltipCard, seriesColor } from "./chartTheme";

export interface DonutDatum {
  key: string;
  label: string;
  value: number;
  tone?: Tone;
}

export interface DonutChartProps {
  data: DonutDatum[];
  /** Big number in the centre; defaults to the total. */
  centerValue?: ReactNode;
  /** Caption under the centre value, e.g. "open findings". */
  centerLabel?: ReactNode;
  size?: number;
  thickness?: number;
  legend?: boolean;
  onSelect?: (key: string) => void;
  valueFormat?: (value: number) => string;
  emptyLabel?: ReactNode;
  "aria-label": string;
  className?: string;
}

/** Share-of-total breakdown with a centre total and an accessible legend. */
export function DonutChart({
  data,
  centerValue,
  centerLabel,
  size = 148,
  thickness = 14,
  legend = true,
  onSelect,
  valueFormat = formatNumber,
  emptyLabel = "No data.",
  "aria-label": ariaLabel,
  className,
}: DonutChartProps) {
  const total = data.reduce((sum, d) => sum + Math.max(0, d.value), 0);
  const slices = data.filter((d) => d.value > 0);
  const colors = new Map(data.map((d, i) => [d.key, seriesColor(d.tone, i)]));
  const outer = size / 2 - 2;

  return (
    <figure className={cn("flex flex-wrap items-center gap-5", className)} aria-label={ariaLabel}>
      <div className="relative shrink-0" style={{ width: size, height: size }} aria-hidden>
        {total > 0 ? (
          <PieChart width={size} height={size}>
            <Pie
              data={slices}
              dataKey="value"
              nameKey="label"
              innerRadius={outer - thickness}
              outerRadius={outer}
              paddingAngle={slices.length > 1 ? 1.5 : 0}
              startAngle={90}
              endAngle={-270}
              stroke="none"
              isAnimationActive={false}
              onClick={onSelect ? (d: { key?: string }) => d.key && onSelect(d.key) : undefined}
              cursor={onSelect ? "pointer" : undefined}
            >
              {slices.map((d) => (
                <Cell key={d.key} fill={colors.get(d.key)} />
              ))}
            </Pie>
            <Tooltip
              isAnimationActive={false}
              content={({ active, payload }) => {
                const p = payload?.[0];
                if (!active || !p) return null;
                const d = p.payload as DonutDatum;
                const share = total > 0 ? Math.round((d.value / total) * 100) : 0;
                return <ChartTooltipCard rows={[{ name: d.label, value: `${valueFormat(d.value)} · ${share}%`, color: colors.get(d.key) }]} />;
              }}
            />
          </PieChart>
        ) : (
          <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
            <circle cx={size / 2} cy={size / 2} r={outer - thickness / 2} fill="none" stroke="rgb(var(--surface-3))" strokeWidth={thickness} />
          </svg>
        )}
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="num text-xl font-semibold leading-none text-fg">{centerValue ?? valueFormat(total)}</span>
          {centerLabel && <span className="mt-1 max-w-[80%] text-2xs leading-tight text-fg-muted">{centerLabel}</span>}
        </div>
      </div>
      {legend && (
        <figcaption className="min-w-[140px] flex-1">
          <span className="sr-only">{ariaLabel}</span>
          {total === 0 ? (
            <p className="text-xs text-fg-muted">{emptyLabel}</p>
          ) : (
            <ul className="space-y-1">
              {data.map((d) => {
                const share = total > 0 ? Math.round((Math.max(0, d.value) / total) * 100) : 0;
                const content = (
                  <>
                    <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: colors.get(d.key) }} aria-hidden />
                    <span className="min-w-0 flex-1 truncate text-fg-muted">{d.label}</span>
                    <span className="num font-mono text-fg">{valueFormat(d.value)}</span>
                    <span className="num w-9 text-right font-mono text-fg-faint">{share}%</span>
                  </>
                );
                return (
                  <li key={d.key}>
                    {onSelect ? (
                      <button type="button" onClick={() => onSelect(d.key)} className="flex w-full items-center gap-2 rounded px-1 py-0.5 text-left text-xs hover:bg-surface-2">
                        {content}
                      </button>
                    ) : (
                      <div className="flex items-center gap-2 px-1 py-0.5 text-xs">{content}</div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </figcaption>
      )}
    </figure>
  );
}
