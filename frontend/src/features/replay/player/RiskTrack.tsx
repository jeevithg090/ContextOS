/**
 * Risk progression over the replayed steps with the playhead, decision markers and a scrubber.
 * The curve is session risk RECOMPUTED from recorded events after each step (0–100, fixed scale;
 * dashed lines at the engine's medium/high/critical thresholds 25/50/75).
 */
import { useId, type MouseEvent } from "react";
import { DECISION_META, TONE_CLASSES, type Decision } from "@/lib/domain";
import { cn } from "@/lib/format";
import { toneColor } from "@/components/data";
import type { ReplayStep } from "../types";
import { stepTone } from "../meta";

const H = 64;
const THRESHOLDS = [25, 50, 75];

export function RiskTrack({ steps, index, onSeek }: { steps: ReplayStep[]; index: number; onSeek: (index: number) => void }) {
  const gradientId = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const n = steps.length;
  if (n === 0) return null;
  const w = 100 / n;
  const y = (score: number) => H - (Math.min(100, Math.max(0, score)) / 100) * (H - 4) - 2;
  let d = `M0,${H}`;
  steps.forEach((s, i) => {
    d += ` L${(i * w).toFixed(3)},${y(s.risk_after.score).toFixed(2)} L${((i + 1) * w).toFixed(3)},${y(s.risk_after.score).toFixed(2)}`;
  });
  const area = `${d} L100,${H} Z`;
  const line = d.replace(`M0,${H} L`, "M");
  const current = steps[index];
  const peak = Math.max(...steps.map((s) => s.risk_after.score));

  const seekFromPointer = (e: MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    if (rect.width <= 0) return;
    onSeek(Math.floor(((e.clientX - rect.left) / rect.width) * n));
  };

  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-baseline justify-between gap-2 text-2xs text-fg-faint">
        <span>
          Session risk after each step <span className="text-fg-muted">· recomputed from recorded events</span>
        </span>
        <span className="num">
          now <span className="font-medium text-fg">{current?.risk_after.score ?? 0}</span> · peak {peak}
        </span>
      </div>
      <div className="relative">
        <svg
          viewBox={`0 0 100 ${H}`}
          preserveAspectRatio="none"
          className="block h-16 w-full cursor-pointer rounded bg-surface-2/60"
          role="img"
          aria-label={`Recomputed session risk over ${n} steps: starts at ${steps[0].risk_after.score}, peaks at ${peak}, ends at ${steps[n - 1].risk_after.score}`}
          onClick={seekFromPointer}
        >
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={toneColor("accent")} stopOpacity={0.32} />
              <stop offset="100%" stopColor={toneColor("accent")} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          {THRESHOLDS.map((t) => (
            <line key={t} x1={0} x2={100} y1={y(t)} y2={y(t)} stroke="rgb(var(--border-strong))" strokeWidth={0.6} strokeDasharray="1.5 1.5" vectorEffect="non-scaling-stroke" />
          ))}
          <rect x={index * w} y={0} width={w} height={H} fill={toneColor("accent", 0.14)} />
          <path d={area} fill={`url(#${gradientId})`} />
          <path d={line} fill="none" stroke={toneColor("accent")} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
          <line x1={(index + 0.5) * w} x2={(index + 0.5) * w} y1={0} y2={H} stroke={toneColor("accent")} strokeWidth={1} vectorEffect="non-scaling-stroke" />
        </svg>
        <div className="pointer-events-none absolute inset-y-0 right-1 flex flex-col justify-between py-0.5 text-[9px] leading-none text-fg-faint" aria-hidden>
          <span>100</span>
          <span>0</span>
        </div>
      </div>
      <DecisionLane steps={steps} index={index} onSeek={onSeek} width={w} />
      <input
        type="range"
        min={0}
        max={Math.max(0, n - 1)}
        step={1}
        value={index}
        onChange={(e) => onSeek(Number(e.target.value))}
        aria-label="Replay position"
        aria-valuetext={current ? `Step ${current.index + 1}: ${current.title}` : undefined}
        className="block w-full accent-[rgb(var(--accent))]"
      />
    </div>
  );
}

function DecisionLane({ steps, index, onSeek, width }: { steps: ReplayStep[]; index: number; onSeek: (i: number) => void; width: number }) {
  const marks = steps.map((s, i) => ({ s, i })).filter(({ s }) => s.outcome || s.findings.length > 0);
  if (marks.length === 0) return null;
  return (
    <div className="relative h-3" aria-label="Decision and finding markers">
      {marks.map(({ s, i }) => {
        const decision = s.outcome?.decision;
        const tone = decision ? stepTone(decision) : "high";
        const label = decision ? (DECISION_META[decision as Decision]?.label ?? decision) : `${s.findings.length} finding(s)`;
        return (
          <button
            key={s.event_id}
            type="button"
            onClick={() => onSeek(i)}
            title={`Step ${s.index + 1}: ${label} — ${s.title}`}
            aria-label={`Go to step ${s.index + 1}: ${label}`}
            className={cn(
              "absolute top-0 h-3 -translate-x-1/2 rounded-sm transition-transform hover:scale-125 focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent",
              decision ? "w-1.5" : "w-1 opacity-70",
              TONE_CLASSES[tone].dot,
              i === index && "ring-1 ring-fg ring-offset-1 ring-offset-surface",
            )}
            style={{ left: `${(i + 0.5) * width}%` }}
          />
        );
      })}
    </div>
  );
}
