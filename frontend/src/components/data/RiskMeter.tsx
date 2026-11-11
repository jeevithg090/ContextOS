import { TONE_CLASSES, humanize, type Tone } from "@/lib/domain";
import { cn } from "@/lib/format";

export type RiskLevel = "low" | "medium" | "high" | "critical";

const LEVEL_TONE: Record<RiskLevel, Tone> = { low: "low", medium: "medium", high: "high", critical: "critical" };

function knownLevel(level: string | null | undefined): RiskLevel | null {
  return level && Object.prototype.hasOwnProperty.call(LEVEL_TONE, level) ? (level as RiskLevel) : null;
}

function clampScore(score: number): number {
  return Number.isFinite(score) ? Math.min(100, Math.max(0, Math.round(score))) : 0;
}

export interface RiskMeterProps {
  /** 0-100, higher is riskier. */
  score: number;
  /** The server-computed level (risk engine thresholds). Without one the meter is drawn neutral — the
   * client never derives a level from the score, so it cannot drift from the server's thresholds. */
  level?: string | null;
  segments?: number;
  showValue?: boolean;
  showLevel?: boolean;
  size?: "sm" | "md";
  label?: string;
  className?: string;
}

/** Segmented 0-100 risk bar with the numeric score and level. */
export function RiskMeter({ score, level, segments = 10, showValue = true, showLevel = false, size = "md", label = "Risk score", className }: RiskMeterProps) {
  const value = clampScore(score);
  const resolved = knownLevel(level);
  const tone = TONE_CLASSES[resolved ? LEVEL_TONE[resolved] : "neutral"];
  const filled = value === 0 ? 0 : Math.max(1, Math.ceil((value / 100) * segments));

  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value}
      aria-valuetext={resolved ? `${value} out of 100, ${resolved} risk` : `${value} out of 100`}
      className={cn("inline-flex items-center gap-2", className)}
    >
      <div className={cn("flex gap-[2px]", size === "sm" ? "w-16" : "w-24")} aria-hidden>
        {Array.from({ length: segments }).map((_, i) => (
          <span key={i} className={cn("flex-1 rounded-[1px]", size === "sm" ? "h-1.5" : "h-2", i < filled ? tone.dot : "bg-surface-3")} />
        ))}
      </div>
      {showValue && <span className={cn("num font-mono font-medium", size === "sm" ? "text-2xs" : "text-xs", tone.text)}>{value}</span>}
      {showLevel && resolved && <span className={cn("text-xs", tone.text)}>{humanize(resolved)}</span>}
    </div>
  );
}
