import { TONE_CLASSES, humanize, type Tone } from "@/lib/domain";
import { cn } from "@/lib/format";

export type RiskLevel = "low" | "medium" | "high" | "critical";

const LEVEL_TONE: Record<RiskLevel, Tone> = { low: "low", medium: "medium", high: "high", critical: "critical" };

/**
 * Display-only fallback used when the API did not send a level. The server-computed level
 * (risk engine) is authoritative — always pass it when you have it.
 */
export function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function clampScore(score: number): number {
  return Number.isFinite(score) ? Math.min(100, Math.max(0, Math.round(score))) : 0;
}

export interface RiskMeterProps {
  /** 0-100, higher is riskier. */
  score: number;
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
  const resolved: RiskLevel = level && Object.prototype.hasOwnProperty.call(LEVEL_TONE, level) ? (level as RiskLevel) : riskLevelFromScore(value);
  const tone = TONE_CLASSES[LEVEL_TONE[resolved]];
  const filled = value === 0 ? 0 : Math.max(1, Math.ceil((value / 100) * segments));

  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value}
      aria-valuetext={`${value} out of 100, ${resolved} risk`}
      className={cn("inline-flex items-center gap-2", className)}
    >
      <div className={cn("flex gap-[2px]", size === "sm" ? "w-16" : "w-24")} aria-hidden>
        {Array.from({ length: segments }).map((_, i) => (
          <span key={i} className={cn("flex-1 rounded-[1px]", size === "sm" ? "h-1.5" : "h-2", i < filled ? tone.dot : "bg-surface-3")} />
        ))}
      </div>
      {showValue && <span className={cn("num font-mono font-medium", size === "sm" ? "text-2xs" : "text-xs", tone.text)}>{value}</span>}
      {showLevel && <span className={cn("text-xs", tone.text)}>{humanize(resolved)}</span>}
    </div>
  );
}
