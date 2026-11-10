import type { ReactNode } from "react";
import { TONE_CLASSES, type Tone } from "@/lib/domain";
import { cn } from "@/lib/format";
import { toneColor } from "./charts/chartTheme";

const GRADE_TONE: Record<string, Tone> = { A: "ok", B: "ok", C: "medium", D: "high", F: "critical" };

/** Display-only fallback when the API omitted a grade; the posture engine's grade is authoritative. */
export function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export interface ScoreRingProps {
  /** 0-100, higher is better (posture). */
  score: number;
  grade?: string | null;
  size?: number;
  thickness?: number;
  label?: string;
  /** Replaces the grade in the centre. */
  children?: ReactNode;
  className?: string;
}

/** Circular posture score with letter grade. Colour follows the grade, not decoration. */
export function ScoreRing({ score, grade, size = 88, thickness = 7, label = "Posture score", children, className }: ScoreRingProps) {
  const value = Number.isFinite(score) ? Math.min(100, Math.max(0, Math.round(score))) : 0;
  const letter = (grade?.trim().toUpperCase() || gradeFromScore(value)).slice(0, 2);
  const tone: Tone = GRADE_TONE[letter.charAt(0)] ?? "neutral";
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  const dash = (value / 100) * circumference;

  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value}
      aria-valuetext={`${value} out of 100, grade ${letter}`}
      className={cn("relative inline-flex shrink-0 items-center justify-center", className)}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgb(var(--surface-3))" strokeWidth={thickness} />
        {value > 0 && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={toneColor(tone)}
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circumference}`}
            className="transition-[stroke-dasharray] duration-500"
          />
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center" aria-hidden>
        {children ?? (
          <>
            <span className={cn("font-semibold leading-none", TONE_CLASSES[tone].text)} style={{ fontSize: Math.round(size * 0.3) }}>
              {letter}
            </span>
            <span className="num mt-1 font-mono text-2xs text-fg-muted">{value}/100</span>
          </>
        )}
      </div>
    </div>
  );
}
