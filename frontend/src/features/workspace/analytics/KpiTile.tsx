import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, Info } from "lucide-react";
import { Skeleton, Tooltip } from "@/components/ui";
import { TONE_CLASSES, type Tone } from "@/lib/domain";
import { cn } from "@/lib/format";
import type { Ratio } from "./types";

export interface KpiTileProps {
  label: string;
  value: ReactNode;
  /** What was counted, e.g. "3 of 6 findings with a linked task". */
  detail?: ReactNode;
  /** Exact definition of the number (shown in a tooltip). */
  definition: string;
  tone?: Tone;
  /** The list behind the number. */
  href?: string;
  hrefLabel?: string;
  loading?: boolean;
}

/** A metric with its numerator/denominator and definition — never a bare number. */
export function KpiTile({ label, value, detail, definition, tone, href, hrefLabel = "View", loading }: KpiTileProps) {
  return (
    <div className="panel flex min-w-0 flex-col gap-2 p-4">
      <div className="flex items-center justify-between gap-2">
        <span className="label-caps truncate">{label}</span>
        <Tooltip content={definition}>
          <button type="button" className="rounded p-0.5 text-fg-faint hover:text-fg" aria-label={`How "${label}" is calculated: ${definition}`}>
            <Info className="h-3.5 w-3.5" aria-hidden />
          </button>
        </Tooltip>
      </div>
      {loading ? (
        <Skeleton className="h-7 w-20" />
      ) : (
        <div className={cn("num text-2xl font-semibold leading-none", tone ? TONE_CLASSES[tone].text : "text-fg")}>{value}</div>
      )}
      <div className="flex min-h-[16px] items-end justify-between gap-2 text-xs text-fg-muted">
        <span className="min-w-0">{loading ? <Skeleton className="h-3 w-28" /> : detail}</span>
        {href && !loading && (
          <Link to={href} className="inline-flex shrink-0 items-center gap-0.5 text-accent hover:text-accent-strong">
            {hrefLabel}
            <ArrowRight className="h-3 w-3" aria-hidden />
          </Link>
        )}
      </div>
    </div>
  );
}

export function percent(ratio: Ratio): string {
  return ratio.rate === null ? "—" : `${Math.round(ratio.rate * 100)}%`;
}

/** "36.5 h" under two days, otherwise "4.2 d". */
export function formatHours(hours: number | null | undefined): string {
  if (hours === null || hours === undefined) return "—";
  if (hours < 1) return `${Math.round(hours * 60)} min`;
  if (hours < 48) return `${hours.toFixed(hours < 10 ? 1 : 0)} h`;
  return `${(hours / 24).toFixed(1)} d`;
}
