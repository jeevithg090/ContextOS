import { useEffect, useRef } from "react";
import { DecisionBadge, SeverityBadge } from "@/components/ui";
import { SEVERITY_META, type Severity } from "@/lib/domain";
import { cn, formatTime } from "@/lib/format";
import { eventIcon, signed } from "../meta";
import type { ReplayStep } from "../types";

function worstSeverity(step: ReplayStep): string | null {
  let worst: string | null = null;
  for (const f of step.findings) {
    if (!worst || (SEVERITY_META[f.severity as Severity]?.rank ?? 0) > (SEVERITY_META[worst as Severity]?.rank ?? 0)) worst = f.severity;
  }
  return worst;
}

/** Ordered list of recorded steps; the active one is kept in view and marked aria-current. */
export function StepList({ steps, index, onSelect }: { steps: ReplayStep[]; index: number; onSelect: (index: number) => void }) {
  const activeRef = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    const el = activeRef.current;
    if (el && typeof el.scrollIntoView === "function") el.scrollIntoView({ block: "nearest" });
  }, [index]);

  return (
    <ol className="max-h-[600px] divide-y divide-border/60 overflow-y-auto" aria-label="Recorded steps">
      {steps.map((step, i) => {
        const Icon = eventIcon(step.event_type);
        const active = i === index;
        const passed = i < index;
        const severity = worstSeverity(step);
        const delta = step.risk_after.delta;
        return (
          <li key={step.event_id}>
            <button
              ref={active ? activeRef : undefined}
              type="button"
              onClick={() => onSelect(i)}
              aria-current={active ? "step" : undefined}
              className={cn(
                "group flex w-full items-start gap-2.5 px-3 py-2 text-left transition-colors focus-visible:bg-surface-2 focus-visible:outline-none",
                active ? "bg-accent/[0.08]" : "hover:bg-surface-2/70",
              )}
            >
              <span className="num mt-0.5 w-7 shrink-0 text-right text-2xs text-fg-faint">{step.index + 1}</span>
              <Icon
                className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", active ? "text-accent" : passed ? "text-fg-muted" : "text-fg-faint")}
                aria-hidden
              />
              <span className="min-w-0 flex-1">
                <span className={cn("block truncate text-[13px]", active ? "font-medium text-fg" : passed ? "text-fg" : "text-fg-muted")}>
                  {step.title}
                </span>
                <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-2xs text-fg-faint">
                  <time dateTime={step.received_at}>{formatTime(step.received_at)}</time>
                  {step.from_other_session && <span>· from another session</span>}
                  {step.processing_status === "error" && <span className="text-danger">· processing error</span>}
                </span>
              </span>
              <span className="flex shrink-0 flex-col items-end gap-1">
                <span className="flex items-center gap-1">
                  {severity && <SeverityBadge severity={severity} />}
                  {step.outcome && <DecisionBadge decision={step.outcome.decision} />}
                </span>
                {delta !== 0 && (
                  <span className={cn("num text-2xs", delta > 0 ? "text-sev-high" : "text-ok")} title="Change in recomputed session risk">
                    risk {signed(delta)}
                  </span>
                )}
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}
