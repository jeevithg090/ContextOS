import { ChevronRight } from "lucide-react";
import { Skeleton } from "@/components/ui";
import { TONE_CLASSES } from "@/lib/domain";
import { cn, formatNumber } from "@/lib/format";
import { REMEDIATION_META } from "./taskMeta";
import { REMEDIATION_STATES, type RemediationCounts, type RemediationState } from "./types";

const STAGE_HINT: Record<RemediationState, string> = {
  no_task: "Create a task to start the fix.",
  task_open: "Being worked on; not in a done column yet.",
  task_done_unverified: "Record a passed verification run.",
  verified: "Fix proven — resolve the finding.",
};

/**
 * The four remediation stages as a filter strip: no task → in progress → done, unverified → verified.
 * Selecting a stage filters the list; selecting it again shows every open finding.
 */
export function RemediationPipeline({
  counts,
  selected,
  onSelect,
  loading,
}: {
  counts: RemediationCounts | undefined;
  selected: RemediationState | undefined;
  onSelect: (state: RemediationState | undefined) => void;
  loading: boolean;
}) {
  const total = counts ? REMEDIATION_STATES.reduce((sum, s) => sum + counts[s], 0) : 0;
  return (
    <div role="group" aria-label="Remediation stages" className="grid grid-cols-2 gap-2 lg:grid-cols-[repeat(4,minmax(0,1fr))]">
      {REMEDIATION_STATES.map((state, i) => {
        const meta = REMEDIATION_META[state];
        const count = counts?.[state] ?? 0;
        const active = selected === state;
        const share = total > 0 ? (count / total) * 100 : 0;
        return (
          <button
            key={state}
            type="button"
            aria-pressed={active}
            onClick={() => onSelect(active ? undefined : state)}
            className={cn(
              "panel relative flex min-w-0 flex-col gap-1.5 p-3 text-left transition-colors hover:bg-surface-2",
              active && "ring-1 ring-inset ring-accent/50",
            )}
          >
            <span className="flex items-center justify-between gap-2">
              <span className="flex min-w-0 items-center gap-1.5">
                <span className={cn("h-2 w-2 shrink-0 rounded-full", TONE_CLASSES[meta.tone].dot)} aria-hidden />
                <span className="truncate text-xs font-medium text-fg">{meta.label}</span>
              </span>
              {i < REMEDIATION_STATES.length - 1 && <ChevronRight className="hidden h-3.5 w-3.5 text-fg-faint lg:block" aria-hidden />}
            </span>
            {loading && !counts ? (
              <Skeleton className="h-6 w-12" />
            ) : (
              <span className={cn("num text-xl font-semibold leading-none", count > 0 ? TONE_CLASSES[meta.tone].text : "text-fg-faint")}>
                {formatNumber(count)}
              </span>
            )}
            <span className="h-1 w-full overflow-hidden rounded-full bg-surface-3" aria-hidden>
              <span className={cn("block h-full rounded-full", TONE_CLASSES[meta.tone].dot)} style={{ width: `${share}%` }} />
            </span>
            <span className="text-2xs text-fg-muted">{STAGE_HINT[state]}</span>
          </button>
        );
      })}
    </div>
  );
}
