/** Radio list of recorded policy decisions, used to pick a dry-run test input. */
import { useId } from "react";
import { Badge, DecisionBadge, EnforcementBadge, ErrorState, LoadingRows, SimulationBadge } from "@/components/ui";
import { EntityLink } from "@/components/data";
import { cn, timeAgo, formatDateTime } from "@/lib/format";
import type { DecisionSummary, PolicyDecisionMatch } from "./types";

export function DecisionPicker({
  items,
  loading,
  error,
  onRetry,
  selectedId,
  onSelect,
  emptyText,
  label,
}: {
  items: Array<DecisionSummary | PolicyDecisionMatch> | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  emptyText: string;
  label: string;
}) {
  const name = useId();
  if (loading) return <LoadingRows rows={3} />;
  if (error) return <ErrorState error={error} onRetry={onRetry} className="py-6" />;
  if (!items?.length) return <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-xs text-fg-muted">{emptyText}</p>;
  return (
    <div role="radiogroup" aria-label={label} className="max-h-72 divide-y divide-border overflow-y-auto rounded-md border border-border">
      {items.map((d) => {
        const selected = d.id === selectedId;
        return (
          <label
            key={d.id}
            className={cn("flex cursor-pointer items-start gap-2.5 px-3 py-2 transition-colors hover:bg-surface-2/70", selected && "bg-accent/[0.06]")}
          >
            <input type="radio" name={name} className="mt-1 accent-[rgb(var(--accent))]" checked={selected} onChange={() => onSelect(d.id)} />
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="truncate text-[13px] text-fg">
                  <span className="font-mono text-xs">{d.tool_name ?? "unknown tool"}</span>
                  {d.tool_category && <span className="text-fg-faint"> · {d.tool_category}</span>}
                </span>
                <DecisionBadge decision={d.decision} />
                <EnforcementBadge mode={d.enforcement} />
                {"match_mode" in d && d.match_mode === "monitor" && (
                  <Badge tone="neutral" title="This policy matched in monitor mode: recorded only">
                    monitor match
                  </Badge>
                )}
                {d.is_simulation && <SimulationBadge />}
              </div>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-2xs text-fg-faint">
                <span title={formatDateTime(d.evaluated_at)}>{timeAgo(d.evaluated_at)}</span>
                <span className="truncate">agent {d.agent_name ?? d.agent_id}</span>
                <EntityLink type="session" id={d.session_id} className="text-2xs" />
              </div>
            </div>
          </label>
        );
      })}
    </div>
  );
}
