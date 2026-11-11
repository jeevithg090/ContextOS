/** Side list of risky paths found by the provenance engine. Selecting one highlights it on the canvas. */
import { ArrowRight, Route } from "lucide-react";
import { Badge, Button, EmptyState, SeverityBadge } from "@/components/ui";
import { cn, pluralize } from "@/lib/format";
import { outcomeMeta } from "./nodeMeta";
import type { GraphNode, RiskyPath } from "./types";

interface RiskyPathListProps {
  paths: RiskyPath[];
  nodesById: Map<string, GraphNode>;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  onInspect: (nodeId: string) => void;
}

function PathChain({ path, nodesById }: { path: RiskyPath; nodesById: Map<string, GraphNode> }) {
  const steps = [path.origin_id, ...path.session_ids, path.sink_id].filter((id): id is string => !!id);
  const unique = steps.filter((id, i) => steps.indexOf(id) === i);
  return (
    <div className="mt-1.5 flex min-w-0 flex-wrap items-center gap-x-1 gap-y-0.5 text-2xs text-fg-muted">
      {unique.map((id, i) => (
        <span key={id} className="inline-flex min-w-0 items-center gap-1">
          {i > 0 && <ArrowRight className="h-3 w-3 shrink-0 text-fg-faint" aria-hidden />}
          <span className="max-w-[140px] truncate" title={nodesById.get(id)?.label}>
            {nodesById.get(id)?.label ?? "Unknown"}
          </span>
        </span>
      ))}
    </div>
  );
}

export function RiskyPathList({ paths, nodesById, selectedId, onSelect, onInspect }: RiskyPathListProps) {
  if (paths.length === 0) {
    return (
      <EmptyState
        icon={<Route className="h-4 w-4" />}
        title="No risky paths in this scope"
        description="A risky path is untrusted content that reached a session which then touched sensitive data, tried to send data to an unapproved destination, or was stopped by policy. None was found here."
      />
    );
  }
  return (
    <ul className="divide-y divide-border" aria-label="Risky paths">
      {paths.map((path) => {
        const selected = path.id === selectedId;
        const outcome = outcomeMeta(path.outcome);
        return (
          <li key={path.id} className={cn(selected && "bg-accent/[0.05]")}>
            <button
              type="button"
              aria-pressed={selected}
              onClick={() => onSelect(selected ? null : path.id)}
              className="w-full px-4 py-3 text-left transition-colors hover:bg-surface-2/60 focus-visible:bg-surface-2/60"
            >
              <div className="flex flex-wrap items-center gap-1.5">
                <SeverityBadge severity={path.severity} />
                <Badge tone={outcome.tone} title={outcome.description}>
                  {outcome.label}
                </Badge>
                {path.cross_session && (
                  <Badge tone="accent" title="The path crosses a delegation or agent message between sessions">
                    Multi-agent
                  </Badge>
                )}
                <span className="num ml-auto text-2xs text-fg-faint" title="Additive, explainable score (see reasons)">
                  score {path.score}
                </span>
              </div>
              <div className="mt-1.5 text-[13px] leading-snug text-fg">{path.title}</div>
              <PathChain path={path} nodesById={nodesById} />
            </button>
            {selected && (
              <div className="space-y-2.5 px-4 pb-3.5 text-xs">
                <p className="leading-relaxed text-fg-muted">{path.explanation}</p>
                {path.reasons.length > 0 && (
                  <div>
                    <div className="label-caps mb-1">Why it scored {path.score}</div>
                    <ul className="list-disc space-y-0.5 pl-4 text-fg-muted">
                      {path.reasons.map((reason) => (
                        <li key={reason}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {!path.order_verified && (
                  <p className="text-warn">A timestamp was missing for at least one step, so the order of events could not be verified.</p>
                )}
                {path.inferred_edge_ids.length > 0 && (
                  <p className="text-fg-muted">Includes {pluralize(path.inferred_edge_ids.length, "inferred step")} (dashed on the canvas).</p>
                )}
                {path.related_origin_ids.length > 0 && (
                  <p className="text-fg-muted">
                    {pluralize(path.related_origin_ids.length, "other untrusted origin")} reached the same session by the same route.
                  </p>
                )}
                <div className="flex flex-wrap gap-2 pt-0.5">
                  {path.origin_id && (
                    <Button size="xs" variant="outline" onClick={() => onInspect(path.origin_id as string)}>
                      Inspect origin
                    </Button>
                  )}
                  {path.sink_id && (
                    <Button size="xs" variant="outline" onClick={() => onInspect(path.sink_id as string)}>
                      Inspect tool call
                    </Button>
                  )}
                </div>
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
