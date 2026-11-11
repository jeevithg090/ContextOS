import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Bot } from "lucide-react";
import { StatusBadge } from "@/components/ui";
import { RiskMeter } from "@/components/data";
import { cn } from "@/lib/format";
import { ENVIRONMENT_LABELS, frameworkLabel } from "../meta";
import type { GraphNode } from "../types";

export const NODE_WIDTH = 228;
export const NODE_HEIGHT = 88;

export type AgentFlowNode = Node<{ node: GraphNode }, "agent">;

/** Graph node: identity (name, owner, framework, environment), status and current session risk. */
export function AgentNodeCard({ data, selected }: NodeProps<AgentFlowNode>) {
  const n = data.node;
  return (
    <div
      className={cn(
        "cursor-pointer rounded-md border bg-surface px-3 py-2 shadow-panel transition-colors hover:border-accent/60",
        n.status === "quarantined" ? "border-dec-deny/60" : "border-border-strong",
        selected && "ring-1 ring-accent",
      )}
      style={{ width: NODE_WIDTH, height: NODE_HEIGHT }}
      title={`Open ${n.name}`}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} className="!h-1.5 !w-1.5 !min-w-0 !border-0 !bg-fg-faint" />
      <div className="flex items-center gap-1.5">
        <Bot className="h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden />
        <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-fg">{n.name}</span>
        {n.status !== "active" && <StatusBadge status={n.status} />}
      </div>
      <div className="mt-0.5 truncate text-2xs text-fg-muted">
        {frameworkLabel(n.framework)} · {ENVIRONMENT_LABELS[n.environment] ?? n.environment}
        {n.is_simulation ? " · simulation" : ""}
      </div>
      <div className="truncate text-2xs text-fg-faint">{n.owner ? `Owner ${n.owner}` : "No owner"}</div>
      <div className="mt-1 flex items-center justify-between gap-2">
        <RiskMeter score={n.risk_score} level={n.risk_level} size="sm" label={`Session risk of ${n.name}`} />
        {n.open_findings > 0 ? <span className="num text-2xs text-sev-high">{n.open_findings} open findings</span> : <span className="text-2xs text-fg-faint">No open findings</span>}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} className="!h-1.5 !w-1.5 !min-w-0 !border-0 !bg-fg-faint" />
    </div>
  );
}
