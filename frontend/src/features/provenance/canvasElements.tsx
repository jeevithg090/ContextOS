/** Custom React Flow node and edge components for the provenance canvas. */
import { memo } from "react";
import { BaseEdge, EdgeLabelRenderer, getBezierPath, Handle, Position, type EdgeProps, type NodeProps } from "@xyflow/react";
import { AlertTriangle, FlaskConical, KeyRound, Lock } from "lucide-react";
import { toneColor } from "@/components/data";
import { Badge, DecisionBadge, SeverityBadge, TrustBadge } from "@/components/ui";
import { TONE_CLASSES } from "@/lib/domain";
import { cn } from "@/lib/format";
import { edgeDash, type LaneFlowNode, type ProvenanceFlowEdge, type ProvenanceFlowNode } from "./graphModel";
import { NODE_HEIGHT, NODE_WIDTH, type HandleId } from "./layout";
import { nodeTone, nodeTypeMeta, riskTone } from "./nodeMeta";
import type { GraphNode } from "./types";

const HANDLES: Array<{ id: HandleId; type: "source" | "target"; position: Position }> = [
  { id: "l-in", type: "target", position: Position.Left },
  { id: "l-out", type: "source", position: Position.Left },
  { id: "r-in", type: "target", position: Position.Right },
  { id: "r-out", type: "source", position: Position.Right },
  { id: "t-in", type: "target", position: Position.Top },
  { id: "t-out", type: "source", position: Position.Top },
  { id: "b-in", type: "target", position: Position.Bottom },
  { id: "b-out", type: "source", position: Position.Bottom },
];

function StatusLine({ node }: { node: GraphNode }) {
  switch (node.type) {
    case "source":
    case "destination":
      return <TrustBadge level={node.trust_level} />;
    case "context_item":
      return (
        <>
          <TrustBadge level={node.trust_level} />
          {node.severity && node.severity !== "info" && <SeverityBadge severity={node.severity} />}
        </>
      );
    case "finding":
      return <SeverityBadge severity={node.severity} />;
    case "tool_invocation":
    case "policy_decision":
      return (
        <>
          {node.decision ? <DecisionBadge decision={node.decision} /> : <Badge>No decision</Badge>}
          {node.attributes.ran_despite_block === true ? (
            <Badge tone="danger" title="The tool reported a result although ContextOS blocked it — nothing was prevented">
              Ran anyway
            </Badge>
          ) : node.enforcement && node.enforcement !== "enforced" && (
            <Badge tone={node.enforcement === "advisory" ? "warn" : "neutral"} title="The decision could not be enforced at an execution boundary">
              {node.enforcement === "advisory" ? "Advisory" : "Observed"}
            </Badge>
          )}
        </>
      );
    case "session":
    case "agent":
      return node.risk_score !== null ? (
        <Badge tone={node.type === "session" ? riskTone(node.risk_level) : "neutral"} title="Risk score (0–100) computed by ContextOS">
          Risk {node.risk_score}
        </Badge>
      ) : null;
    case "resource":
      return node.sensitive ? <Badge tone="warn">Sensitive</Badge> : null;
    default:
      return null;
  }
}

function ProvenanceNodeView({ data, selected }: NodeProps<ProvenanceFlowNode>) {
  const { node, isRoot, onPath, dimmed, pathTone } = data;
  const meta = nodeTypeMeta(node.type);
  const Icon = meta.icon;
  const tone = nodeTone(node);
  return (
    <div
      style={{ width: NODE_WIDTH, height: NODE_HEIGHT, borderColor: onPath && pathTone && !selected ? toneColor(pathTone) : undefined }}
      className={cn(
        "group flex overflow-hidden rounded-md border bg-surface text-left shadow-panel transition-[opacity,box-shadow] duration-150",
        selected ? "border-accent ring-2 ring-accent/40" : "border-border-strong",
        onPath && !selected && "shadow-pop",
        isRoot && !selected && "ring-1 ring-accent/50",
        dimmed && "opacity-30",
      )}
    >
      {HANDLES.map((h) => (
        <Handle key={h.id} id={h.id} type={h.type} position={h.position} isConnectable={false} className="!h-1 !w-1 !min-h-0 !min-w-0 !border-0 !bg-transparent" />
      ))}
      <span className={cn("w-1 shrink-0", TONE_CLASSES[tone].dot)} aria-hidden />
      <div className="flex min-w-0 flex-1 flex-col justify-center gap-0.5 px-2.5">
        <div className="flex min-w-0 items-center gap-1.5">
          <Icon className="h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden />
          <span className="truncate text-[12.5px] font-medium leading-4 text-fg" title={node.label}>
            {node.label}
          </span>
          <span className="ml-auto flex shrink-0 items-center gap-1 text-fg-faint">
            {node.risk_origin && <AlertTriangle className="h-3 w-3 text-sev-high" aria-label="Starts a risky path" />}
            {node.contains_secrets && <KeyRound className="h-3 w-3 text-warn" aria-label="Secrets involved (redacted)" />}
            {node.sensitive && !node.contains_secrets && <Lock className="h-3 w-3 text-warn" aria-label="Sensitive" />}
            {node.is_simulation && <FlaskConical className="h-3 w-3 text-accent" aria-label="Simulation data" />}
          </span>
        </div>
        <div className="truncate text-2xs leading-4 text-fg-faint" title={node.subtitle ?? undefined}>
          {isRoot ? "Scope · " : ""}
          {meta.label}
          {node.subtitle ? ` · ${node.subtitle}` : ""}
        </div>
        <div className="flex min-w-0 items-center gap-1 overflow-hidden">
          <StatusLine node={node} />
        </div>
      </div>
    </div>
  );
}

function LaneHeaderView({ data }: NodeProps<LaneFlowNode>) {
  return (
    <div style={{ width: NODE_WIDTH }} className="pointer-events-none flex items-center justify-between border-b border-border pb-1.5">
      <span className="label-caps">{data.label}</span>
      <span className="num text-2xs text-fg-faint">{data.count}</span>
    </div>
  );
}

function ProvenanceEdgeView({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, markerEnd }: EdgeProps<ProvenanceFlowEdge>) {
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition, curvature: 0.3 });
  if (!data) return null;
  const { edge, state, color, showLabel } = data;
  const width = state === "path" ? 2.25 : state === "active" ? 1.75 : 1.25;
  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        interactionWidth={14}
        style={{ stroke: color, strokeWidth: width, strokeDasharray: state === "path" ? undefined : edgeDash(edge), opacity: state === "dim" ? 0.25 : 1 }}
      />
      {showLabel && (
        <EdgeLabelRenderer>
          <div
            style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
            className="nodrag nopan pointer-events-none absolute z-10 whitespace-nowrap rounded border border-border-strong bg-surface-3 px-1.5 py-0.5 text-2xs text-fg shadow-pop"
          >
            {edge.relation_label}
            {edge.confidence === "inferred" && <span className="text-fg-muted"> · inferred</span>}
            {edge.basis === "finding_record" && <span className="text-fg-muted"> · from finding</span>}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export const nodeTypes = { provenance: memo(ProvenanceNodeView), lane: memo(LaneHeaderView) };
export const edgeTypes = { provenance: memo(ProvenanceEdgeView) };
