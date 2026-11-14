/**
 * Identity & delegation graph: agents as nodes, observed delegations/messages as edges (React Flow,
 * dagre layout). Edges are observed relationships, never causation. Edges whose child consumed
 * lower-trust content than its parent are highlighted as trust-boundary crossings.
 */
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Background, Controls, MarkerType, ReactFlow, type Edge } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import { Network, ShieldAlert } from "lucide-react";
import { Checkbox, EmptyState, ErrorState, Skeleton } from "@/components/ui";
import { toneColor } from "@/components/data";
import { useTheme } from "@/lib/theme";
import { useAgentGraph } from "../api";
import type { GraphEdge, GraphNode } from "../types";
import { AgentNodeCard, NODE_HEIGHT, NODE_WIDTH, type AgentFlowNode } from "./AgentNodeCard";
import { EdgeDetails, RelationshipList } from "./RelationshipList";

const nodeTypes = { agent: AgentNodeCard };

function layout(nodes: GraphNode[], edges: GraphEdge[]): AgentFlowNode[] {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 28, ranksep: 120, marginx: 16, marginy: 16 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id);
    return { id: n.id, type: "agent", position: { x: p.x - NODE_WIDTH / 2, y: p.y - NODE_HEIGHT / 2 }, data: { node: n } };
  });
}

function toFlowEdge(e: GraphEdge, selected: boolean): Edge {
  const color = e.crosses_trust_boundary ? toneColor("danger") : toneColor(selected ? "accent" : "neutral");
  return {
    id: e.id,
    source: e.source,
    target: e.target,
    label: `${e.relationship_type === "messages" ? "messages" : "delegates"} · ${e.event_count}×`,
    style: { stroke: color, strokeWidth: e.crosses_trust_boundary || selected ? 2 : 1.25, strokeDasharray: e.relationship_type === "messages" ? "5 4" : undefined },
    markerEnd: { type: MarkerType.ArrowClosed, color, width: 16, height: 16 },
    labelStyle: { fill: "rgb(var(--fg-muted))", fontSize: 11 },
    labelBgStyle: { fill: "rgb(var(--surface))" },
    labelBgPadding: [4, 2],
    interactionWidth: 18,
  };
}

export function AgentGraphView({ includeSimulated }: { includeSimulated: boolean }) {
  const theme = useTheme().resolved;
  const graph = useAgentGraph(includeSimulated);
  const navigate = useNavigate();
  const [showIsolated, setShowIsolated] = useState(false);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);

  const data = graph.data;
  const connected = useMemo(() => new Set((data?.edges ?? []).flatMap((e) => [e.source, e.target])), [data]);
  const visibleNodes = useMemo(() => (data?.nodes ?? []).filter((n) => showIsolated || connected.has(n.id)), [data, showIsolated, connected]);
  const flowNodes = useMemo(() => layout(visibleNodes, data?.edges ?? []), [visibleNodes, data]);
  const flowEdges = useMemo(() => (data?.edges ?? []).map((e) => toFlowEdge(e, e.id === selectedEdge)), [data, selectedEdge]);
  const byId = useMemo(() => new Map((data?.nodes ?? []).map((n) => [n.id, n])), [data]);

  if (graph.isLoading) return <Skeleton className="h-[520px] w-full" />;
  if (graph.error) return <ErrorState error={graph.error} onRetry={() => graph.refetch()} />;
  if (!data || data.nodes.length === 0) {
    return <EmptyState icon={<Network className="h-5 w-5" />} title="No agents yet" description="Agents appear here once an integration reports events or you register one." />;
  }

  const crossings = data.edges.filter((e) => e.crosses_trust_boundary).length;
  const isolated = data.nodes.length - connected.size;
  const edge = data.edges.find((e) => e.id === selectedEdge) ?? null;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-fg-muted">
        <span>
          <span className="num text-fg">{data.nodes.length}</span> agents · <span className="num text-fg">{data.edges.length}</span> observed relationships
        </span>
        {crossings > 0 && (
          <span className="inline-flex items-center gap-1 text-danger">
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
            {crossings} cross a trust boundary
          </span>
        )}
        {isolated > 0 && data.edges.length > 0 && <Checkbox label={`Show ${isolated} agents without relationships`} checked={showIsolated} onChange={setShowIsolated} />}
        {data.truncated && <span className="text-warn">Showing the 500 most recently active agents.</span>}
      </div>

      {data.edges.length === 0 && !showIsolated ? (
        <div className="panel">
          <EmptyState
            icon={<Network className="h-5 w-5" />}
            title="No delegation or messaging observed yet"
            description="Edges appear when an agent reports agent.delegated or agent.message events, or a session names a parent session."
            action={<Checkbox label={`Show all ${data.nodes.length} agents`} checked={showIsolated} onChange={setShowIsolated} />}
          />
        </div>
      ) : (
        <div className="panel relative h-[560px] overflow-hidden" aria-label="Agent identity and delegation graph">
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2, maxZoom: 1.2 }}
            minZoom={0.2}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable
            onNodeClick={(_, node) => navigate(`/agents/${encodeURIComponent(node.id)}`)}
            onEdgeClick={(_, e) => setSelectedEdge((cur) => (cur === e.id ? null : e.id))}
            onPaneClick={() => setSelectedEdge(null)}
            colorMode={theme}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="rgb(var(--border))" gap={20} size={1} />
            <Controls showInteractive={false} position="bottom-right" />
          </ReactFlow>
          <Legend />
        </div>
      )}

      {edge && <EdgeDetails edge={edge} source={byId.get(edge.source)} target={byId.get(edge.target)} onClose={() => setSelectedEdge(null)} />}
      <p className="text-xs text-fg-muted">{data.note}</p>
      {data.edges.length > 0 && <RelationshipList edges={data.edges} nodes={byId} selectedId={selectedEdge} onSelect={setSelectedEdge} />}
    </div>
  );
}

function Legend() {
  return (
    <div className="pointer-events-none absolute left-3 top-3 space-y-1 rounded border border-border bg-surface/95 px-2.5 py-2 text-2xs text-fg-muted" aria-hidden>
      <LegendLine color={toneColor("neutral")} label="Delegation (parent → child)" />
      <LegendLine color={toneColor("neutral")} dashed label="Messages (sender → receiver)" />
      <LegendLine color={toneColor("danger")} label="Crosses a trust boundary" />
    </div>
  );
}

function LegendLine({ color, label, dashed }: { color: string; label: string; dashed?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <svg width="22" height="6" aria-hidden>
        <line x1="0" y1="3" x2="22" y2="3" stroke={color} strokeWidth="2" strokeDasharray={dashed ? "4 3" : undefined} />
      </svg>
      {label}
    </div>
  );
}
