/**
 * Turns the API graph + UI state (hidden types, selection, highlighted risky path) into React Flow
 * nodes and edges. Pure functions so they can be unit-tested without rendering a canvas.
 */
import { MarkerType, type Edge, type Node } from "@xyflow/react";
import { toneColor } from "@/components/data";
import { severityTone, type Tone } from "@/lib/domain";
import { NODE_HEIGHT, NODE_WIDTH, type GraphLayout } from "./layout";
import type { GraphEdge, GraphNode, ProvenanceGraph, RiskyPath } from "./types";

export type ProvenanceNodeData = {
  node: GraphNode;
  isRoot: boolean;
  onPath: boolean;
  dimmed: boolean;
  pathTone: Tone | null;
};
export type LaneNodeData = { label: string; count: number };
export type ProvenanceFlowNode = Node<ProvenanceNodeData, "provenance">;
export type LaneFlowNode = Node<LaneNodeData, "lane">;
export type FlowNode = ProvenanceFlowNode | LaneFlowNode;

export type EdgeVisualState = "default" | "dim" | "path" | "active";
export type ProvenanceEdgeData = { edge: GraphEdge; state: EdgeVisualState; showLabel: boolean; color: string };
export type ProvenanceFlowEdge = Edge<ProvenanceEdgeData, "provenance">;

export interface ViewState {
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  hoveredEdgeId: string | null;
  path: RiskyPath | null;
}

/** Nodes and edges to draw: hidden types are removed unless they are on the highlighted path, the
 * scope root, or the selected node (so a selection never points at something invisible). */
export function visibleSubgraph(graph: ProvenanceGraph, hiddenTypes: ReadonlySet<string>, keep: ReadonlySet<string>) {
  const nodes = graph.nodes.filter((n) => !hiddenTypes.has(n.type) || keep.has(n.id));
  const ids = new Set(nodes.map((n) => n.id));
  const edges = graph.edges.filter((e) => ids.has(e.src) && ids.has(e.dst));
  return { nodes, edges };
}

export const LANE_HEADER_OFFSET = 52;

export interface Bounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Area covered by the laid-out nodes, lane headers included. */
export function layoutBounds(layout: GraphLayout): Bounds {
  let right = 0;
  let bottom = layout.top;
  for (const p of layout.nodes.values()) {
    right = Math.max(right, p.x + NODE_WIDTH);
    bottom = Math.max(bottom, p.y + NODE_HEIGHT);
  }
  const y = layout.top - LANE_HEADER_OFFSET;
  return { x: 0, y, width: Math.max(right, NODE_WIDTH), height: Math.max(bottom - y, NODE_HEIGHT) };
}

/** Area covered by the given nodes (e.g. the scope root), or null when none is placed. */
export function nodesBounds(layout: GraphLayout, ids: Iterable<string>): Bounds | null {
  const placed = [...ids].map((id) => layout.nodes.get(id)).filter((p): p is NonNullable<typeof p> => !!p);
  if (placed.length === 0) return null;
  const x = Math.min(...placed.map((p) => p.x));
  const y = Math.min(...placed.map((p) => p.y));
  return { x, y, width: Math.max(...placed.map((p) => p.x)) + NODE_WIDTH - x, height: Math.max(...placed.map((p) => p.y)) + NODE_HEIGHT - y };
}

/** `overlay` is the minimap's footprint in the bottom-right corner (canvas pixels, margin included). */
export const VIEWPORT = { padding: 24, top: 52, readableZoom: 0.6, maxZoom: 1, overlay: { width: 224, height: 172 } };

/**
 * First viewport for a graph. When the whole graph fits at a readable zoom it is centred; otherwise it
 * starts at the readable zoom aligned to the left (sources) and top, so the flow reads from its
 * beginning instead of being cut on both sides — shifted just enough to keep `focus` (the scope root)
 * on screen. `top` leaves room for the legend in the corner.
 */
export function initialViewport(bounds: Bounds, width: number, height: number, focus: Bounds | null = null, opts = VIEWPORT) {
  const availW = Math.max(1, width - 2 * opts.padding);
  const availH = Math.max(1, height - opts.top - opts.padding);
  const fit = Math.min(availW / bounds.width, availH / bounds.height);
  const zoom = Math.min(opts.maxZoom, Math.max(opts.readableZoom, fit));
  const w = bounds.width * zoom;
  const h = bounds.height * zoom;
  let x = w <= availW ? opts.padding + (availW - w) / 2 - bounds.x * zoom : opts.padding - bounds.x * zoom;
  let y = h <= availH ? opts.top + (availH - h) / 2 - bounds.y * zoom : opts.top - bounds.y * zoom;
  if (focus) {
    const overflowRight = x + (focus.x + focus.width) * zoom - (opts.padding + availW);
    if (overflowRight > 0) x = Math.max(x - overflowRight, opts.padding - focus.x * zoom);
    const overflowBottom = y + (focus.y + focus.height) * zoom - (opts.top + availH);
    if (overflowBottom > 0) y = Math.max(y - overflowBottom, opts.top - focus.y * zoom);
    // Keep the focus clear of the minimap: move up when there is room, otherwise left.
    const right = x + (focus.x + focus.width) * zoom;
    const top = y + focus.y * zoom;
    const bottom = y + (focus.y + focus.height) * zoom;
    const overlayLeft = width - opts.overlay.width;
    const overlayTop = height - opts.overlay.height;
    if (right > overlayLeft && bottom > overlayTop) {
      const up = bottom - overlayTop + 8;
      if (top - up >= opts.top) y -= up;
      else x -= right - overlayLeft + 8;
    }
  }
  return { x, y, zoom };
}

export function toFlowNodes(nodes: GraphNode[], layout: GraphLayout, rootIds: ReadonlySet<string>, view: ViewState): FlowNode[] {
  const pathNodes = view.path ? new Set(view.path.node_ids) : null;
  const pathTone = view.path ? severityTone(view.path.severity) : null;
  const flow: FlowNode[] = layout.lanes.map((lane) => ({
    id: `lane:${lane.key}`,
    type: "lane",
    position: { x: lane.x, y: layout.top - LANE_HEADER_OFFSET },
    data: { label: lane.label, count: lane.count },
    draggable: false,
    selectable: false,
    focusable: false,
    width: NODE_WIDTH,
  }));
  for (const node of nodes) {
    const place = layout.nodes.get(node.id);
    if (!place) continue;
    const onPath = pathNodes?.has(node.id) ?? false;
    flow.push({
      id: node.id,
      type: "provenance",
      position: { x: place.x, y: place.y },
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
      // Nodes have a fixed size. Declaring it means React Flow does not discard the measurement each
      // time these objects are rebuilt, so fitView (risky-path focus) works immediately after a change.
      measured: { width: NODE_WIDTH, height: NODE_HEIGHT },
      selected: view.selectedNodeId === node.id,
      draggable: false,
      ariaLabel: `${node.type.replace(/_/g, " ")}: ${node.label}`,
      data: { node, isRoot: rootIds.has(node.id), onPath, dimmed: pathNodes !== null && !onPath, pathTone: onPath ? pathTone : null },
    });
  }
  return flow;
}

export function edgeDash(edge: Pick<GraphEdge, "confidence" | "basis">): string | undefined {
  if (edge.confidence === "inferred") return "6 4";
  if (edge.basis === "finding_record") return "2 4";
  return undefined;
}

export function toFlowEdges(edges: GraphEdge[], layout: GraphLayout, view: ViewState): ProvenanceFlowEdge[] {
  const pathEdges = view.path ? new Set(view.path.edge_ids) : null;
  const pathColor = view.path ? toneColor(severityTone(view.path.severity)) : null;
  const touchesSelection = (e: GraphEdge) => view.selectedNodeId !== null && (e.src === view.selectedNodeId || e.dst === view.selectedNodeId);
  return edges.flatMap((edge) => {
    const handles = layout.handles.get(edge.id);
    if (!handles) return [];
    const onPath = pathEdges?.has(edge.id) ?? false;
    const active = view.selectedEdgeId === edge.id || view.hoveredEdgeId === edge.id || touchesSelection(edge);
    const state: EdgeVisualState = onPath ? "path" : active ? "active" : pathEdges ? "dim" : "default";
    const color = state === "path" && pathColor ? pathColor : state === "active" ? "rgb(var(--fg-muted))" : "rgb(var(--border-strong))";
    return [
      {
        id: edge.id,
        type: "provenance" as const,
        source: edge.src,
        target: edge.dst,
        sourceHandle: handles.sourceHandle,
        targetHandle: handles.targetHandle,
        selected: view.selectedEdgeId === edge.id,
        animated: onPath,
        zIndex: onPath ? 2 : active ? 1 : 0,
        markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color },
        ariaLabel: `${edge.relation_label}${edge.confidence === "inferred" ? " (inferred)" : ""}`,
        data: { edge, state, color, showLabel: view.selectedEdgeId === edge.id || view.hoveredEdgeId === edge.id },
      },
    ];
  });
}
