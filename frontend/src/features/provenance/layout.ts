/**
 * Left-to-right provenance layout.
 *
 * Columns are fixed lanes (sources → context → sessions → tool calls → resources/destinations), so every
 * node type lines up and the canvas reads like a flow. dagre supplies the vertical order inside each lane
 * (crossing minimisation): edges are given to dagre oriented by lane, with `minlen` equal to the lane
 * distance, and edges that point backwards (a tool call that returned content, an agent message) are
 * reversed for layout only. A final pass removes vertical overlaps within a lane.
 */
import dagre from "dagre";
import { LANES, laneOf, type LaneKey } from "./nodeMeta";
import type { GraphEdge, GraphNode } from "./types";

export const NODE_WIDTH = 220;
export const NODE_HEIGHT = 68;
export const LANE_GAP = 80;
const ROW_GAP = 14;

export type HandleId = "l-in" | "l-out" | "r-in" | "r-out" | "t-in" | "t-out" | "b-in" | "b-out";

export interface PlacedNode {
  id: string;
  /** Top-left corner (React Flow coordinates). */
  x: number;
  y: number;
  lane: LaneKey;
  column: number;
}

export interface LaneHeader {
  key: LaneKey;
  label: string;
  x: number;
  count: number;
}

export interface GraphLayout {
  nodes: Map<string, PlacedNode>;
  lanes: LaneHeader[];
  handles: Map<string, { sourceHandle: HandleId; targetHandle: HandleId }>;
  /** Smallest y of any node (lane headers sit above it). */
  top: number;
}

export function layoutGraph(nodes: GraphNode[], edges: GraphEdge[]): GraphLayout {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const valid = edges
    .filter((e) => e.src !== e.dst && byId.has(e.src) && byId.has(e.dst))
    .sort((a, b) => a.id.localeCompare(b.id));
  const incoming = new Map<string, GraphEdge[]>();
  for (const e of valid) incoming.set(e.dst, [...(incoming.get(e.dst) ?? []), e]);

  const laneKeyOf = new Map(nodes.map((n) => [n.id, laneOf(n, incoming.get(n.id), (id) => byId.get(id)?.type)]));
  const usedLanes = LANES.filter((lane) => nodes.some((n) => laneKeyOf.get(n.id) === lane.key));
  const columnOfLane = new Map<LaneKey, number>(usedLanes.map((lane, i) => [lane.key, i]));
  const column = (id: string) => columnOfLane.get(laneKeyOf.get(id) as LaneKey) ?? 0;

  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({ rankdir: "LR", nodesep: ROW_GAP, ranksep: LANE_GAP, marginx: 0, marginy: 0 });
  g.setDefaultEdgeLabel(() => ({}));
  // Stable insertion order keeps the layout deterministic for the same data.
  const ordered = [...nodes].sort((a, b) => column(a.id) - column(b.id) || a.id.localeCompare(b.id));
  for (const n of ordered) g.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  for (const e of valid) {
    const a = column(e.src);
    const b = column(e.dst);
    const [from, to] = a <= b ? [e.src, e.dst] : [e.dst, e.src];
    g.setEdge(from, to, { minlen: Math.max(1, Math.abs(b - a)), weight: a === b ? 1 : 2 }, e.id);
  }
  dagre.layout(g);

  const columns = new Map<number, Array<{ id: string; y: number }>>();
  for (const n of ordered) {
    const c = column(n.id);
    const point = g.node(n.id) as { y?: number } | undefined;
    columns.set(c, [...(columns.get(c) ?? []), { id: n.id, y: point?.y ?? 0 }]);
  }

  const placed = new Map<string, PlacedNode>();
  let top = Number.POSITIVE_INFINITY;
  for (const [c, entries] of columns) {
    entries.sort((p, q) => p.y - q.y || p.id.localeCompare(q.id));
    let previous = Number.NEGATIVE_INFINITY;
    for (const entry of entries) {
      const center = Math.max(entry.y, previous + NODE_HEIGHT + ROW_GAP);
      previous = center;
      const y = center - NODE_HEIGHT / 2;
      top = Math.min(top, y);
      placed.set(entry.id, { id: entry.id, x: c * (NODE_WIDTH + LANE_GAP), y, lane: laneKeyOf.get(entry.id) as LaneKey, column: c });
    }
  }

  const handles = new Map<string, { sourceHandle: HandleId; targetHandle: HandleId }>();
  for (const e of valid) {
    const s = placed.get(e.src);
    const t = placed.get(e.dst);
    if (!s || !t) continue;
    if (s.column < t.column) handles.set(e.id, { sourceHandle: "r-out", targetHandle: "l-in" });
    else if (s.column > t.column) handles.set(e.id, { sourceHandle: "l-out", targetHandle: "r-in" });
    else if (s.y <= t.y) handles.set(e.id, { sourceHandle: "b-out", targetHandle: "t-in" });
    else handles.set(e.id, { sourceHandle: "t-out", targetHandle: "b-in" });
  }

  const lanes = usedLanes.map((lane, i) => ({
    key: lane.key,
    label: lane.label,
    x: i * (NODE_WIDTH + LANE_GAP),
    count: nodes.filter((n) => laneKeyOf.get(n.id) === lane.key).length,
  }));
  return { nodes: placed, lanes, handles, top: Number.isFinite(top) ? top : 0 };
}
