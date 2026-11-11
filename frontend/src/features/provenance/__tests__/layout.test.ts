import { layoutGraph, NODE_HEIGHT, NODE_WIDTH } from "../layout";
import { initialViewport, layoutBounds, nodesBounds, toFlowEdges, toFlowNodes, VIEWPORT, visibleSubgraph } from "../graphModel";
import type { GraphEdge, GraphNode, ProvenanceGraph, RiskyPath } from "../types";

function node(id: string, type: string, extra: Partial<GraphNode> = {}): GraphNode {
  return {
    id,
    type,
    ref_id: id.split(":")[1] ?? id,
    label: id,
    subtitle: null,
    session_id: null,
    trust_level: null,
    severity: null,
    decision: null,
    enforcement: null,
    risk_level: null,
    risk_score: null,
    sensitive: false,
    contains_secrets: false,
    is_simulation: false,
    risk_origin: false,
    observed_at: null,
    attributes: {},
    ...extra,
  };
}

function edge(id: string, src: string, dst: string, relation: string, extra: Partial<GraphEdge> = {}): GraphEdge {
  return { id, src, dst, relation, relation_label: relation, confidence: "observed", basis: "provenance_edge", observed_at: null, session_id: null, ...extra };
}

// README -> item -> session -> Read call -> returned .env item -> session; session -> WebFetch -> destination.
const NODES = [
  node("source:readme", "source", { trust_level: "SUSPICIOUS" }),
  node("context_item:readme", "context_item", { trust_level: "SUSPICIOUS", severity: "critical" }),
  node("finding:inj", "finding", { severity: "critical" }),
  node("session:s1", "session", { risk_level: "high", risk_score: 80 }),
  node("session:child", "session"),
  node("tool_invocation:read", "tool_invocation", { decision: "ALLOW" }),
  node("context_item:env", "context_item", { contains_secrets: true }),
  node("tool_invocation:fetch", "tool_invocation", { decision: "DENY", enforcement: "enforced" }),
  node("destination:evil", "destination", { trust_level: "UNKNOWN" }),
  node("finding:exfil", "finding", { severity: "critical" }),
  node("policy_decision:d1", "policy_decision", { decision: "DENY" }),
];
const EDGES = [
  edge("e1", "source:readme", "context_item:readme", "source_produced_item"),
  edge("e2", "context_item:readme", "session:s1", "item_entered_session"),
  edge("e3", "context_item:readme", "finding:inj", "item_triggered_finding"),
  edge("e4", "session:s1", "tool_invocation:read", "session_invoked_tool"),
  edge("e5", "tool_invocation:read", "context_item:env", "invocation_returned_item"),
  edge("e6", "context_item:env", "session:s1", "item_entered_session"),
  edge("e7", "session:s1", "tool_invocation:fetch", "session_invoked_tool"),
  edge("e8", "tool_invocation:fetch", "destination:evil", "invocation_sent_to", { confidence: "inferred" }),
  edge("e9", "tool_invocation:fetch", "finding:exfil", "finding_evidence", { basis: "finding_record" }),
  edge("e10", "tool_invocation:fetch", "policy_decision:d1", "invocation_decided_by"),
  edge("e11", "session:s1", "session:child", "session_delegated_to"),
];

describe("layoutGraph", () => {
  const layout = layoutGraph(NODES, EDGES);
  const x = (id: string) => layout.nodes.get(id)!.x;

  it("places node types in left-to-right lanes", () => {
    expect(x("source:readme")).toBeLessThan(x("context_item:readme"));
    expect(x("context_item:readme")).toBeLessThan(x("finding:inj"));
    expect(x("finding:inj")).toBeLessThan(x("session:s1"));
    expect(x("session:s1")).toBeLessThan(x("tool_invocation:fetch"));
    expect(x("tool_invocation:fetch")).toBeLessThan(x("destination:evil"));
    expect(x("destination:evil")).toBeLessThan(x("policy_decision:d1"));
    // Same type, same column — even when one item was returned by a tool call (a backwards edge).
    expect(x("context_item:env")).toBe(x("context_item:readme"));
    expect(x("session:child")).toBe(x("session:s1"));
    // Findings raised by content sit next to the context; findings on tool calls sit with outcomes.
    expect(layout.nodes.get("finding:inj")!.lane).toBe("detections");
    expect(layout.nodes.get("finding:exfil")!.lane).toBe("outcomes");
  });

  it("never overlaps nodes within a lane", () => {
    const byColumn = new Map<number, number[]>();
    for (const p of layout.nodes.values()) byColumn.set(p.column, [...(byColumn.get(p.column) ?? []), p.y]);
    for (const ys of byColumn.values()) {
      ys.sort((a, b) => a - b);
      ys.slice(1).forEach((y, i) => expect(y - ys[i]).toBeGreaterThanOrEqual(NODE_HEIGHT));
    }
  });

  it("routes backwards and same-lane edges through side handles", () => {
    expect(layout.handles.get("e2")).toEqual({ sourceHandle: "r-out", targetHandle: "l-in" });
    expect(layout.handles.get("e5")).toEqual({ sourceHandle: "l-out", targetHandle: "r-in" });
    expect(["b-out", "t-out"]).toContain(layout.handles.get("e11")!.sourceHandle);
  });

  it("collapses empty lanes and counts nodes per lane", () => {
    expect(layout.lanes.map((l) => l.key)).not.toContain("agents");
    expect(layout.lanes.find((l) => l.key === "context")!.count).toBe(2);
  });

  it("is deterministic for the same data", () => {
    const again = layoutGraph([...NODES].reverse(), [...EDGES].reverse());
    for (const [id, p] of layout.nodes) expect(again.nodes.get(id)).toEqual(p);
  });
});

describe("graph model", () => {
  const graph = { nodes: NODES, edges: EDGES, scope: { root_node_ids: ["session:s1"] } } as unknown as ProvenanceGraph;
  const path: RiskyPath = {
    id: "rp_1",
    node_ids: ["source:readme", "context_item:readme", "session:s1", "tool_invocation:fetch", "destination:evil", "policy_decision:d1"],
    edge_ids: ["e1", "e2", "e7", "e8", "e10"],
    severity: "high",
    title: "t",
    explanation: "x",
    score: 10,
    category: "exfiltration",
    outcome: "prevented",
    origin_id: "source:readme",
    sink_id: "tool_invocation:fetch",
    session_ids: ["session:s1"],
    cross_session: false,
    order_verified: true,
    reasons: [],
    related_origin_ids: [],
    inferred_edge_ids: ["e8"],
  };

  it("hides optional types unless they are on the highlighted path", () => {
    const hidden = new Set(["policy_decision", "finding"]);
    const plain = visibleSubgraph(graph, hidden, new Set());
    expect(plain.nodes.some((n) => n.type === "policy_decision")).toBe(false);
    expect(plain.edges.some((e) => e.id === "e10")).toBe(false);
    const kept = visibleSubgraph(graph, hidden, new Set(path.node_ids));
    expect(kept.nodes.map((n) => n.id)).toContain("policy_decision:d1");
    expect(kept.nodes.map((n) => n.id)).not.toContain("finding:exfil");
  });

  it("highlights path edges, dims the rest and keeps lane headers non-interactive", () => {
    const layout = layoutGraph(NODES, EDGES);
    const view = { selectedNodeId: null, selectedEdgeId: null, hoveredEdgeId: "e3", path };
    const edges = toFlowEdges(EDGES, layout, view);
    const byId = new Map(edges.map((e) => [e.id, e]));
    expect(byId.get("e7")!.animated).toBe(true);
    expect(byId.get("e7")!.data!.state).toBe("path");
    expect(byId.get("e4")!.data!.state).toBe("dim");
    expect(byId.get("e3")!.data!.showLabel).toBe(true);
    expect(byId.get("e4")!.data!.showLabel).toBe(false);

    const nodes = toFlowNodes(NODES, layout, new Set(["session:s1"]), view);
    const lanes = nodes.filter((n) => n.type === "lane");
    expect(lanes.length).toBe(layout.lanes.length);
    expect(lanes.every((n) => n.selectable === false && n.focusable === false)).toBe(true);
    const flowNode = (id: string) => nodes.find((n) => n.id === id)!;
    expect(flowNode("session:s1").data).toMatchObject({ isRoot: true, onPath: true, dimmed: false });
    expect(flowNode("tool_invocation:read").data).toMatchObject({ onPath: false, dimmed: true });
    // Fixed, declared size: React Flow can fit to these nodes without waiting for a DOM measurement.
    expect(flowNode("session:s1").measured).toEqual({ width: NODE_WIDTH, height: NODE_HEIGHT });
  });
});

describe("initialViewport", () => {
  const layout = layoutGraph(NODES, EDGES);
  const bounds = layoutBounds(layout);

  it("covers every node and the lane headers", () => {
    for (const p of layout.nodes.values()) {
      expect(p.x + NODE_WIDTH).toBeLessThanOrEqual(bounds.x + bounds.width);
      expect(p.y).toBeGreaterThanOrEqual(bounds.y);
    }
    expect(bounds.y).toBeLessThan(layout.top);
  });

  it("centres a graph that fits at a readable zoom", () => {
    const v = initialViewport(bounds, 4000, 2000);
    expect(v.zoom).toBe(VIEWPORT.maxZoom);
    const left = v.x + bounds.x * v.zoom;
    const right = 4000 - (left + bounds.width * v.zoom);
    expect(Math.abs(left - right)).toBeLessThan(1);
  });

  it("starts a wide graph at the sources instead of cutting both sides", () => {
    const v = initialViewport(bounds, 700, 2000);
    expect(v.zoom).toBe(VIEWPORT.readableZoom);
    expect(v.x + bounds.x * v.zoom).toBe(VIEWPORT.padding);
    // It still fits vertically, so it is centred in the space below the legend.
    const top = v.y + bounds.y * v.zoom;
    expect(Math.abs(top - VIEWPORT.top - (2000 - VIEWPORT.top - VIEWPORT.padding - bounds.height * v.zoom) / 2)).toBeLessThan(1);
    // Too tall as well: aligned to the top (below the legend) rather than cut at both ends.
    const tall = initialViewport(bounds, 700, 150);
    expect(tall.y + bounds.y * tall.zoom).toBe(VIEWPORT.top);
  });

  it("shifts just enough to keep the scope root on screen", () => {
    const focus = nodesBounds(layout, ["policy_decision:d1"])!;
    expect(nodesBounds(layout, ["missing"])).toBeNull();
    const v = initialViewport(bounds, 700, 2000, focus);
    const rootRight = v.x + (focus.x + focus.width) * v.zoom;
    expect(rootRight).toBeCloseTo(700 - VIEWPORT.padding);
    expect(v.x + focus.x * v.zoom).toBeGreaterThanOrEqual(VIEWPORT.padding);
    // Never left under the minimap in the bottom-right corner.
    const low = initialViewport(bounds, 700, 260, focus);
    const lowRight = low.x + (focus.x + focus.width) * low.zoom;
    const lowBottom = low.y + (focus.y + focus.height) * low.zoom;
    expect(lowRight <= 700 - VIEWPORT.overlay.width || lowBottom <= 260 - VIEWPORT.overlay.height).toBe(true);
    // A root that is already visible does not move the view.
    const source = nodesBounds(layout, ["source:readme"])!;
    expect(initialViewport(bounds, 700, 2000, source)).toEqual(initialViewport(bounds, 700, 2000));
  });
});
