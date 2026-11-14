/** React Flow canvas for one provenance graph: lanes, custom nodes, hover labels, path highlight. */
import "@xyflow/react/dist/style.css";
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type EdgeChange,
  type NodeChange,
} from "@xyflow/react";
import { toneColor } from "@/components/data";
import { useTheme } from "@/lib/theme";
import { edgeTypes, nodeTypes } from "./canvasElements";
import {
  initialViewport,
  layoutBounds,
  nodesBounds,
  toFlowEdges,
  toFlowNodes,
  visibleSubgraph,
  type FlowNode,
  type ProvenanceFlowEdge,
} from "./graphModel";
import { layoutGraph } from "./layout";
import { Legend } from "./Legend";
import { nodeTone } from "./nodeMeta";
import type { ProvenanceGraph, RiskyPath } from "./types";

export interface CanvasSelection {
  nodeId: string | null;
  edgeId: string | null;
}

interface ProvenanceCanvasProps {
  graph: ProvenanceGraph;
  hiddenTypes: ReadonlySet<string>;
  selection: CanvasSelection;
  path: RiskyPath | null;
  onSelectNode: (id: string) => void;
  onSelectEdge: (id: string) => void;
  onClearSelection: () => void;
  /** Changes when the scope changes; the canvas remounts and sets a fresh initial viewport. */
  scopeKey: string;
}

const LARGE_GRAPH = 180;
const IS_MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent);

function Canvas({ graph, hiddenTypes, selection, path, onSelectNode, onSelectEdge, onClearSelection }: ProvenanceCanvasProps) {
  const theme = useTheme().resolved;
  const [hoveredEdgeId, setHoveredEdgeId] = useState<string | null>(null);
  const { fitView, setViewport } = useReactFlow();
  const containerRef = useRef<HTMLDivElement>(null);

  const rootIds = useMemo(() => new Set(graph.scope.root_node_ids), [graph.scope.root_node_ids]);
  const keep = useMemo(() => {
    const ids = new Set<string>(rootIds);
    path?.node_ids.forEach((id) => ids.add(id));
    if (selection.nodeId) ids.add(selection.nodeId);
    return ids;
  }, [rootIds, path, selection.nodeId]);
  const visible = useMemo(() => visibleSubgraph(graph, hiddenTypes, keep), [graph, hiddenTypes, keep]);
  const layout = useMemo(() => layoutGraph(visible.nodes, visible.edges), [visible]);
  const view = useMemo(
    () => ({ selectedNodeId: selection.nodeId, selectedEdgeId: selection.edgeId, hoveredEdgeId, path }),
    [selection.nodeId, selection.edgeId, hoveredEdgeId, path],
  );
  const nodes = useMemo(() => toFlowNodes(visible.nodes, layout, rootIds, view), [visible.nodes, layout, rootIds, view]);
  const edges = useMemo(() => toFlowEdges(visible.edges, layout, view), [visible.edges, layout, view]);

  // First view per scope (the canvas remounts when the scope changes): readable, starting at the sources.
  // Only the first layout sets it; later type toggles keep whatever view the user has panned to.
  const layoutRef = useRef(layout);
  layoutRef.current = layout;
  const onInit = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    const current = layoutRef.current;
    void setViewport(initialViewport(layoutBounds(current), el.clientWidth, el.clientHeight, nodesBounds(current, rootIds)));
  }, [setViewport, rootIds]);

  useEffect(() => {
    if (!path) return;
    const frame = requestAnimationFrame(() => void fitView({ nodes: path.node_ids.map((id) => ({ id })), padding: 0.12, duration: 350, maxZoom: 1.1 }));
    return () => cancelAnimationFrame(frame);
  }, [path, fitView]);

  // Keyboard selection (Tab to a node, Enter) arrives as select changes; clicks are handled below too.
  const onNodesChange = useCallback(
    (changes: NodeChange<FlowNode>[]) => {
      const picked = changes.find((c) => c.type === "select" && c.selected && !c.id.startsWith("lane:"));
      if (picked && picked.type === "select") onSelectNode(picked.id);
    },
    [onSelectNode],
  );
  const onEdgesChange = useCallback(
    (changes: EdgeChange<ProvenanceFlowEdge>[]) => {
      const picked = changes.find((c) => c.type === "select" && c.selected);
      if (picked && picked.type === "select") onSelectEdge(picked.id);
    },
    [onSelectEdge],
  );
  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") onClearSelection();
  };
  const miniMapColor = useCallback((n: FlowNode) => (n.type === "provenance" ? toneColor(nodeTone(n.data.node)) : "transparent"), []);

  return (
    <div ref={containerRef} className="h-full w-full" onKeyDown={onKeyDown}>
      <ReactFlow<FlowNode, ProvenanceFlowEdge>
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={(_, node) => node.type === "provenance" && onSelectNode(node.id)}
        onEdgeClick={(_, edge) => onSelectEdge(edge.id)}
        onPaneClick={onClearSelection}
        onEdgeMouseEnter={(_, edge) => setHoveredEdgeId(edge.id)}
        onEdgeMouseLeave={() => setHoveredEdgeId(null)}
        nodesDraggable={false}
        nodesConnectable={false}
        edgesReconnectable={false}
        // The canvas sits in a scrolling page: the wheel scrolls the page, and ⌘/Ctrl + wheel or a
        // trackpad pinch zooms (React Flow's zoom activation key), so the page never traps scrolling.
        zoomOnScroll={false}
        preventScrolling={false}
        deleteKeyCode={null}
        selectionKeyCode={null}
        multiSelectionKeyCode={null}
        onlyRenderVisibleElements={visible.nodes.length > LARGE_GRAPH}
        onInit={onInit}
        minZoom={0.08}
        maxZoom={1.8}
        colorMode={theme}
        proOptions={{ hideAttribution: true }}
        aria-label="Provenance graph"
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="rgb(var(--border-strong))" />
        <Controls showInteractive={false} position="bottom-left" />
        <MiniMap
          pannable
          zoomable
          position="bottom-right"
          nodeColor={miniMapColor}
          nodeStrokeWidth={0}
          maskColor="rgb(var(--bg) / 0.65)"
          ariaLabel="Graph overview"
          className="!rounded-md !border !border-border"
        />
        <Panel position="top-left">
          <Legend visibleTypes={new Set(visible.nodes.map((n) => n.type))} />
        </Panel>
        <Panel position="bottom-center" className="pointer-events-none hidden lg:block">
          <span className="whitespace-nowrap rounded border border-border bg-surface/90 px-2 py-0.5 text-2xs text-fg-faint">
            Drag to pan · {IS_MAC ? "⌘" : "Ctrl"} + scroll or pinch to zoom · Esc clears the selection
          </span>
        </Panel>
      </ReactFlow>
    </div>
  );
}

export function ProvenanceCanvas(props: ProvenanceCanvasProps) {
  // Remount per scope so each new graph gets its own initial viewport.
  return (
    <ReactFlowProvider key={props.scopeKey}>
      <Canvas {...props} />
    </ReactFlowProvider>
  );
}
