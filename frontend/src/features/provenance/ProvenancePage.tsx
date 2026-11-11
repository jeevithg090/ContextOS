/**
 * Provenance / Context Trust Graph — how information flowed from sources, through sessions, to tool
 * calls, resources and destinations, as observed by ContextOS.
 *
 * URL parameters drive the scope so other pages can link here (see scopeParams.ts): ?session=,
 * ?agent=, ?item=, ?finding= (plus ?depth= and ?limit=). No parameter shows the most recent high-risk
 * session.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { FlaskConical, GitBranch, Info, Plug } from "lucide-react";
import { InlineStat } from "@/components/data";
import { Button, EmptyState, ErrorState, PageHeader, Select, SimulationBadge, Skeleton, Tabs, TabPanel } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { formatNumber } from "@/lib/format";
import { useProvenanceGraph } from "./api";
import { EdgeInspector, NodeInspector } from "./Inspector";
import { DEFAULT_HIDDEN } from "./nodeMeta";
import { ProvenanceCanvas, type CanvasSelection } from "./ProvenanceCanvas";
import { RiskyPathList } from "./RiskyPathList";
import { ScopeBar, type PickerMode } from "./ScopeBar";
import { DEFAULT_DEPTH, NODE_LIMITS, queryFromParams, withScope, type ScopeParam } from "./scopeParams";
import type { ProvenanceGraph } from "./types";

const DISCLAIMER = "Edges are relationships observed by ContextOS — they do not prove the content caused an action.";

function CanvasSkeleton() {
  return (
    <div className="flex h-full gap-10 p-8" aria-busy="true" aria-label="Loading graph">
      {[4, 6, 2, 5, 3].map((rows, col) => (
        <div key={col} className="flex w-[200px] flex-col justify-center gap-3">
          {Array.from({ length: rows }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ))}
    </div>
  );
}

function ScopeSummary({ graph, onLimit }: { graph: ProvenanceGraph; onLimit: (limit: number) => void }) {
  const { scope, stats } = graph;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-[13px] font-medium text-fg" title={scope.label}>
            {scope.label}
          </span>
          {scope.is_simulation && <SimulationBadge />}
        </div>
        <InlineStat label="Nodes" value={formatNumber(stats.node_count)} hint="Nodes in this graph" />
        <InlineStat label="Edges" value={formatNumber(stats.edge_count)} hint="Observed or inferred relationships" />
        <InlineStat label="Sessions" value={formatNumber(stats.session_count)} />
        <InlineStat label="Untrusted" value={formatNumber(stats.untrusted_node_count)} tone={stats.untrusted_node_count ? "suspicious" : undefined} hint="Sources, content and destinations that are not trusted or approved" />
        <InlineStat label="Risky paths" value={formatNumber(stats.risky_path_count)} tone={stats.risky_path_count ? "high" : undefined} />
        {stats.inferred_edge_count > 0 && <InlineStat label="Inferred" value={formatNumber(stats.inferred_edge_count)} hint="Relationships derived by ContextOS, drawn dashed" />}
      </div>
      {scope.reason && <p className="text-xs text-fg-muted">{scope.reason}</p>}
      {(graph.truncated || stats.dropped_edge_count > 0) && (
        <div role="status" className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-fg">
          <Info className="h-3.5 w-3.5 shrink-0 text-warn" aria-hidden />
          <span className="min-w-0 flex-1">
            {graph.truncation_reason}
            {stats.dropped_edge_count > 0 && ` ${stats.dropped_edge_count} relationship(s) point at records that no longer exist and are not drawn.`}
          </span>
          {graph.truncated && (
            <label className="inline-flex items-center gap-1.5 text-fg-muted">
              Show up to
              <Select aria-label="Maximum nodes" value={graph.limit} onChange={(e) => onLimit(Number(e.target.value))} className="h-7 w-24 text-xs">
                {NODE_LIMITS.map((l) => (
                  <option key={l} value={l}>
                    {l} nodes
                  </option>
                ))}
              </Select>
            </label>
          )}
        </div>
      )}
    </div>
  );
}

export function ProvenancePage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const query = useMemo(() => queryFromParams(params), [params]);
  const graphQuery = useProvenanceGraph(query);
  const graph = graphQuery.data;

  const [pickerMode, setPickerMode] = useState<PickerMode>(query.agent_id ? "agent" : query.finding_id ? "finding" : "session");
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(() => new Set(DEFAULT_HIDDEN));
  const [selection, setSelection] = useState<CanvasSelection>({ nodeId: null, edgeId: null });
  const [pathId, setPathId] = useState<string | null>(null);
  const [tab, setTab] = useState<"paths" | "inspector">("paths");

  const scopeKey = graph ? `${graph.scope.kind}:${graph.scope.id ?? ""}:${graph.scope.depth ?? ""}` : "";
  useEffect(() => {
    setSelection({ nodeId: null, edgeId: null });
    setPathId(null);
    setTab("paths");
  }, [scopeKey]);
  useEffect(() => {
    if (query.agent_id) setPickerMode("agent");
    else if (query.finding_id) setPickerMode("finding");
    else if (query.session_id) setPickerMode("session");
  }, [query.agent_id, query.finding_id, query.session_id]);

  const nodesById = useMemo(() => new Map((graph?.nodes ?? []).map((n) => [n.id, n])), [graph]);
  const edgesById = useMemo(() => new Map((graph?.edges ?? []).map((e) => [e.id, e])), [graph]);
  const path = graph?.risky_paths.find((p) => p.id === pathId) ?? null;
  const selectedNode = selection.nodeId ? nodesById.get(selection.nodeId) ?? null : null;
  const selectedEdge = selection.edgeId ? edgesById.get(selection.edgeId) ?? null : null;

  const setScope = useCallback((param: ScopeParam | null, id: string | null) => setParams(withScope(params, param, id)), [params, setParams]);
  const setParam = (key: string, value: number) => {
    const next = new URLSearchParams(params);
    next.set(key, String(value));
    setParams(next, { replace: true });
  };
  const selectNode = useCallback((id: string) => {
    setSelection({ nodeId: id, edgeId: null });
    setTab("inspector");
  }, []);
  const selectEdge = useCallback((id: string) => {
    setSelection({ nodeId: null, edgeId: id });
    setTab("inspector");
  }, []);
  const clearSelection = useCallback(() => setSelection({ nodeId: null, edgeId: null }), []);
  const toggleType = (type: string) =>
    setHiddenTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });

  const notFound = graphQuery.error instanceof ApiError && graphQuery.error.status === 404;
  const empty = graph && graph.scope.kind === "none";

  return (
    <>
      <PageHeader
        eyebrow="Context Trust Graph"
        title="Provenance graph"
        description="How information flowed from sources into agent sessions and on to tool calls, resources and destinations — with the paths ContextOS considers risky."
      />
      <div className="space-y-3">
        <ScopeBar
          scope={graph?.scope ?? null}
          pickerMode={pickerMode}
          onPickerModeChange={setPickerMode}
          onPick={(mode, id) => setScope(mode, id)}
          onClearScope={() => setScope(null, null)}
          depth={query.depth ?? graph?.scope.depth ?? DEFAULT_DEPTH}
          onDepthChange={(d) => setParam("depth", d)}
          hiddenTypes={hiddenTypes}
          onToggleType={toggleType}
          typeCounts={graph && !graphQuery.isError ? graph.stats.node_counts : null}
        />
        {graph && !empty && <ScopeSummary graph={graph} onLimit={(l) => setParam("limit", l)} />}

        {graphQuery.isError ? (
          <div className="panel">
            {notFound ? (
              <EmptyState
                icon={<GitBranch className="h-4 w-4" />}
                title="That record isn’t available"
                description="It does not exist, or it belongs to another organisation."
                action={<Button size="sm" variant="outline" onClick={() => setScope(null, null)}>Show the most recent high-risk session</Button>}
              />
            ) : (
              <ErrorState error={graphQuery.error} onRetry={() => void graphQuery.refetch()} />
            )}
          </div>
        ) : empty ? (
          <div className="panel">
            <EmptyState
              icon={<GitBranch className="h-4 w-4" />}
              title="No provenance recorded yet"
              description="The graph fills in as connected agents report context and tool calls. To see it now, run a Simulation Lab scenario through the real pipeline (results are labelled as simulations)."
              action={
                <div className="flex flex-wrap justify-center gap-2">
                  <Button size="sm" variant="primary" icon={<FlaskConical className="h-3.5 w-3.5" />} onClick={() => navigate("/simulation")}>
                    Open Simulation Lab
                  </Button>
                  <Button size="sm" variant="outline" icon={<Plug className="h-3.5 w-3.5" />} onClick={() => navigate("/integrations")}>
                    Connect an integration
                  </Button>
                </div>
              }
            />
          </div>
        ) : (
          <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_360px]">
            <div className="flex min-w-0 flex-col">
              <div className="panel relative h-[calc(100vh-300px)] min-h-[520px] overflow-hidden">
                {graph ? (
                  <ProvenanceCanvas
                    graph={graph}
                    hiddenTypes={hiddenTypes}
                    selection={selection}
                    path={path}
                    onSelectNode={selectNode}
                    onSelectEdge={selectEdge}
                    onClearSelection={clearSelection}
                    scopeKey={scopeKey}
                  />
                ) : (
                  <CanvasSkeleton />
                )}
                {graphQuery.isFetching && graph && (
                  <span className="absolute right-3 top-3 rounded border border-border bg-surface-2 px-1.5 py-0.5 text-2xs text-fg-muted">Updating…</span>
                )}
              </div>
              <p className="mt-2 flex items-start gap-1.5 text-xs text-fg-muted">
                <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                {DISCLAIMER}
              </p>
            </div>
            <aside className="panel flex h-[min(640px,80vh)] flex-col overflow-hidden xl:h-[calc(100vh-300px)] xl:min-h-[520px]" aria-label="Graph details">
              <Tabs
                value={tab}
                onValueChange={(v) => setTab(v as "paths" | "inspector")}
                className="flex min-h-0 flex-1 flex-col"
                tabs={[
                  { value: "paths", label: "Risky paths", count: graph?.risky_paths.length },
                  { value: "inspector", label: "Inspector" },
                ]}
              >
                <TabPanel value="paths" className="min-h-0 flex-1 overflow-y-auto">
                  {graph ? (
                    <RiskyPathList paths={graph.risky_paths} nodesById={nodesById} selectedId={pathId} onSelect={setPathId} onInspect={selectNode} />
                  ) : (
                    <div className="space-y-2 p-4">
                      {[0, 1, 2].map((i) => (
                        <Skeleton key={i} className="h-16 w-full" />
                      ))}
                    </div>
                  )}
                </TabPanel>
                <TabPanel value="inspector" className="min-h-0 flex-1 overflow-y-auto">
                  {selectedNode ? (
                    <NodeInspector
                      key={selectedNode.id}
                      node={selectedNode}
                      isRoot={graph?.scope.root_node_ids.includes(selectedNode.id) ?? false}
                      inGraph={(id) => nodesById.has(id)}
                      onSelectNode={selectNode}
                      onRescope={(param, ref) => setScope(param, ref)}
                      onClose={clearSelection}
                    />
                  ) : selectedEdge ? (
                    <EdgeInspector edge={selectedEdge} nodesById={nodesById} onSelectNode={selectNode} onClose={clearSelection} />
                  ) : (
                    <EmptyState title="Nothing selected" description="Select a node or an edge on the canvas (or Tab to it and press Enter) to see its details and relationships. Press Esc to clear." />
                  )}
                </TabPanel>
              </Tabs>
            </aside>
          </div>
        )}
      </div>
    </>
  );
}
