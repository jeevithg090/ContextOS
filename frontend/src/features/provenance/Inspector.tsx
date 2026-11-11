/** Inspector for the selected node (fetched detail, fields, links) or edge (relationship + confidence). */
import type { ReactNode } from "react";
import { Crosshair, X } from "lucide-react";
import { CodeBlock, EntityLink, entityHref, isEntityType } from "@/components/data";
import {
  Badge,
  Button,
  DecisionBadge,
  EnforcementBadge,
  ErrorState,
  IconButton,
  KeyValue,
  LoadingRows,
  SeverityBadge,
  SimulationBadge,
  TrustBadge,
} from "@/components/ui";
import { cn, formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { useProvenanceNode } from "./api";
import { confidenceText, nodeTypeMeta, riskTone } from "./nodeMeta";
import type { ScopeParam } from "./scopeParams";
import type { GraphEdge, GraphNode, NodeField, NodeLink } from "./types";

/** Scopes the graph can be re-centred on, keyed by node type → URL parameter. */
const RESCOPE_PARAM: Partial<Record<string, ScopeParam>> = { session: "session", agent: "agent", context_item: "item", finding: "finding" };

function FieldValue({ field }: { field: NodeField }) {
  const v = field.value;
  switch (field.kind) {
    case "datetime":
      return <span title={timeAgo(String(v))}>{formatDateTime(String(v))}</span>;
    case "bool":
      return <span className={v ? "text-fg" : "text-fg-muted"}>{v ? "Yes" : "No"}</span>;
    case "number":
      return <span className="num">{typeof v === "number" ? formatNumber(v) : String(v)}</span>;
    case "list":
      return (
        <span className="flex flex-wrap gap-1">
          {(Array.isArray(v) ? v : [String(v)]).slice(0, 16).map((item) => (
            <span key={item} className="max-w-full break-all rounded border border-border bg-surface-2 px-1 font-mono text-2xs text-fg-muted">
              {item}
            </span>
          ))}
        </span>
      );
    case "trust":
      return <TrustBadge level={String(v)} />;
    case "severity":
      return <SeverityBadge severity={String(v)} />;
    case "decision":
      return <DecisionBadge decision={String(v)} />;
    case "enforcement":
      return <EnforcementBadge mode={String(v)} />;
    case "risk":
      return <Badge tone={riskTone(String(v))}>{String(v)}</Badge>;
    case "mono":
      return <span className="break-all font-mono text-xs text-fg-muted">{String(v)}</span>;
    default:
      return <span className="break-words">{String(v)}</span>;
  }
}

function recordLink(node: GraphNode): ReactNode {
  if (!isEntityType(node.type) || !entityHref(node.type, node.ref_id, { sessionId: node.session_id })) return null;
  return <EntityLink type={node.type} id={node.ref_id} label="Open record" sessionId={node.session_id} showIcon={false} className="text-xs" />;
}

function NodeChip({ node, inGraph, onSelect }: { node: GraphNode; inGraph: boolean; onSelect: (id: string) => void }) {
  const meta = nodeTypeMeta(node.type);
  const Icon = meta.icon;
  const content = (
    <>
      <Icon className="h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden />
      <span className="truncate">{node.label}</span>
    </>
  );
  if (inGraph) {
    return (
      <button type="button" onClick={() => onSelect(node.id)} className="inline-flex min-w-0 max-w-full items-center gap-1.5 rounded-sm text-left text-accent hover:text-accent-strong hover:underline" title={`Select ${meta.label.toLowerCase()} on the canvas`}>
        {content}
      </button>
    );
  }
  return isEntityType(node.type) ? (
    <EntityLink type={node.type} id={node.ref_id} label={node.label} sessionId={node.session_id} />
  ) : (
    <span className="inline-flex min-w-0 items-center gap-1.5 text-fg-muted" title="Not shown in the current graph">
      {content}
    </span>
  );
}

function LinkGroup({ title, links, inGraph, onSelect }: { title: string; links: NodeLink[]; inGraph: (id: string) => boolean; onSelect: (id: string) => void }) {
  if (links.length === 0) return null;
  return (
    <div>
      <div className="label-caps mb-1.5">
        {title} <span className="num">({links.length})</span>
      </div>
      <ul className="space-y-1.5">
        {links.map((link) => (
          <li key={`${link.direction}:${link.relation}:${link.node.id}`} className="grid grid-cols-[minmax(0,110px)_minmax(0,1fr)] items-start gap-2 text-xs">
            <span className="truncate text-fg-faint" title={`${link.relation_label} — ${confidenceText(link)}`}>
              {link.relation_label}
              {link.confidence === "inferred" && " (inferred)"}
            </span>
            <NodeChip node={link.node} inGraph={inGraph(link.node.id)} onSelect={onSelect} />
          </li>
        ))}
      </ul>
    </div>
  );
}

function NodeBadges({ node }: { node: GraphNode }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {node.trust_level && <TrustBadge level={node.trust_level} />}
      {node.severity && <SeverityBadge severity={node.severity} />}
      {node.decision && <DecisionBadge decision={node.decision} />}
      {node.enforcement && <EnforcementBadge mode={node.enforcement} />}
      {node.risk_level && <Badge tone={riskTone(node.risk_level)}>Risk {node.risk_score ?? node.risk_level}</Badge>}
      {node.contains_secrets && <Badge tone="warn">Secrets (redacted)</Badge>}
      {node.sensitive && <Badge tone="warn">Sensitive</Badge>}
      {node.risk_origin && <Badge tone="high">Starts a risky path</Badge>}
      {node.is_simulation && <SimulationBadge />}
    </div>
  );
}

interface NodeInspectorProps {
  node: GraphNode;
  inGraph: (id: string) => boolean;
  isRoot: boolean;
  onSelectNode: (id: string) => void;
  onRescope: (param: ScopeParam, refId: string) => void;
  onClose: () => void;
}

export function NodeInspector({ node, inGraph, isRoot, onSelectNode, onRescope, onClose }: NodeInspectorProps) {
  const detail = useProvenanceNode(node.type, node.ref_id);
  const meta = nodeTypeMeta(node.type);
  const Icon = meta.icon;
  const rescope = RESCOPE_PARAM[node.type];
  const links = detail.data?.links ?? [];
  return (
    <div className="space-y-4 p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-2xs uppercase tracking-[0.06em] text-fg-faint">
            <Icon className="h-3.5 w-3.5" aria-hidden />
            {meta.label}
            {isRoot && <span className="text-accent">· scope</span>}
          </div>
          <h3 className="mt-1 break-words text-[14px] font-semibold text-fg">{node.label}</h3>
          {node.subtitle && <p className="mt-0.5 text-xs text-fg-muted">{node.subtitle}</p>}
        </div>
        <IconButton label="Close inspector" onClick={onClose}>
          <X className="h-4 w-4" />
        </IconButton>
      </div>
      <NodeBadges node={node} />
      <div className="flex flex-wrap items-center gap-3">
        {recordLink(node)}
        {rescope && !isRoot && (
          <Button size="xs" variant="outline" icon={<Crosshair className="h-3 w-3" />} onClick={() => onRescope(rescope, node.ref_id)}>
            Graph from here
          </Button>
        )}
      </div>

      {detail.isLoading && <LoadingRows rows={4} />}
      {detail.isError && <ErrorState error={detail.error} onRetry={() => void detail.refetch()} className="py-6" />}
      {detail.data && (
        <>
          {detail.data.notes.length > 0 && (
            <ul className="space-y-1.5 rounded-md border border-border bg-surface-2/60 px-3 py-2.5 text-xs leading-relaxed text-fg-muted">
              {detail.data.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          )}
          {detail.data.fields.length > 0 && (
            <KeyValue className="text-xs" items={detail.data.fields.map((f) => ({ label: f.label, value: <FieldValue field={f} /> }))} />
          )}
          {detail.data.preview && (
            <CodeBlock code={detail.data.preview} title={detail.data.preview_label ?? "Preview"} maxHeight={220} wrap />
          )}
          <LinkGroup title="Linked from" links={links.filter((l) => l.direction === "in")} inGraph={inGraph} onSelect={onSelectNode} />
          <LinkGroup title="Linked to" links={links.filter((l) => l.direction === "out")} inGraph={inGraph} onSelect={onSelectNode} />
          {detail.data.link_total > links.length && (
            <p className="text-2xs text-fg-faint">
              Showing the {links.length} most recent of {formatNumber(detail.data.link_total)} relationships.
            </p>
          )}
        </>
      )}
    </div>
  );
}

interface EdgeInspectorProps {
  edge: GraphEdge;
  nodesById: Map<string, GraphNode>;
  onSelectNode: (id: string) => void;
  onClose: () => void;
}

export function EdgeInspector({ edge, nodesById, onSelectNode, onClose }: EdgeInspectorProps) {
  const src = nodesById.get(edge.src);
  const dst = nodesById.get(edge.dst);
  return (
    <div className="space-y-4 p-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Relationship</div>
          <h3 className="mt-1 text-[14px] font-semibold text-fg">{edge.relation_label}</h3>
        </div>
        <IconButton label="Close inspector" onClick={onClose}>
          <X className="h-4 w-4" />
        </IconButton>
      </div>
      <div className="space-y-1.5 text-xs">
        {[
          { label: "From", node: src },
          { label: "To", node: dst },
        ].map(({ label, node }) => (
          <div key={label} className="grid grid-cols-[44px_minmax(0,1fr)] items-center gap-2">
            <span className="text-fg-faint">{label}</span>
            {node ? <NodeChip node={node} inGraph onSelect={onSelectNode} /> : <span className="text-fg-muted">Not shown</span>}
          </div>
        ))}
      </div>
      <div className={cn("rounded-md border px-3 py-2.5 text-xs leading-relaxed", edge.confidence === "inferred" ? "border-warn/30 bg-warn/5 text-fg" : "border-border bg-surface-2/60 text-fg-muted")}>
        {confidenceText(edge)}
      </div>
      <KeyValue
        className="text-xs"
        items={[
          { label: "Recorded", value: edge.observed_at ? <span title={timeAgo(edge.observed_at)}>{formatDateTime(edge.observed_at)}</span> : "—" },
          { label: "Relation", value: <span className="font-mono text-xs text-fg-muted">{edge.relation}</span> },
          { label: "Session", value: <EntityLink type="session" id={edge.session_id} /> },
        ]}
      />
      <p className="text-2xs text-fg-faint">This edge records that both were observed together. It does not prove the content caused the action.</p>
    </div>
  );
}
