/**
 * Mini provenance view for one context item, drawn only from persisted edges that touch the item:
 * source → item → session, plus the tool call that returned it, the agent that sent it and the
 * findings it triggered. Edges are observed relationships — the note under the chain says so.
 */
import { ArrowRight, FileText } from "lucide-react";
import type { ReactNode } from "react";
import { Badge, TrustBadge } from "@/components/ui";
import { EntityLink } from "@/components/data";
import { cn } from "@/lib/format";
import { relationGroupLabel, relationLabel, sourceTypeMeta } from "./meta";
import type { ContextItemDetail, ProvenanceEdge } from "./types";

export function ProvenanceChain({ item }: { item: ContextItemDetail }) {
  const findings = new Map(item.findings.map((f) => [f.id, f]));
  const SourceIcon = sourceTypeMeta(item.source.source_type).icon;

  const node = (type: string, id: string): ReactNode => {
    if (type === "context_item" && id === item.id) {
      return (
        <Node icon={<FileText className="h-3.5 w-3.5" aria-hidden />} highlight>
          <span className="font-medium text-fg">This item</span>
          <TrustBadge level={item.trust_level} />
        </Node>
      );
    }
    if (type === "source" && id === item.source.id) {
      return (
        <Node icon={<SourceIcon className="h-3.5 w-3.5" aria-hidden />}>
          <EntityLink type="source" id={id} label={item.source.display_name || item.source.identifier} showIcon={false} className="max-w-[220px]" />
        </Node>
      );
    }
    if (type === "session") {
      const label = id === item.session.id ? `${item.session.external_session_id ?? "session"} · ${item.agent.name ?? "agent"}` : null;
      return (
        <Node>
          <EntityLink type="session" id={id} label={label} />
        </Node>
      );
    }
    if (type === "tool_invocation") {
      const inv = item.tool_invocation?.id === id ? item.tool_invocation : null;
      return (
        <Node>
          <EntityLink type="tool_invocation" id={id} label={inv?.tool_name ? `${inv.tool_name} call` : null} sessionId={item.session.id} />
        </Node>
      );
    }
    if (type === "finding") {
      return (
        <Node>
          <EntityLink type="finding" id={id} label={findings.get(id)?.title ?? null} className="max-w-[260px]" />
        </Node>
      );
    }
    return (
      <Node>
        <EntityLink type={type} id={id} />
      </Node>
    );
  };

  const edges = item.provenance;
  if (edges.length === 0) return <p className="text-xs text-fg-muted">No provenance edges were recorded for this item.</p>;
  const main = ["source_produced_item", "item_entered_session"];
  const chain = main.map((r) => edges.find((e) => e.relation === r)).filter((e): e is ProvenanceEdge => !!e);
  const groups = groupOthers(edges.filter((e) => !chain.includes(e)), item.id);

  return (
    <div className="space-y-3">
      {chain.length > 0 && (
        <ol className="flex flex-wrap items-center gap-1.5" aria-label="Source to session">
          {chain.map((edge, i) => (
            <li key={edge.id} className="contents">
              {i === 0 && node(edge.src.type, edge.src.id)}
              <Arrow edge={edge} />
              {node(edge.dst.type, edge.dst.id)}
            </li>
          ))}
        </ol>
      )}
      {groups.length > 0 && (
        <dl className="grid grid-cols-[max-content_1fr] items-start gap-x-3 gap-y-2" aria-label="Other observed relationships">
          {groups.map((g) => (
            <div key={g.key} className="contents">
              <dt className="pt-1.5 text-2xs text-fg-faint">{g.label}</dt>
              <dd className="flex min-w-0 flex-wrap gap-1.5">
                {g.edges.map((edge) => {
                  const far = edge.src.type === "context_item" && edge.src.id === item.id ? edge.dst : edge.src;
                  return (
                    <span key={edge.id} className="inline-flex items-center gap-1" title={`${edge.relation} (${edge.confidence})`}>
                      {node(far.type, far.id)}
                      {edge.confidence !== "observed" && <Badge tone="warn">{edge.confidence}</Badge>}
                    </span>
                  );
                })}
              </dd>
            </div>
          ))}
        </dl>
      )}
      <p className="text-2xs text-fg-faint">{item.provenance_note}</p>
    </div>
  );
}

function Node({ children, icon, highlight }: { children: ReactNode; icon?: ReactNode; highlight?: boolean }) {
  return (
    <span className={cn("inline-flex min-w-0 max-w-full items-center gap-1.5 rounded-md border px-2 py-1 text-xs", highlight ? "border-accent/40 bg-accent/[0.06]" : "border-border bg-surface-2/60")}>
      {icon && <span className="text-fg-muted">{icon}</span>}
      {children}
    </span>
  );
}

function Arrow({ edge }: { edge: ProvenanceEdge }) {
  return (
    <span className="inline-flex items-center gap-1 px-0.5 text-2xs text-fg-faint" title={`${edge.relation} (${edge.confidence})`}>
      {relationLabel(edge.relation)}
      {edge.confidence !== "observed" && <Badge tone="warn">{edge.confidence}</Badge>}
      <ArrowRight className="h-3 w-3" aria-hidden />
    </span>
  );
}

/** Secondary edges grouped by relation and direction, e.g. "Returned by" (tool call → item) or "Triggered" (item → findings). */
function groupOthers(edges: ProvenanceEdge[], itemId: string) {
  const groups = new Map<string, { key: string; label: string; edges: ProvenanceEdge[] }>();
  for (const edge of edges) {
    const outgoing = edge.src.type === "context_item" && edge.src.id === itemId;
    const key = `${edge.relation}:${outgoing ? "out" : "in"}`;
    const group = groups.get(key) ?? { key, label: relationGroupLabel(edge.relation, outgoing), edges: [] };
    group.edges.push(edge);
    groups.set(key, group);
  }
  // Upstream relationships (what produced or returned the item) before downstream ones.
  return Array.from(groups.values()).sort((a, b) => Number(a.key.endsWith(":out")) - Number(b.key.endsWith(":out")));
}
