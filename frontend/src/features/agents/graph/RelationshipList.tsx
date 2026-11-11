import { ArrowRight, ShieldAlert, X } from "lucide-react";
import { Badge, IconButton, KeyValue } from "@/components/ui";
import { EntityLink, Section } from "@/components/data";
import { cn, formatDateTime, timeAgo } from "@/lib/format";
import type { GraphEdge, GraphNode } from "../types";

const TYPE_LABEL: Record<string, string> = { delegates_to: "Delegation", messages: "Messages" };
const BOUNDARY_TEXT =
  "The receiving agent's session consumed less-trusted content than the sending agent's session. Anything it hands back (results, messages) can carry that content into the more trusted context. This is an observed relationship, not proof that one agent influenced the other.";

/** Keyboard- and screen-reader-accessible list of the graph's edges. */
export function RelationshipList({ edges, nodes, selectedId, onSelect }: { edges: GraphEdge[]; nodes: Map<string, GraphNode>; selectedId: string | null; onSelect: (id: string | null) => void }) {
  const sorted = [...edges].sort((a, b) => Number(b.crosses_trust_boundary) - Number(a.crosses_trust_boundary) || b.event_count - a.event_count);
  return (
    <Section title="Observed relationships" description="Select a relationship to see when it was observed and the sessions involved." flush>
      <ul className="divide-y divide-border/70">
        {sorted.map((e) => (
          <li key={e.id}>
            <button
              type="button"
              onClick={() => onSelect(selectedId === e.id ? null : e.id)}
              aria-pressed={selectedId === e.id}
              className={cn("flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-left text-[13px] hover:bg-surface-2/70", selectedId === e.id && "bg-accent/[0.06]")}
            >
              <span className="font-medium text-fg">{nodes.get(e.source)?.name ?? "Unknown agent"}</span>
              <ArrowRight className="h-3.5 w-3.5 text-fg-faint" aria-label="to" />
              <span className="font-medium text-fg">{nodes.get(e.target)?.name ?? "Unknown agent"}</span>
              <Badge>{TYPE_LABEL[e.relationship_type] ?? e.relationship_type}</Badge>
              {e.crosses_trust_boundary && (
                <Badge tone="danger">
                  <ShieldAlert className="h-3 w-3" aria-hidden />
                  Trust boundary
                </Badge>
              )}
              <span className="num ml-auto text-xs text-fg-muted">
                {e.event_count}× · last {timeAgo(e.last_seen_at)}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </Section>
  );
}

export function EdgeDetails({ edge, source, target, onClose }: { edge: GraphEdge; source?: GraphNode; target?: GraphNode; onClose: () => void }) {
  return (
    <Section
      title={
        <span className="inline-flex flex-wrap items-center gap-2">
          {source?.name ?? "Unknown"} <ArrowRight className="h-3.5 w-3.5 text-fg-faint" aria-label="to" /> {target?.name ?? "Unknown"}
          <Badge>{TYPE_LABEL[edge.relationship_type] ?? edge.relationship_type}</Badge>
        </span>
      }
      actions={
        <IconButton label="Close relationship details" onClick={onClose}>
          <X className="h-4 w-4" aria-hidden />
        </IconButton>
      }
    >
      {edge.crosses_trust_boundary && (
        <p className="mb-3 flex gap-2 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-fg">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-danger" aria-hidden />
          {BOUNDARY_TEXT}
        </p>
      )}
      <KeyValue
        items={[
          { label: "From", value: <EntityLink type="agent" id={edge.source} label={source?.name} /> },
          { label: "To", value: <EntityLink type="agent" id={edge.target} label={target?.name} /> },
          { label: "Observed", value: `${edge.event_count} time${edge.event_count === 1 ? "" : "s"}` },
          { label: "First seen", value: formatDateTime(edge.first_seen_at) },
          { label: "Last seen", value: formatDateTime(edge.last_seen_at) },
          { label: "Latest sending session", value: <EntityLink type="session" id={edge.last_parent_session_id} /> },
          { label: "Latest receiving session", value: <EntityLink type="session" id={edge.last_child_session_id} /> },
        ]}
      />
    </Section>
  );
}
