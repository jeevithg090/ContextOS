/** Events recorded in the same session after the item — an observed sequence, never causation. */
import { Badge, Button, DecisionBadge, EnforcementBadge, StatusBadge } from "@/components/ui";
import { EntityLink, Timeline, type TimelineItem } from "@/components/data";
import { humanize, type Tone } from "@/lib/domain";
import type { ContextReceipt, SubsequentEvent } from "../types";

function tone(e: SubsequentEvent): Tone {
  if (e.processing_status === "error") return "danger";
  if (e.decision === "DENY") return "deny";
  if (e.decision === "REQUIRE_APPROVAL") return "approval";
  if (e.finding_ids.length) return "high";
  if (e.event_type.startsWith("tool.")) return "accent";
  return "neutral";
}

export function SubsequentEvents({ related, sessionId, onShowMore, loadingMore }: { related: ContextReceipt["related"]; sessionId: string; onShowMore?: () => void; loadingMore: boolean }) {
  const items: TimelineItem[] = related.subsequent_events.map((e) => ({
    id: e.id,
    time: e.received_at,
    tone: tone(e),
    title: e.summary,
    badges: (
      <>
        {e.decision && <DecisionBadge decision={e.decision} />}
        {e.enforcement && <EnforcementBadge mode={e.enforcement} />}
        {e.processing_status === "error" && <StatusBadge status="error" />}
        {e.finding_ids.length > 0 && <Badge tone="high">{e.finding_ids.length === 1 ? "1 finding" : `${e.finding_ids.length} findings`}</Badge>}
      </>
    ),
    description: (
      <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <span className="font-mono text-2xs text-fg-faint">#{e.sequence} · {humanize(e.event_type)}</span>
        {e.tool_invocation_id && <EntityLink type="tool_invocation" id={e.tool_invocation_id} label="tool call" sessionId={sessionId} />}
        {e.context_item_id && <EntityLink type="context_item" id={e.context_item_id} label="context item" />}
        {e.finding_ids.map((id) => (
          <EntityLink key={id} type="finding" id={id} />
        ))}
      </span>
    ),
  }));

  return (
    <div className="space-y-3">
      <p className="text-xs text-fg-muted">{related.subsequent_events_note}</p>
      <Timeline items={items} timeFormat="time" aria-label="Events after this item" emptyLabel="Nothing was recorded in this session after this item." />
      {related.more_subsequent_events && onShowMore && (
        <Button size="sm" variant="outline" onClick={onShowMore} loading={loadingMore}>
          Show more events
        </Button>
      )}
    </div>
  );
}
