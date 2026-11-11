/**
 * Full session timeline in server sequence order. ``focusInvocation`` (from ?invocation=<id>) loads
 * the page containing that tool call and highlights its request entry.
 */
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  GitBranch,
  MessageSquare,
  MessagesSquare,
  Play,
  Plug,
  Square,
  Wrench,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { Badge, DecisionBadge, EnforcementBadge, ErrorState, LoadingRows, SeverityBadge, TrustBadge } from "@/components/ui";
import { EntityLink, Pagination, Section, Timeline, provenanceHref, type TimelineItem } from "@/components/data";
import { decisionTone, severityTone, trustTone, type Tone } from "@/lib/domain";
import { formatDateTime } from "@/lib/format";
import { useSessionTimeline } from "../api";
import type { TimelineEntry } from "../types";

const PAGE = 200;
/** Trust levels that colour a timeline node (others stay neutral to keep status colour meaningful). */
const ALARMING_TRUST = new Set(["SUSPICIOUS", "BLOCKED"]);
const ICONS: Record<string, LucideIcon> = {
  "session.started": Play,
  "session.ended": Square,
  "prompt.submitted": MessageSquare,
  "context.ingested": FileText,
  "tool.requested": Wrench,
  "tool.completed": CheckCircle2,
  "tool.failed": XCircle,
  "agent.delegated": GitBranch,
  "agent.message": MessagesSquare,
  "mcp.server_connected": Plug,
};

function toneOf(e: TimelineEntry): Tone {
  if (e.processing_status === "error") return "danger";
  if (e.severity) return severityTone(e.severity);
  if (e.decision && e.decision !== "ALLOW") return decisionTone(e.decision);
  if (e.trust_level && ALARMING_TRUST.has(e.trust_level)) return trustTone(e.trust_level);
  return "neutral";
}

function EntryLinks({ e, sessionId }: { e: TimelineEntry; sessionId: string }) {
  const r = e.refs;
  const links = [
    r.context_item_id && <EntityLink key="ctx" type="context_item" id={r.context_item_id} label="Context receipt" />,
    r.context_item_id && (
      <Link key="prov" to={provenanceHref("item", r.context_item_id)} className="text-accent hover:underline">
        Provenance
      </Link>
    ),
    r.policy_decision_id && <EntityLink key="dec" type="policy_decision" id={r.policy_decision_id} label="Replay decision" sessionId={sessionId} />,
    r.approval_id && <EntityLink key="apr" type="approval" id={r.approval_id} label="Approval" />,
    r.child_session_id && <EntityLink key="child" type="session" id={r.child_session_id} label="Delegated session" />,
    ...r.finding_ids.slice(0, 3).map((id) => <EntityLink key={id} type="finding" id={id} />),
    r.finding_ids.length > 3 && (
      <span key="more" className="text-fg-faint">
        +{r.finding_ids.length - 3} findings
      </span>
    ),
  ].filter(Boolean);
  if (links.length === 0) return null;
  return <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-2xs">{links}</div>;
}

function toItem(e: TimelineEntry, sessionId: string): TimelineItem {
  const Icon = ICONS[e.event_type] ?? AlertTriangle;
  return {
    id: e.id,
    time: e.received_at,
    icon: e.processing_status === "error" ? <AlertTriangle /> : <Icon />,
    tone: toneOf(e),
    title: <span title={`${e.event_type} · #${e.sequence} · client time ${formatDateTime(e.occurred_at)}`}>{e.title}</span>,
    description: e.summary,
    badges: (
      <>
        {e.decision && <DecisionBadge decision={e.decision} />}
        {e.decision && e.enforcement && <EnforcementBadge mode={e.enforcement} />}
        {e.trust_level && <TrustBadge level={e.trust_level} />}
        {e.severity && <SeverityBadge severity={e.severity} />}
        {e.from_other_session && <Badge title="Recorded in the parent session that delegated this task">From parent session</Badge>}
        {e.processing_status === "error" && <Badge tone="danger">Processing error</Badge>}
      </>
    ),
    children: <EntryLinks e={e} sessionId={sessionId} />,
  };
}

export function SessionTimeline({ sessionId, focusInvocation }: { sessionId: string; focusInvocation: string | null }) {
  const [manualOffset, setManualOffset] = useState<number | null>(null);
  useEffect(() => setManualOffset(null), [focusInvocation]);
  const params = manualOffset === null && focusInvocation ? { limit: PAGE, offset: 0, invocation_id: focusInvocation } : { limit: PAGE, offset: manualOffset ?? 0 };
  const timeline = useSessionTimeline(sessionId, params);
  const listRef = useRef<HTMLDivElement>(null);
  const data = timeline.data;
  const focusId = manualOffset === null ? (data?.focus_event_ids[0] ?? null) : null;

  useEffect(() => {
    if (!focusId) return;
    listRef.current?.querySelector('[aria-current="true"]')?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [focusId, data]);

  const missingFocus = !!focusInvocation && manualOffset === null && data && data.focus_event_ids.length === 0;
  return (
    <Section
      title="Timeline"
      description="Every event in server order, with what ContextOS decided and the records it produced. Times are server receipt times."
      actions={data && <span className="num text-2xs text-fg-faint">{data.total} events</span>}
    >
      {missingFocus && (
        <p role="status" className="mb-3 rounded border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-fg">
          The requested tool call is not part of this session, so nothing is highlighted.
        </p>
      )}
      {timeline.isLoading ? (
        <LoadingRows rows={6} />
      ) : timeline.error || !data ? (
        <ErrorState error={timeline.error} onRetry={() => timeline.refetch()} />
      ) : (
        <div ref={listRef}>
          <Timeline items={data.items.map((e) => toItem(e, sessionId))} selectedId={focusId} emptyLabel="No events recorded for this session yet." aria-label="Session timeline" />
          <Pagination total={data.total} limit={PAGE} offset={data.offset} onChange={setManualOffset} itemLabel="events" className="mt-3" />
        </div>
      )}
    </Section>
  );
}
