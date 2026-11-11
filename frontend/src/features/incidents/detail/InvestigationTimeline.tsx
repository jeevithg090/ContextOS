/**
 * The investigation timeline: involved sessions' recorded events, findings, policy decisions,
 * approvals and incident activity in server-time order. Each entry links to the record behind it
 * (context receipt, session, tool call, decision replay, finding, approval).
 */
import { useState, type ReactNode } from "react";
import { format } from "date-fns";
import { EntityLink, Timeline, type TimelineItem } from "@/components/data";
import { Badge, DecisionBadge, EnforcementBadge, ErrorState, LoadingRows, SeverityBadge, StatusBadge, TrustBadge } from "@/components/ui";
import { formatTime } from "@/lib/format";
import { useIncidentTimeline } from "../api";
import { ENTRY_META, entryIcon, entryTone } from "../meta";
import { TIMELINE_ENTRY_TYPES, type IncidentTimeline, type TimelineEntry, type TimelineEntryType } from "../types";

function Stamp({ iso, showDate }: { iso: string; showDate: boolean }) {
  const d = new Date(iso);
  return (
    <time dateTime={iso} title={format(d, "d MMM yyyy, HH:mm:ss.SSS")} className="block leading-tight">
      {showDate && <span className="block text-fg-muted">{format(d, "d MMM")}</span>}
      {formatTime(iso)}
    </time>
  );
}

function Links({ entry }: { entry: TimelineEntry }) {
  const r = entry.refs;
  const session = r.session_id ?? entry.session_id;
  const links: ReactNode[] = [];
  if (r.context_item_id) links.push(<EntityLink key="ci" type="context_item" id={r.context_item_id} label="Context receipt" />);
  if (r.tool_invocation_id && session) links.push(<EntityLink key="inv" type="tool_invocation" id={r.tool_invocation_id} sessionId={session} label={entry.tool_name ? `${entry.tool_name} call` : "Tool call"} />);
  if (r.policy_decision_id && session) links.push(<EntityLink key="dec" type="policy_decision" id={r.policy_decision_id} sessionId={session} label="Decision in replay" />);
  if (r.approval_id) links.push(<EntityLink key="apr" type="approval" id={r.approval_id} label="Approval" />);
  const findings = r.finding_id ? [r.finding_id] : r.finding_ids;
  findings.slice(0, 3).forEach((id, i) => links.push(<EntityLink key={`f${id}`} type="finding" id={id} label={findings.length > 1 ? `Finding ${i + 1}` : "Finding"} />));
  if (findings.length > 3) links.push(<span key="more" className="text-fg-faint">+{findings.length - 3} findings</span>);
  if (session && entry.type !== "activity") links.push(<EntityLink key="ses" type="session" id={session} label="Session" />);
  if (links.length === 0) return null;
  return <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">{links}</div>;
}

function badges(entry: TimelineEntry): ReactNode {
  return (
    <>
      {entry.severity && <SeverityBadge severity={entry.severity} />}
      {entry.decision && <DecisionBadge decision={entry.decision} />}
      {entry.enforcement && entry.decision && <EnforcementBadge mode={entry.enforcement} />}
      {entry.trust_level && entry.type === "event" && <TrustBadge level={entry.trust_level} />}
      {entry.type === "approval" && entry.status && <StatusBadge status={entry.status} />}
      {entry.type === "finding" && entry.status && entry.status !== "open" && <StatusBadge status={entry.status} />}
      {entry.type === "activity" && entry.status && <StatusBadge status={entry.status} />}
      {entry.status === "error" && <Badge tone="danger">Processing error</Badge>}
      {entry.from_other_session && (
        <Badge tone="neutral" title="Recorded in another session (for example the parent that delegated this work)">
          Other session
        </Badge>
      )}
    </>
  );
}

function toItems(entries: TimelineEntry[]): TimelineItem[] {
  let lastDay = "";
  return entries.map((e) => {
    const day = format(new Date(e.occurred_at), "yyyy-MM-dd"); // local day, matching the displayed date
    const showDate = day !== lastDay;
    lastDay = day;
    const Icon = entryIcon(e);
    const who = e.type === "activity" && e.actor ? `${e.actor.name}: ` : "";
    return {
      id: e.id,
      time: e.occurred_at,
      timeLabel: <Stamp iso={e.occurred_at} showDate={showDate} />,
      icon: <Icon aria-hidden />,
      tone: entryTone(e),
      title: e.title,
      badges: badges(e),
      description: e.summary ? <span className="whitespace-pre-wrap break-words">{who}{e.summary}</span> : who ? who.slice(0, -2) : undefined,
      children: <Links entry={e} />,
    };
  });
}

function TypeFilter({ counts, selected, onToggle }: { counts: IncidentTimeline["counts"]; selected: TimelineEntryType[]; onToggle: (t: TimelineEntryType) => void }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Show entry types">
      {TIMELINE_ENTRY_TYPES.map((t) => {
        const on = selected.includes(t);
        const Icon = ENTRY_META[t].icon;
        return (
          <button
            key={t}
            type="button"
            aria-pressed={on}
            onClick={() => onToggle(t)}
            disabled={counts[t] === 0}
            className={
              "inline-flex h-7 items-center gap-1.5 rounded border px-2 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-40 " +
              (on ? "border-accent/40 bg-accent/10 text-fg" : "border-border text-fg-muted hover:bg-surface-2 hover:text-fg")
            }
          >
            <Icon className="h-3.5 w-3.5" aria-hidden />
            {ENTRY_META[t].plural}
            <span className="num rounded bg-surface-3 px-1 text-2xs text-fg-muted">{counts[t]}</span>
          </button>
        );
      })}
    </div>
  );
}

export function InvestigationTimeline({ incidentId }: { incidentId: string }) {
  const [selected, setSelected] = useState<TimelineEntryType[]>([...TIMELINE_ENTRY_TYPES]);
  const query = useIncidentTimeline(incidentId, selected.length === TIMELINE_ENTRY_TYPES.length ? [] : selected);

  const toggle = (t: TimelineEntryType) =>
    setSelected((current) => {
      const next = current.includes(t) ? current.filter((x) => x !== t) : [...current, t];
      return next.length === 0 ? [...TIMELINE_ENTRY_TYPES] : TIMELINE_ENTRY_TYPES.filter((x) => next.includes(x));
    });

  if (query.isLoading) return <LoadingRows rows={6} />;
  if (query.error || !query.data) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const data = query.data;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <TypeFilter counts={data.counts} selected={selected} onToggle={toggle} />
        <span className="text-2xs text-fg-faint">
          {data.session_ids.length === 0 ? "No session is linked yet" : `Events from ${data.session_ids.length} session${data.session_ids.length === 1 ? "" : "s"}`}
        </span>
      </div>
      {data.truncated && (
        <p className="rounded border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn" role="status">
          Showing the first {data.items.length} of {data.total} entries{data.recorded_event_count > data.counts.event ? ` (sessions recorded ${data.recorded_event_count} events)` : ""}. Narrow the entry types or open a session for its complete timeline.
        </p>
      )}
      <Timeline
        aria-label="Investigation timeline"
        items={toItems(data.items)}
        emptyLabel={data.session_ids.length === 0 ? "Link findings to bring their sessions' events into the timeline." : "No entries of the selected types."}
      />
      <p className="border-t border-border pt-2 text-2xs text-fg-faint">{data.note}</p>
    </div>
  );
}
