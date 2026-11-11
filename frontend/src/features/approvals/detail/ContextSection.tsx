/** "Recent context in this session" (what the agent had read when it asked), related findings and
 * the approval's audit trail. */
import { Link } from "react-router-dom";
import { KeyRound } from "lucide-react";
import { EntityLink, RedactedText, Section, Timeline } from "@/components/data";
import { Badge, SeverityBadge, StatusBadge, TrustBadge } from "@/components/ui";
import { FINDING_CATEGORY_LABELS, humanize } from "@/lib/domain";
import { formatDateTime, timeAgo } from "@/lib/format";
import { activityTitle, sourceLabel } from "../meta";
import type { ApprovalDetail, ContextItemRef } from "../types";

export function ContextSection({ approval }: { approval: ApprovalDetail }) {
  const items = approval.recent_context;
  return (
    <Section
      title="Recent context in this session"
      description={
        items.length < approval.context_total
          ? `The ${items.length} most recent of ${approval.context_total} items the agent had received before it asked. Trust is as classified when each item arrived.`
          : "What the agent had received before it asked, newest first. Trust is as classified when each item arrived."
      }
      flush
      actions={
        items.length > 0 ? (
          <Link
            to={`/context?session=${encodeURIComponent(approval.session.id)}${approval.is_simulation ? "&sim=1" : ""}`}
            className="text-xs text-accent hover:underline"
          >
            Open in Context Explorer
          </Link>
        ) : undefined
      }
    >
      {items.length === 0 ? (
        <p className="px-4 py-4 text-xs text-fg-muted">No context had been recorded in this session before the request.</p>
      ) : (
        <ul className="divide-y divide-border/70">
          {items.map((item) => (
            <ContextRow key={item.id} item={item} />
          ))}
        </ul>
      )}
    </Section>
  );
}

function ContextRow({ item }: { item: ContextItemRef }) {
  const trustChanged = item.source_trust_level && item.source_trust_level !== item.trust_level;
  return (
    <li className="px-4 py-2.5">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
        <TrustBadge level={item.trust_level} />
        <EntityLink type="source" id={item.source_id} label={sourceLabel(item)} showIcon={false} className="min-w-0 max-w-[22rem]" />
        {item.source_type && <span className="text-fg-faint">{humanize(item.source_type)}</span>}
        {trustChanged && (
          <span className="inline-flex items-center gap-1 text-2xs text-fg-faint">
            source now <TrustBadge level={item.source_trust_level} />
          </span>
        )}
        {item.contains_secrets && (
          <Badge tone="danger" title="Contained a secret (stored only in redacted form)">
            <KeyRound className="h-3 w-3" aria-hidden /> Secret
          </Badge>
        )}
        {item.detection_max_severity && (
          <span className="inline-flex items-center gap-1">
            <SeverityBadge severity={item.detection_max_severity} />
            <span className="text-2xs text-fg-faint">{item.detection_hit_count} detections</span>
          </span>
        )}
        <span className="ml-auto text-2xs text-fg-faint" title={formatDateTime(item.received_at)}>
          {timeAgo(item.received_at)}
        </span>
      </div>
      {item.preview && (
        <p className="mt-1.5 line-clamp-2 break-words font-mono text-2xs leading-4 text-fg-muted">
          <RedactedText text={item.preview} />
        </p>
      )}
      <div className="mt-1 flex items-center gap-2 text-2xs text-fg-faint">
        <span className="truncate">via {item.collected_via}</span>
        <EntityLink type="context_item" id={item.id} label="Receipt" showIcon={false} />
      </div>
    </li>
  );
}

export function FindingsSection({ approval }: { approval: ApprovalDetail }) {
  const findings = approval.related_findings;
  return (
    <Section title="Related findings" description="Detections in this session; those raised on this call are listed first." flush>
      {findings.length === 0 ? (
        <p className="px-4 py-4 text-xs text-fg-muted">No findings were raised in this session.</p>
      ) : (
        <ul className="divide-y divide-border/70">
          {findings.map((f) => (
            <li key={f.id} className="flex flex-wrap items-center gap-2 px-4 py-2 text-xs">
              <SeverityBadge severity={f.severity} />
              <EntityLink type="finding" id={f.id} label={f.title} showIcon={false} className="min-w-0 flex-1" />
              <span className="text-2xs text-fg-faint">{FINDING_CATEGORY_LABELS[f.category] ?? humanize(f.category)}</span>
              {f.linked_to_this_call && <Badge tone="accent">This call</Badge>}
              <StatusBadge status={f.status} />
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

export function ActivitySection({ approval }: { approval: ApprovalDetail }) {
  const items = approval.activity.map((entry) => {
    const { title, tone } = activityTitle(entry);
    const note = typeof entry.details.note === "string" ? entry.details.note : null;
    return {
      id: entry.id,
      time: entry.occurred_at,
      tone,
      title,
      description: note ? `“${note}”` : undefined,
      badges: <span className="num text-2xs text-fg-faint">audit #{entry.seq}</span>,
    };
  });
  return (
    <Section title="Activity" description="From the tamper-evident audit log.">
      <Timeline items={items} timeFormat="datetime" dense emptyLabel="No audit entries recorded for this request yet." aria-label="Approval activity" />
    </Section>
  );
}
