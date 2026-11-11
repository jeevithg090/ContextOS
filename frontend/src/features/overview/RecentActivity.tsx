/** The latest entries of the organisation's tamper-evident audit log (details redacted server-side). */
import { Link } from "react-router-dom";
import { Bot, KeyRound, ScrollText, User } from "lucide-react";
import { EntityLink, Section, isEntityType } from "@/components/data";
import { EmptyState, LoadingRows } from "@/components/ui";
import { humanize } from "@/lib/domain";
import { formatDateTime, timeAgo } from "@/lib/format";
import type { ActivityEntry, Overview } from "./types";

const ACTOR_ICONS = { user: User, api_key: KeyRound, system: Bot } as const;

function Target({ entry }: { entry: ActivityEntry }) {
  if (!entry.target_type || !entry.target_id) return null;
  if (isEntityType(entry.target_type) && entry.target_type !== "tool_invocation" && entry.target_type !== "policy_decision") {
    return <EntityLink type={entry.target_type} id={entry.target_id} showIcon={false} className="text-2xs" />;
  }
  const session = typeof entry.details.session_id === "string" ? entry.details.session_id : null;
  if (entry.target_type === "tool_invocation" && session) {
    return <EntityLink type="tool_invocation" id={entry.target_id} sessionId={session} showIcon={false} className="text-2xs" />;
  }
  return <span className="font-mono text-2xs text-fg-faint">{humanize(entry.target_type)}</span>;
}

export function RecentActivity({ data, loading }: { data: Overview | undefined; loading: boolean }) {
  const rows = data?.recent_activity ?? [];
  return (
    <Section
      title="Recent activity"
      description="Latest audit log entries: decisions, triage and configuration changes."
      flush
      actions={
        <Link to="/audit" className="text-xs text-accent hover:underline">
          Audit log
        </Link>
      }
    >
      {!data ? (
        loading ? <LoadingRows rows={5} /> : null
      ) : rows.length === 0 ? (
        <EmptyState icon={<ScrollText className="h-4 w-4" />} title="No audit entries yet" description="Every decision, triage step and configuration change is recorded here." />
      ) : (
        <ol className="divide-y divide-border/70">
          {rows.map((entry) => {
            const Icon = ACTOR_ICONS[entry.actor_type as keyof typeof ACTOR_ICONS] ?? Bot;
            return (
              <li key={entry.id} className="flex min-w-0 items-start gap-2.5 px-4 py-2">
                <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] text-fg">{humanize(entry.action)}</div>
                  <div className="flex min-w-0 items-center gap-1.5 text-2xs text-fg-muted">
                    <span className="truncate">{entry.actor_label}</span>
                    {entry.target_id && <span aria-hidden>·</span>}
                    <Target entry={entry} />
                  </div>
                </div>
                <time dateTime={entry.occurred_at} title={formatDateTime(entry.occurred_at)} className="shrink-0 text-xs text-fg-faint">
                  {timeAgo(entry.occurred_at)}
                </time>
              </li>
            );
          })}
        </ol>
      )}
    </Section>
  );
}
