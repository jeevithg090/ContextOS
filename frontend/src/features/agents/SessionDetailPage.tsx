/**
 * Session — answers "what did this agent session consume and do, what did ContextOS decide, and how
 * close did it come to the lethal trifecta?". Risk with evidence, related sessions, findings and the
 * full timeline (?invocation=<id> highlights one tool call).
 */
import type { ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Activity, ArrowLeft, GitBranch, History, Network } from "lucide-react";
import { Badge, DecisionBadge, EmptyState, ErrorState, LoadingRows, Mono, PageHeader, SeverityBadge, SimulationBadge, StatusBadge } from "@/components/ui";
import { EntityLink, InlineStat, RiskMeter, Section } from "@/components/data";
import { ApiError } from "@/lib/api";
import { FINDING_CATEGORY_LABELS } from "@/lib/domain";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useSession } from "./api";
import { TrifectaIndicator } from "./detail/SessionsTable";
import { DECISION_ORDER, durationLabel, sortedCounts } from "./meta";
import { RiskFactors, TrifectaPanel } from "./session/SessionRisk";
import { SessionTimeline } from "./session/SessionTimeline";
import type { SessionDetail, SessionRef } from "./types";

const linkButton =
  "inline-flex h-7 items-center gap-1.5 whitespace-nowrap rounded border border-border-strong px-2.5 text-xs text-fg transition-colors hover:bg-surface-2";

export function SessionDetailPage() {
  const { sessionId } = useParams();
  const [params] = useSearchParams();
  const session = useSession(sessionId);

  if (session.isLoading) return <LoadingRows rows={8} />;
  if (session.error instanceof ApiError && session.error.status === 404) {
    return (
      <EmptyState
        icon={<Activity className="h-5 w-5" />}
        title="Session not found"
        description="It may belong to another organisation or the link is wrong."
        action={
          <Link to="/agents" className="text-xs text-accent hover:underline">
            Back to agents
          </Link>
        }
      />
    );
  }
  if (session.error || !session.data) return <ErrorState error={session.error} onRetry={() => session.refetch()} />;
  const s = session.data;

  return (
    <>
      <Link to={`/agents/${encodeURIComponent(s.agent.id)}`} className="mb-3 inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> {s.agent.name}
      </Link>
      <PageHeader
        eyebrow="Session"
        title={
          <span className="inline-flex flex-wrap items-center gap-2">
            <span className="font-mono text-lg">{s.external_session_id}</span>
            <StatusBadge status={s.status} />
            {s.is_simulation && <SimulationBadge />}
          </span>
        }
        description={
          <span className="inline-flex flex-wrap items-center gap-x-1.5">
            Run by <EntityLink type="agent" id={s.agent.id} label={s.agent.name} /> · started{" "}
            <time dateTime={s.started_at} title={formatDateTime(s.started_at)}>
              {timeAgo(s.started_at)}
            </time>{" "}
            · {s.ended_at ? `lasted ${durationLabel(s.started_at, s.ended_at)}` : `active for ${durationLabel(s.started_at)}`}
          </span>
        }
        actions={
          <>
            <Link to={`/replay/${encodeURIComponent(s.id)}`} className={linkButton}>
              <History className="h-3.5 w-3.5" aria-hidden /> Replay
            </Link>
            <Link to={`/provenance?session_id=${encodeURIComponent(s.id)}`} className={linkButton}>
              <Network className="h-3.5 w-3.5" aria-hidden /> Provenance graph
            </Link>
          </>
        }
      />
      <SessionFacts session={s} />
      <TrifectaPanel session={s} />
      <div className="mt-5 grid gap-5 xl:grid-cols-3">
        <div className="min-w-0 xl:col-span-2">
          <SessionTimeline sessionId={s.id} focusInvocation={params.get("invocation")} />
        </div>
        <div className="space-y-5">
          <RiskFactors session={s} />
          <RelatedSessions session={s} />
          <SessionFindings session={s} />
        </div>
      </div>
    </>
  );
}

function SessionFacts({ session: s }: { session: SessionDetail }) {
  const decisions = sortedCounts(s.counts.decisions, DECISION_ORDER);
  const meta = Object.entries(s.metadata).filter(([, v]) => typeof v === "string" || typeof v === "number").slice(0, 4);
  return (
    <div className="-mt-2 mb-5 flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-border pb-4">
      <span className="inline-flex items-center gap-2">
        <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Risk</span>
        <RiskMeter score={s.risk_score} level={s.risk_level} showLevel label="Session risk" />
      </span>
      <span className="inline-flex items-center gap-2">
        <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Trifecta</span>
        <TrifectaIndicator session={s} />
      </span>
      <InlineStat label="Events" value={s.counts.timeline_entries} />
      <InlineStat label="Context items" value={`${s.counts.context_items}${s.counts.untrusted_context_items ? ` (${s.counts.untrusted_context_items} untrusted)` : ""}`} />
      <InlineStat label="Tool calls" value={s.counts.tool_invocations} />
      {decisions.length > 0 && (
        <span className="inline-flex flex-wrap items-center gap-1">
          {decisions.map(([d, n]) => (
            <span key={d} className="inline-flex items-center gap-1">
              <DecisionBadge decision={d} />
              <span className="num text-xs text-fg">{n}</span>
            </span>
          ))}
        </span>
      )}
      <InlineStat label="Open findings" value={s.counts.findings_open} tone={s.counts.findings_open ? "high" : undefined} />
      {s.counts.approvals_pending > 0 && <InlineStat label="Pending approvals" value={s.counts.approvals_pending} tone="approval" />}
      {s.counts.processing_errors > 0 && <InlineStat label="Processing errors" value={s.counts.processing_errors} tone="danger" hint="Events that were recorded but could not be processed" />}
      {meta.map(([k, v]) => (
        <InlineStat key={k} label={k.replace(/_/g, " ")} value={<Mono className="text-fg">{String(v)}</Mono>} />
      ))}
    </div>
  );
}

function SessionRow({ s, relation }: { s: SessionRef; relation: ReactNode }) {
  return (
    <li className="px-4 py-2.5">
      <div className="flex items-center gap-2 text-[13px]">
        <GitBranch className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
        <span className="text-xs text-fg-muted">{relation}</span>
        <EntityLink type="agent" id={s.agent.id} label={s.agent.name} />
      </div>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 pl-5 text-2xs">
        <EntityLink type="session" id={s.id} label={s.external_session_id} showIcon={false} />
        <RiskMeter score={s.risk_score} level={s.risk_level} size="sm" label={`Risk of session ${s.external_session_id}`} />
        {s.trifecta && <Badge tone="critical">Trifecta</Badge>}
        <StatusBadge status={s.status} />
      </div>
    </li>
  );
}

function RelatedSessions({ session: s }: { session: SessionDetail }) {
  if (!s.parent && s.children.length === 0) return null;
  return (
    <Section title="Delegation" description="Sessions linked by observed delegation (parent hands work to child)." flush>
      <ul className="divide-y divide-border/70">
        {s.parent && <SessionRow s={s.parent} relation="Delegated by" />}
        {s.children.map((c) => (
          <SessionRow key={c.id} s={c} relation="Delegated to" />
        ))}
      </ul>
      {s.child_count > s.children.length && <p className="px-4 py-2 text-2xs text-fg-faint">Showing {s.children.length} of {s.child_count} sub-sessions.</p>}
    </Section>
  );
}

function SessionFindings({ session: s }: { session: SessionDetail }) {
  return (
    <Section title="Findings" description={`${s.counts.findings_open} open of ${s.counts.findings_total} in this session.`} flush>
      {s.findings.length === 0 ? (
        <p className="px-4 py-4 text-xs text-fg-faint">No findings were raised in this session.</p>
      ) : (
        <ul className="divide-y divide-border/70">
          {s.findings.map((f) => (
            <li key={f.id} className="px-4 py-2.5">
              <div className="flex items-start gap-2">
                <SeverityBadge severity={f.severity} />
                <EntityLink type="finding" id={f.id} label={f.title} showIcon={false} className="min-w-0 whitespace-normal" />
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 pl-1 text-2xs text-fg-muted">
                <span>{FINDING_CATEGORY_LABELS[f.category] ?? f.category}</span>
                <StatusBadge status={f.status} />
                {f.occurrence_count > 1 && <span className="num">{f.occurrence_count}×</span>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
