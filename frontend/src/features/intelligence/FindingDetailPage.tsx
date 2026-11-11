/**
 * Finding — answers "what did ContextOS detect, on what evidence, and what should we do about it?".
 *
 * Plain-language explanation and confidence, the redacted evidence resolved to records, the
 * recorded chain (source → context item → session → tool call → decision), remediation guidance,
 * triage (acknowledge / resolve / false positive / reopen), incident linking and remediation tasks.
 */
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, GitBranch, History, Radar } from "lucide-react";
import { EntityLink, EvidenceList, InlineStat, Section, type EvidenceItem } from "@/components/data";
import { Badge, EmptyState, ErrorState, LoadingRows, Mono, PageHeader, SeverityBadge, SimulationBadge, StatusBadge } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { isNotFound, useFinding } from "./api";
import { IncidentPanel } from "./detail/IncidentPanel";
import { TasksPanel } from "./detail/TasksPanel";
import { TriageActions, TriageHistory, TriageStatus } from "./detail/TriagePanel";
import { WhatHappened } from "./detail/WhatHappened";
import { CATEGORY_DESCRIPTIONS, categoryLabel, confidenceWords } from "./meta";
import type { FindingDetail, ResolvedEvidence } from "./types";
import { useTriage } from "./useTriage";

const linkButton =
  "inline-flex h-7 items-center gap-1.5 whitespace-nowrap rounded border border-border-strong px-2.5 text-xs text-fg transition-colors hover:bg-surface-2";

function toEvidence(e: ResolvedEvidence): EvidenceItem {
  if (e.found || !e.id) return { type: e.type, id: e.id, label: e.label, session_id: e.session_id, excerpt: e.excerpt, detail: e.detail };
  // The record was removed (retention) — keep the redacted excerpt, but do not link to nothing.
  const gone = "The referenced record is no longer available.";
  return { type: e.type, id: null, excerpt: e.excerpt, detail: e.detail ? `${e.detail} ${gone}` : gone };
}

function Paragraphs({ text }: { text: string }) {
  return (
    <div className="space-y-2 text-[13px] leading-relaxed text-fg">
      {text
        .split(/\n{2,}/)
        .map((p) => p.trim())
        .filter(Boolean)
        .map((p, i) => (
          <p key={i} className="whitespace-pre-wrap break-words">
            {p}
          </p>
        ))}
    </div>
  );
}

function Investigate({ finding }: { finding: FindingDetail }) {
  const sessionId = finding.related.session?.id ?? finding.session?.id;
  const links: Array<{ to: string; label: string; icon: ReactNode; hint: string }> = [
    {
      to: `/provenance?finding=${encodeURIComponent(finding.id)}`,
      label: "View in provenance graph",
      icon: <GitBranch className="h-3.5 w-3.5" aria-hidden />,
      hint: "Every record observed around this finding, as a graph",
    },
  ];
  if (sessionId) {
    links.push({
      to: `/replay/${encodeURIComponent(sessionId)}`,
      label: "Replay session",
      icon: <History className="h-3.5 w-3.5" aria-hidden />,
      hint: "Step through the session and try what-if policy changes (a simulation)",
    });
  }
  return (
    <div className="flex flex-wrap gap-2">
      {links.map((l) => (
        <Link key={l.to} to={l.to} className={linkButton} title={l.hint}>
          {l.icon}
          {l.label}
        </Link>
      ))}
    </div>
  );
}

function Header({ finding, actions }: { finding: FindingDetail; actions: ReactNode }) {
  const confidence = confidenceWords(finding.confidence);
  return (
    <>
      <Link to="/intelligence" className="mb-3 inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Security Intelligence
      </Link>
      <PageHeader
        eyebrow={
          <span className="inline-flex items-center gap-2">
            {categoryLabel(finding.category)}
            <Mono className="text-2xs normal-case tracking-normal text-fg-faint">{finding.rule_id}</Mono>
          </span>
        }
        title={
          <span className="inline-flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="min-w-0 break-words">{finding.title}</span>
          </span>
        }
        description={CATEGORY_DESCRIPTIONS[finding.category]}
        actions={actions}
      />
      <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-border pb-3">
        <StatusBadge status={finding.status} />
        {finding.is_simulation && <SimulationBadge />}
        <InlineStat
          label="Confidence"
          value={`${confidence.label.replace(/ confidence$/, "")} · ${confidence.percent}`}
          tone={confidence.tone}
          hint="How sure the detector is that this is a real problem, not how severe it would be"
        />
        <InlineStat label="Seen" value={`×${formatNumber(finding.occurrence_count)}`} hint="Repeats of the same problem in the same session are merged into this finding" />
        <InlineStat label="First seen" value={<time dateTime={finding.first_seen_at} title={formatDateTime(finding.first_seen_at)}>{timeAgo(finding.first_seen_at)}</time>} />
        <InlineStat label="Last seen" value={<time dateTime={finding.last_seen_at} title={formatDateTime(finding.last_seen_at)}>{timeAgo(finding.last_seen_at)}</time>} />
        {finding.agent && (
          <span className="inline-flex items-baseline gap-1.5 text-[13px]">
            <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Agent</span>
            <EntityLink type="agent" id={finding.agent.id} label={finding.agent.name} showIcon={false} />
          </span>
        )}
        {finding.session && (
          <span className="inline-flex items-baseline gap-1.5 text-[13px]">
            <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Session</span>
            <EntityLink type="session" id={finding.session.id} label={finding.session.external_session_id} showIcon={false} className="font-mono text-xs" />
          </span>
        )}
      </div>
    </>
  );
}

export function FindingDetailPage() {
  const { findingId } = useParams();
  const query = useFinding(findingId);
  const { can } = useAuth();
  const canWrite = can("write");
  const triage = useTriage();

  if (query.isLoading) return <LoadingRows rows={8} />;
  if (isNotFound(query.error)) {
    return (
      <EmptyState
        icon={<Radar className="h-5 w-5" aria-hidden />}
        title="Finding not found"
        description="It may belong to another organisation, or the link is wrong."
        action={
          <Link to="/intelligence" className="text-xs text-accent hover:underline">
            Back to Security Intelligence
          </Link>
        }
      />
    );
  }
  if (query.error || !query.data) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const f = query.data;
  const evidence = f.evidence.map(toEvidence);

  return (
    <>
      <Header
        finding={f}
        actions={canWrite ? <TriageActions finding={f} busy={triage.busyId === f.id} onAction={(action) => triage.start(action, { id: f.id, title: f.title })} /> : undefined}
      />

      <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
        <div className="min-w-0 space-y-4">
          <Section title="What ContextOS detected" description="In plain language, from the detector that raised this finding.">
            <Paragraphs text={f.explanation} />
          </Section>

          <Section title="What happened" description="The records linked to this finding, in the order they were observed." actions={<Investigate finding={f} />}>
            <WhatHappened finding={f} />
          </Section>

          <Section
            title="Evidence"
            description="What the detector matched. Excerpts were redacted before they were stored, so credentials never appear here."
            actions={<Badge tone="neutral">{evidence.length}</Badge>}
          >
            <EvidenceList evidence={evidence} sessionId={f.session?.id} />
          </Section>

          <Section title="How to remediate" description="Recommended next steps for this kind of finding.">
            {f.remediation ? (
              <Paragraphs text={f.remediation} />
            ) : (
              <p className="text-xs text-fg-muted">The detector gave no specific guidance. Review the evidence, decide whether the source should be trusted, and add a policy if this should be blocked next time.</p>
            )}
          </Section>
        </div>

        <aside className="min-w-0 space-y-4" aria-label="Triage and follow-up">
          <Section title="Triage">
            <TriageStatus finding={f} canWrite={canWrite} />
          </Section>
          <Section title="Incident" description="Group related findings into one investigation.">
            <IncidentPanel finding={f} canWrite={canWrite} />
          </Section>
          <Section title="Remediation tasks" description="Engineering Workspace tasks that reference this finding.">
            <TasksPanel finding={f} canWrite={canWrite} />
          </Section>
          <Section title="History" description="Every triage change is written to the audit log.">
            <TriageHistory finding={f} />
          </Section>
        </aside>
      </div>
      {triage.dialog}
    </>
  );
}
