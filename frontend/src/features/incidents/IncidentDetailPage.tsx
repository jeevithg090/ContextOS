/**
 * Incident — the investigator's workspace, answering "what happened, what is affected and what are
 * we doing about it?".
 *
 * Header (severity, status, key facts), the status workflow, the merged investigation timeline,
 * linked findings, involved agents / sessions / sources / destinations, ownership, notes and
 * activity, remediation tasks, and the evidence export. Live `incident.*` events refresh it.
 */
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Siren } from "lucide-react";
import { EntityLink, InlineStat, Section } from "@/components/data";
import { Badge, EmptyState, ErrorState, LoadingRows, Mono, PageHeader, SeverityBadge, SimulationBadge, StatusBadge } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { useDocumentTitle } from "@/hooks";
import { formatDateTime, timeAgo } from "@/lib/format";
import { isNotFound, useIncident } from "./api";
import { ActionsBar } from "./detail/ActionsBar";
import { ActivityPanel } from "./detail/ActivityPanel";
import { DetailsPanel } from "./detail/DetailsPanel";
import { FindingsActions, FindingsPanel } from "./detail/FindingsPanel";
import { InvestigationTimeline } from "./detail/InvestigationTimeline";
import { InvolvedPanel } from "./detail/InvolvedPanel";
import { TasksPanel } from "./detail/TasksPanel";
import { WorkflowPanel } from "./detail/WorkflowPanel";
import type { IncidentDetail } from "./types";

function Facts({ incident }: { incident: IncidentDetail }) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-border pb-3">
      <StatusBadge status={incident.status} />
      {incident.is_simulation && <SimulationBadge />}
      <InlineStat
        label="Opened"
        value={
          <time dateTime={incident.opened_at} title={formatDateTime(incident.opened_at)}>
            {timeAgo(incident.opened_at)}
          </time>
        }
        hint={incident.created_by.type === "system" ? "Opened automatically by ContextOS from a qualifying finding" : `Opened by ${incident.created_by.name}`}
      />
      <InlineStat
        label="Findings"
        value={`${incident.open_finding_count} open / ${incident.finding_count}`}
        tone={incident.open_finding_count > 0 ? undefined : "ok"}
        hint="Linked findings still open or acknowledged, out of all linked findings"
      />
      {incident.primary_agent && (
        <span className="inline-flex items-baseline gap-1.5 text-[13px]">
          <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Agent</span>
          <EntityLink type="agent" id={incident.primary_agent.id} label={incident.primary_agent.name} showIcon={false} />
        </span>
      )}
      {incident.primary_session && (
        <span className="inline-flex items-baseline gap-1.5 text-[13px]">
          <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Session</span>
          <EntityLink type="session" id={incident.primary_session.id} label={incident.primary_session.external_session_id} showIcon={false} className="font-mono text-xs" />
        </span>
      )}
      <InlineStat label="Assignee" value={incident.assignee?.name ?? "Unassigned"} tone={incident.assignee ? undefined : "warn"} />
    </div>
  );
}

export function IncidentDetailPage() {
  const { incidentId } = useParams();
  const query = useIncident(incidentId);
  useDocumentTitle(query.data ? `${query.data.key} ${query.data.title}` : null);
  const { can } = useAuth();
  const canWrite = can("write");

  if (query.isLoading) return <LoadingRows rows={8} />;
  if (isNotFound(query.error)) {
    return (
      <EmptyState
        icon={<Siren className="h-5 w-5" aria-hidden />}
        title="Incident not found"
        description="It may belong to another organisation, or the link is wrong."
        action={
          <Link to="/incidents" className="text-xs text-accent hover:underline">
            Back to incidents
          </Link>
        }
      />
    );
  }
  if (query.error || !query.data) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const incident = query.data;

  return (
    <>
      <Link to="/incidents" className="mb-3 inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Incidents
      </Link>
      <PageHeader
        eyebrow={
          <span className="inline-flex items-center gap-2">
            Incident <Mono className="text-2xs normal-case tracking-normal text-fg-faint">{incident.key}</Mono>
          </span>
        }
        title={
          <span className="inline-flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <span className="min-w-0 break-words">{incident.title}</span>
          </span>
        }
        actions={<ActionsBar incident={incident} canWrite={canWrite} />}
      />
      <Facts incident={incident} />

      <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(340px,1fr)]">
        <div className="min-w-0 space-y-4">
          <Section title="Status" description="Where the investigation stands. Closing an incident requires a resolution.">
            <WorkflowPanel incident={incident} canWrite={canWrite} />
          </Section>

          {incident.summary && (
            <Section title="Summary">
              <p className="whitespace-pre-wrap break-words text-[13px] leading-relaxed text-fg">{incident.summary}</p>
            </Section>
          )}

          <Section
            title="Investigation timeline"
            description="Everything recorded around this incident — events from the involved sessions, findings, policy decisions, approvals and activity — in server-time order."
          >
            <InvestigationTimeline incidentId={incident.id} />
          </Section>

          <Section
            title="Findings"
            description="Detections grouped into this incident, most severe first. Each keeps its own triage status."
            actions={
              <>
                <Badge tone="neutral">{incident.findings.length}</Badge>
                <FindingsActions incident={incident} canWrite={canWrite} />
              </>
            }
            flush
          >
            <FindingsPanel incident={incident} />
          </Section>
        </div>

        <aside className="min-w-0 space-y-4" aria-label="Ownership, involved records and activity">
          <Section title="Details">
            <DetailsPanel incident={incident} canWrite={canWrite} />
          </Section>
          <Section title="Involved" description="Records attached to this incident's findings.">
            <InvolvedPanel involved={incident.involved} />
          </Section>
          <Section title="Remediation tasks" actions={<Badge tone="neutral">{incident.tasks.length}</Badge>}>
            <TasksPanel tasks={incident.tasks} />
          </Section>
          <Section title="Notes & activity" description="Investigator notes and every change to this incident.">
            <ActivityPanel incident={incident} canWrite={canWrite} />
          </Section>
        </aside>
      </div>
    </>
  );
}
