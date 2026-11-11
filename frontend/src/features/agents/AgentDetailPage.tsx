/**
 * Agent profile — answers "what is this agent, how well is it protected, and what has it been doing?".
 * Posture with per-dimension evidence, current risk, relationships, sessions, tools, findings and
 * declared configuration, plus edit and (honestly worded) quarantine actions.
 */
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeft, Bot, Pencil } from "lucide-react";
import { Badge, Button, Card, EmptyState, EnforcementBadge, ErrorState, LoadingRows, PageHeader, SimulationBadge, StatusBadge, TabPanel, Tabs } from "@/components/ui";
import { FilterBar, FilterSelect, InlineStat, Pagination } from "@/components/data";
import { ApiError } from "@/lib/api";
import { useAuth } from "@/features/auth/AuthProvider";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useAgent, useAgentSessions } from "./api";
import { AgentToolsTable } from "./detail/AgentToolsTable";
import { ConfigurationPanel, FindingsPanel, RelationshipsPanel, RiskSummary } from "./detail/AgentPanels";
import { PosturePanel } from "./detail/PosturePanel";
import { QuarantineBanner, QuarantineButton } from "./detail/Quarantine";
import { SessionsTable } from "./detail/SessionsTable";
import { EditAgentDialog } from "./forms/AgentDialogs";
import { ENVIRONMENT_LABELS, environmentTone, frameworkLabel, integrationLabel } from "./meta";
import type { AgentDetail, SessionSort } from "./types";

const TABS = ["sessions", "tools", "findings", "configuration"] as const;
type Tab = (typeof TABS)[number];
const SESSION_PAGE = 25;

export function AgentDetailPage() {
  const { agentId } = useParams();
  const agent = useAgent(agentId);
  const { can } = useAuth();
  const [editOpen, setEditOpen] = useState(false);

  if (agent.isLoading) return <LoadingRows rows={8} />;
  if (agent.error instanceof ApiError && agent.error.status === 404) {
    return (
      <EmptyState
        icon={<Bot className="h-5 w-5" />}
        title="Agent not found"
        description="It may belong to another organisation or the link is wrong."
        action={
          <Link to="/agents" className="text-xs text-accent hover:underline">
            Back to agents
          </Link>
        }
      />
    );
  }
  if (agent.error || !agent.data) return <ErrorState error={agent.error} onRetry={() => agent.refetch()} />;
  const a = agent.data;

  return (
    <>
      <Link to="/agents" className="mb-3 inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Agents
      </Link>
      <PageHeader
        eyebrow="Agent"
        title={
          <span className="inline-flex flex-wrap items-center gap-2">
            {a.name}
            <StatusBadge status={a.status} />
            {a.is_simulation && <SimulationBadge />}
          </span>
        }
        description={a.description ?? undefined}
        actions={
          <>
            {can("write") && (
              <Button size="sm" variant="outline" icon={<Pencil className="h-3.5 w-3.5" aria-hidden />} onClick={() => setEditOpen(true)}>
                Edit
              </Button>
            )}
            {can("write") && <QuarantineButton agent={a} canManage={can("policy:manage")} />}
          </>
        }
      />
      <AgentFacts agent={a} />
      <QuarantineBanner agent={a} canManage={can("policy:manage")} />
      <div className="grid gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <PosturePanel agentId={a.id} />
        </div>
        <div className="space-y-5">
          <RiskSummary agent={a} />
          <RelationshipsPanel agent={a} />
        </div>
      </div>
      <AgentTabs agent={a} />
      {can("write") && <EditAgentDialog agent={a} open={editOpen} onOpenChange={setEditOpen} canEditPolicyFields={can("policy:manage")} />}
    </>
  );
}

function AgentFacts({ agent: a }: { agent: AgentDetail }) {
  const integration = a.integration;
  const mode = integration ? (integration.supports_enforcement ? "enforced" : a.decisions_by_enforcement.advisory ? "advisory" : "observed") : null;
  return (
    <div className="-mt-2 mb-5 flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-border pb-4">
      <InlineStat label="Framework" value={frameworkLabel(a.framework)} />
      <span className="inline-flex items-center gap-1.5">
        <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Environment</span>
        <Badge tone={environmentTone(a.environment)}>{ENVIRONMENT_LABELS[a.environment] ?? a.environment}</Badge>
      </span>
      <InlineStat label="Owner" value={a.owner ?? "—"} />
      {a.version && <InlineStat label="Version" value={a.version} />}
      <span className="inline-flex items-center gap-1.5" title={integration?.enforcement_basis}>
        <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Integration</span>
        {integration ? (
          <>
            <span className="text-[13px] text-fg">{integrationLabel(integration.kind)}</span>
            {mode && <EnforcementBadge mode={mode} />}
          </>
        ) : (
          <span className="text-[13px] text-fg-faint">{a.is_simulation ? "Simulation Lab" : "None reported yet"}</span>
        )}
      </span>
      <InlineStat label="Last seen" value={a.last_seen_at ? timeAgo(a.last_seen_at) : "Never"} hint={a.last_seen_at ? formatDateTime(a.last_seen_at) : undefined} />
      {a.labels.length > 0 && (
        <span className="flex flex-wrap items-center gap-1">
          {a.labels.map((l) => (
            <Badge key={l} tone={l === "quarantined" ? "deny" : "neutral"}>
              {l}
            </Badge>
          ))}
        </span>
      )}
    </div>
  );
}

function AgentTabs({ agent }: { agent: AgentDetail }) {
  const [params, setParams] = useSearchParams();
  const tab: Tab = (TABS as readonly string[]).includes(params.get("tab") ?? "") ? (params.get("tab") as Tab) : "sessions";
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState<SessionSort>("recent");
  const [offset, setOffset] = useState(0);
  const sessions = useAgentSessions(agent.id, { status: status || undefined, sort, limit: SESSION_PAGE, offset });

  const select = (value: string) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (value === "sessions") next.delete("tab");
        else next.set("tab", value);
        return next;
      },
      { replace: true },
    );

  return (
    <Tabs
      className="mt-6"
      value={tab}
      onValueChange={select}
      tabs={[
        { value: "sessions", label: "Sessions", count: agent.session_count },
        { value: "tools", label: "Tools", count: agent.observed_tool_count },
        { value: "findings", label: "Findings", count: agent.open_findings },
        { value: "configuration", label: "Configuration" },
      ]}
    >
      <TabPanel value="sessions" className="pt-3">
        <FilterBar>
          <FilterSelect
            label="Status"
            value={status}
            onChange={(v) => {
              setStatus(v);
              setOffset(0);
            }}
            options={[
              { value: "active", label: "Active" },
              { value: "ended", label: "Ended" },
            ]}
          />
          <FilterSelect
            label="Sort"
            value={sort}
            allLabel={null}
            onChange={(v) => {
              setSort(v as SessionSort);
              setOffset(0);
            }}
            options={[
              { value: "recent", label: "Most recent activity" },
              { value: "risk", label: "Highest risk" },
            ]}
          />
        </FilterBar>
        <Card className="overflow-hidden">
          <SessionsTable
            rows={sessions.data?.items}
            loading={sessions.isLoading}
            error={sessions.error}
            onRetry={() => sessions.refetch()}
            emptyTitle={status ? "No sessions with this status" : "No sessions yet"}
            emptyDescription="Sessions appear when the integration reports events for this agent."
          />
        </Card>
        {sessions.data && <Pagination total={sessions.data.total} limit={SESSION_PAGE} offset={offset} onChange={setOffset} itemLabel="sessions" />}
      </TabPanel>
      <TabPanel value="tools" className="pt-3">
        <Card className="overflow-hidden">
          <AgentToolsTable agentId={agent.id} />
        </Card>
      </TabPanel>
      <TabPanel value="findings" className="pt-3">
        <Card className="overflow-hidden">
          <FindingsPanel agent={agent} />
        </Card>
      </TabPanel>
      <TabPanel value="configuration" className="pt-3">
        <Card>
          <ConfigurationPanel agent={agent} />
        </Card>
      </TabPanel>
    </Tabs>
  );
}
