import { ArrowLeft, ArrowRight, ShieldAlert } from "lucide-react";
import { Badge, EmptyState, KeyValue, Mono, SeverityBadge, StatusBadge } from "@/components/ui";
import { EntityLink, RiskMeter, Section } from "@/components/data";
import { ENFORCEMENT_META, FINDING_CATEGORY_LABELS, SEVERITIES, type EnforcementMode } from "@/lib/domain";
import { formatDateTime, timeAgo } from "@/lib/format";
import { relationshipLabel, sortedCounts, toolCategoryLabel } from "../meta";
import type { AgentDetail } from "../types";

/** Current exposure: highest active-session risk, unresolved findings and how decisions were enforced. */
export function RiskSummary({ agent }: { agent: AgentDetail }) {
  const enforcement = sortedCounts(agent.decisions_by_enforcement, ["enforced", "advisory", "observed"]);
  const total = enforcement.reduce((sum, [, n]) => sum + n, 0);
  return (
    <Section title="Current risk" description="From persisted session risk, findings and policy decisions.">
      <div className="space-y-4">
        <div>
          <div className="label-caps mb-1">Highest active-session risk</div>
          {agent.active_session_count > 0 ? (
            <RiskMeter score={agent.risk_score} level={agent.risk_level} showLevel label="Highest active-session risk" />
          ) : (
            <p className="text-xs text-fg-faint">No active session. Ended sessions keep their own risk scores.</p>
          )}
        </div>
        <div>
          <div className="label-caps mb-1.5">Unresolved findings</div>
          {agent.open_findings > 0 ? (
            <div className="flex flex-wrap gap-2">
              {SEVERITIES.filter((s) => agent.findings_by_severity[s]).map((s) => (
                <span key={s} className="inline-flex items-center gap-1">
                  <SeverityBadge severity={s} />
                  <span className="num text-xs text-fg">{agent.findings_by_severity[s]}</span>
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-fg-faint">None open or acknowledged.</p>
          )}
        </div>
        <div>
          <div className="label-caps mb-1.5">Policy decisions</div>
          {total > 0 ? (
            <ul className="space-y-1 text-xs">
              {enforcement.map(([mode, n]) => (
                <li key={mode} className="flex items-center justify-between gap-2" title={ENFORCEMENT_META[mode as EnforcementMode]?.description}>
                  <span className="text-fg-muted">{ENFORCEMENT_META[mode as EnforcementMode]?.label ?? mode}</span>
                  <span className="num text-fg">{n}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-fg-faint">No tool call has been evaluated yet.</p>
          )}
        </div>
      </div>
    </Section>
  );
}

export function RelationshipsPanel({ agent }: { agent: AgentDetail }) {
  return (
    <Section title="Relationships" description="Observed delegations and messages, not causation." flush>
      {agent.relationships.length === 0 ? (
        <p className="px-4 py-4 text-xs text-fg-faint">No delegation or messaging with other agents has been observed.</p>
      ) : (
        <ul className="divide-y divide-border/70">
          {agent.relationships.map((r) => (
            <li key={r.id} className="px-4 py-2.5">
              <div className="flex items-center gap-2 text-[13px]">
                {r.direction === "outgoing" ? <ArrowRight className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden /> : <ArrowLeft className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />}
                <span className="text-xs text-fg-muted">{relationshipLabel(r.relationship_type, r.direction)}</span>
                <EntityLink type="agent" id={r.other_agent.id} label={r.other_agent.name} />
                {r.other_agent.status !== "active" && <StatusBadge status={r.other_agent.status} />}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 pl-5 text-2xs text-fg-muted">
                <span className="num">{r.event_count}× · last {timeAgo(r.last_seen_at)}</span>
                {r.crosses_trust_boundary && (
                  <Badge tone="danger" title="The receiving session consumed less-trusted content than the sending session">
                    <ShieldAlert className="h-3 w-3" aria-hidden />
                    Crosses trust boundary
                  </Badge>
                )}
                {(r.direction === "outgoing" ? r.last_child_session_id : r.last_parent_session_id) && (
                  <EntityLink
                    type="session"
                    id={r.direction === "outgoing" ? r.last_child_session_id : r.last_parent_session_id}
                    label={`Latest ${r.other_agent.name} session`}
                    showIcon={false}
                  />
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

export function FindingsPanel({ agent }: { agent: AgentDetail }) {
  if (agent.recent_findings.length === 0) {
    return <EmptyState title="No unresolved findings" description="Findings raised by detection, policy and risk evaluation for this agent's sessions appear here." />;
  }
  return (
    <div>
      <p className="border-b border-border px-4 py-2 text-xs text-fg-muted">
        The {agent.recent_findings.length} most severe of {agent.open_findings} unresolved findings. Open a finding to triage it.
      </p>
      <ul className="divide-y divide-border/70">
        {agent.recent_findings.map((f) => (
          <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5">
            <SeverityBadge severity={f.severity} />
            <EntityLink type="finding" id={f.id} label={f.title} showIcon={false} className="min-w-0 max-w-[60ch]" />
            <span className="text-2xs text-fg-faint">{FINDING_CATEGORY_LABELS[f.category] ?? f.category}</span>
            <span className="ml-auto flex items-center gap-3 text-2xs text-fg-muted">
              {f.occurrence_count > 1 && <span className="num">{f.occurrence_count}×</span>}
              <StatusBadge status={f.status} />
              {f.session_id && <EntityLink type="session" id={f.session_id} label="Session" showIcon={false} />}
              <time dateTime={f.last_seen_at} title={formatDateTime(f.last_seen_at)}>
                {timeAgo(f.last_seen_at)}
              </time>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ConfigurationPanel({ agent }: { agent: AgentDetail }) {
  const caps = agent.declared_capabilities;
  return (
    <div className="grid gap-6 p-4 lg:grid-cols-[2fr_1fr]">
      <div>
        <div className="label-caps mb-2">Declared tools</div>
        {caps.tools.length === 0 ? (
          <p className="text-xs text-fg-faint">No tools declared. Without a declaration, every observed tool counts as expected and undeclared use cannot stand out.</p>
        ) : (
          <ul className="divide-y divide-border/70 rounded border border-border">
            {caps.tools.map((t) => (
              <li key={t.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5">
                <Mono className="min-w-0 flex-1 truncate text-fg">{t.name}</Mono>
                <span className="text-xs text-fg-muted">{toolCategoryLabel(t.category)}</span>
                <SeverityBadge severity={t.risk_level} />
                {t.category_hint && t.category_hint !== t.category && <span className="text-2xs text-fg-faint">hint: {toolCategoryLabel(t.category_hint)}</span>}
              </li>
            ))}
          </ul>
        )}
      </div>
      <KeyValue
        items={[
          { label: "Labels", value: agent.labels.length ? <span className="flex flex-wrap gap-1">{agent.labels.map((l) => <Badge key={l}>{l}</Badge>)}</span> : <span className="text-fg-faint">None</span> },
          { label: "Permissions", value: caps.permissions.length ? <span className="font-mono text-xs">{caps.permissions.join(", ")}</span> : <span className="text-fg-faint">None declared</span> },
          { label: "MCP servers", value: caps.mcp_servers.length ? <span className="font-mono text-xs">{caps.mcp_servers.join(", ")}</span> : <span className="text-fg-faint">None declared</span> },
          { label: "Registered", value: formatDateTime(agent.created_at) },
          { label: "Agent id", value: <Mono>{agent.id}</Mono> },
        ]}
      />
    </div>
  );
}
