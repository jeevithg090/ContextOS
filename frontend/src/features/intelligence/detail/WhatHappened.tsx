/**
 * "What happened": the recorded chain around a finding — source → context item → session → tool
 * call → decision → destination. Only links ContextOS observed are shown; a missing step is said
 * plainly rather than inferred. These are observed relationships, not proof of causation.
 */
import type { ReactNode } from "react";
import { Activity, Database, FileText, Globe, Scale, Wrench } from "lucide-react";
import { EntityLink, Timeline, type TimelineItem } from "@/components/data";
import { Badge, DecisionBadge, EnforcementBadge, StatusBadge, TrustBadge } from "@/components/ui";
import { ENFORCEMENT_META, humanize, severityTone, trustTone, type EnforcementMode } from "@/lib/domain";
import { formatNumber, pluralize, truncate } from "@/lib/format";
import type { FindingDetail } from "../types";

function Meta({ children }: { children: ReactNode }) {
  return <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">{children}</span>;
}

function Sep() {
  return (
    <span aria-hidden className="text-fg-faint">
      ·
    </span>
  );
}

function bytes(n: number): string {
  if (n < 1024) return `${formatNumber(n)} chars`;
  return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)}k chars`;
}

export function chainItems(f: FindingDetail): TimelineItem[] {
  const r = f.related;
  const items: TimelineItem[] = [];

  if (r.source) {
    const s = r.source;
    items.push({
      id: "source",
      icon: <Database aria-hidden />,
      tone: "neutral",
      timeLabel: "Source",
      title: <EntityLink type="source" id={s.id} label={truncate(s.display_name || s.identifier, 80)} showIcon={false} />,
      badges: <TrustBadge level={s.trust_level} />,
      description: (
        <Meta>
          <span>{humanize(s.source_type)}</span>
          <Sep />
          <span title="Detections against this source that were not judged false positives — the evidence the trust engine uses">
            {pluralize(s.finding_count, "detection")} counted against it
            {s.max_finding_severity ? `, worst ${s.max_finding_severity}` : ""}
          </span>
          {s.manually_classified && (
            <>
              <Sep />
              <span>trust set manually</span>
            </>
          )}
        </Meta>
      ),
    });
  }

  if (r.context_item) {
    const c = r.context_item;
    items.push({
      id: "context_item",
      icon: <FileText aria-hidden />,
      tone: c.contains_secrets ? "high" : "neutral",
      time: c.received_at,
      title: (
        <span className="inline-flex items-center gap-1.5">
          Content received <EntityLink type="context_item" id={c.id} label="view receipt" showIcon={false} className="text-xs" />
        </span>
      ),
      badges: (
        <>
          <TrustBadge level={c.trust_level} />
          {c.contains_secrets && (
            <Badge tone="high" title="A credential was detected in this content; only a redacted form is stored">
              Contained a credential
            </Badge>
          )}
        </>
      ),
      description: (
        <Meta>
          <span>via {humanize(c.collected_via)}</span>
          {c.retrieved_by && (
            <>
              <Sep />
              <span>
                returned by <span className="font-mono text-fg">{c.retrieved_by.tool_name}</span>
              </span>
            </>
          )}
          <Sep />
          <span>{humanize(c.sensitivity)} sensitivity</span>
          <Sep />
          <span>{bytes(c.content_length)}</span>
        </Meta>
      ),
    });
  }

  if (r.session) {
    const s = r.session;
    items.push({
      id: "session",
      icon: <Activity aria-hidden />,
      tone: severityTone(s.risk_level),
      time: s.started_at,
      title: (
        <span className="inline-flex items-center gap-1.5">
          Session <EntityLink type="session" id={s.id} label={s.external_session_id} showIcon={false} className="font-mono text-xs" />
        </span>
      ),
      badges: (
        <>
          <StatusBadge status={s.status} />
          <Badge tone={severityTone(s.risk_level)} title={`Session risk score ${s.risk_score} / 100`}>
            {humanize(s.risk_level)} risk · {s.risk_score}
          </Badge>
          {s.trifecta && (
            <Badge tone="critical" title="Sensitive data, untrusted content and an outbound channel all occurred in this session">
              Lethal trifecta
            </Badge>
          )}
        </>
      ),
      description: r.agent ? (
        <Meta>
          <span>
            agent <EntityLink type="agent" id={r.agent.id} label={r.agent.name} showIcon={false} />
          </span>
          <Sep />
          <span>{humanize(r.agent.framework)}</span>
          <Sep />
          <span>{r.agent.environment}</span>
        </Meta>
      ) : undefined,
    });
  }

  if (r.tool_invocation) {
    const t = r.tool_invocation;
    items.push({
      id: "tool_invocation",
      icon: <Wrench aria-hidden />,
      tone: t.status === "denied" || t.status === "rejected" ? "deny" : "neutral",
      time: t.requested_at,
      title: (
        <span className="inline-flex items-center gap-1.5">
          Tool call <EntityLink type="tool_invocation" id={t.id} label={t.tool_name} sessionId={t.session_id} showIcon={false} className="font-mono" />
        </span>
      ),
      badges: <StatusBadge status={t.status} />,
      description: <span>{humanize(t.tool_category)} tool</span>,
    });
  }

  if (r.decision) {
    const d = r.decision;
    const mode = ENFORCEMENT_META[d.enforcement as EnforcementMode];
    items.push({
      id: "decision",
      icon: <Scale aria-hidden />,
      tone: d.decision === "DENY" ? "deny" : d.decision === "ALLOW" ? "allow" : "approval",
      time: d.evaluated_at,
      title: (
        <span className="inline-flex items-center gap-1.5">
          Policy decision <EntityLink type="policy_decision" id={d.id} label="replay" sessionId={d.session_id} showIcon={false} className="text-xs" />
        </span>
      ),
      badges: (
        <>
          <DecisionBadge decision={d.decision} />
          <EnforcementBadge mode={d.enforcement} />
        </>
      ),
      description: (
        <span className="block space-y-1">
          {d.explanation && <span className="block">{d.explanation}</span>}
          {mode && <span className="block text-fg-faint">{mode.description}</span>}
          {d.matched_policies.length > 0 && (
            <span className="flex flex-wrap items-center gap-1.5">
              <span className="text-fg-faint">Matched</span>
              {d.matched_policies.map((p, i) => (
                <span key={`${p.policy_id ?? p.name}-${i}`} className="inline-flex items-center gap-1">
                  {p.policy_id ? <EntityLink type="policy" id={p.policy_id} label={p.name} showIcon={false} /> : <span className="text-fg">{p.name}</span>}
                  {p.mode && <span className="text-fg-faint">({p.mode})</span>}
                </span>
              ))}
            </span>
          )}
        </span>
      ),
    });
  }

  if (r.destination) {
    const d = r.destination;
    items.push({
      id: "destination",
      icon: <Globe aria-hidden />,
      tone: trustTone(d.classification),
      timeLabel: "Destination",
      title: <EntityLink type="destination" id={d.id} label={truncate(d.identifier, 90)} showIcon={false} className="font-mono text-xs" />,
      badges: <TrustBadge level={d.classification} />,
      description: <span>{humanize(d.kind)}</span>,
    });
  }

  return items;
}

export function WhatHappened({ finding }: { finding: FindingDetail }) {
  const items = chainItems(finding);
  const r = finding.related;
  const missing: string[] = [];
  if (!r.source && !r.context_item) missing.push("No content source is linked: this finding was raised from the agent's actions, not from something it read.");
  if (!r.tool_invocation && !r.decision) missing.push("No tool call is linked: the detection happened when the content was received, before the agent acted on it.");

  return (
    <div className="space-y-3">
      <Timeline items={items} aria-label="Recorded chain of events" emptyLabel="No related records were linked when this finding was raised." />
      {missing.length > 0 && (
        <ul className="space-y-1 text-2xs text-fg-faint">
          {missing.map((m) => (
            <li key={m}>{m}</li>
          ))}
        </ul>
      )}
      <p className="border-t border-border pt-2 text-2xs leading-relaxed text-fg-faint">{finding.provenance_note}</p>
    </div>
  );
}
