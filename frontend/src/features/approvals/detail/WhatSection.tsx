/** "What the agent wants to do": tool, target, destination checks, resources and redacted arguments. */
import { CheckCircle2, CircleHelp, KeyRound, ShieldAlert, XCircle } from "lucide-react";
import { CopyButton, EntityLink, JsonView, Section } from "@/components/data";
import { Badge, KeyValue, Mono, TrustBadge } from "@/components/ui";
import { humanize, TONE_CLASSES, type Tone } from "@/lib/domain";
import { cn, formatDateTime, pluralize, shortId } from "@/lib/format";
import type { ApprovalDetail, DestinationCheck, DestinationDetail } from "../types";

const CHECK_META: Record<string, { tone: Tone; icon: typeof CheckCircle2; label: string }> = {
  pass: { tone: "ok", icon: CheckCircle2, label: "Passed" },
  fail: { tone: "danger", icon: XCircle, label: "Failed" },
  warn: { tone: "warn", icon: ShieldAlert, label: "Warning" },
  unknown: { tone: "neutral", icon: CircleHelp, label: "Not determined" },
};

export function WhatSection({ approval }: { approval: ApprovalDetail }) {
  const a = approval;
  const toolLabel = [a.tool.name ?? "Unknown tool", a.tool.server ? `on ${a.tool.server}` : null].filter(Boolean).join(" ");
  return (
    <Section title="What the agent wants to do" description={<span className="text-fg">{a.summary}</span>}>
      <div className="space-y-5">
        <KeyValue
          items={[
            {
              label: "Tool",
              value: (
                <span className="inline-flex flex-wrap items-center gap-1.5">
                  <span className="font-medium">{toolLabel}</span>
                  {a.tool.category && <Badge tone="neutral">{humanize(a.tool.category)}</Badge>}
                  {a.tool.risk_level && <span className="text-xs text-fg-muted">{humanize(a.tool.risk_level)} risk tool</span>}
                </span>
              ),
            },
            { label: "Target", value: a.target.primary ? <Mono className="break-all text-fg">{a.target.primary}</Mono> : <span className="text-fg-muted">No target could be derived from the arguments</span> },
            {
              label: "Agent",
              value: (
                <span className="inline-flex items-center gap-2">
                  <EntityLink type="agent" id={a.agent.id} label={a.agent.name} />
                  {a.agent.environment && <span className="text-xs text-fg-muted">{a.agent.environment}</span>}
                </span>
              ),
            },
            { label: "Session", value: <EntityLink type="session" id={a.session.id} label={a.session.external_session_id} /> },
            {
              label: "Tool call",
              value: a.tool_invocation_id ? (
                <span className="inline-flex items-center gap-2">
                  <EntityLink type="tool_invocation" id={a.tool_invocation_id} sessionId={a.session.id} />
                  {a.tool_invocation_status && <span className="text-xs text-fg-muted">status: {humanize(a.tool_invocation_status)}</span>}
                </span>
              ) : (
                "—"
              ),
            },
          ]}
        />

        {a.destination && <DestinationBlock destination={a.destination} />}

        {(a.secrets.in_arguments.length > 0 || a.secrets.from_session_context.length > 0) && (
          <div className="rounded-md border border-danger/30 bg-danger/[0.06] p-3">
            <div className="flex items-center gap-2 text-[13px] font-medium text-danger">
              <KeyRound className="h-4 w-4" aria-hidden /> Credentials in this call
            </div>
            <p className="mt-1 text-xs text-fg-muted">
              ContextOS stores and shows only redacted values. If you approve, the agent sends the real value.
            </p>
            <ul className="mt-2 space-y-1 text-xs">
              {a.secrets.in_arguments.map((s, i) => (
                <li key={`arg-${s.type}-${i}`} className="text-fg">
                  <span className="font-mono">{s.type}</span> detected in the arguments
                </li>
              ))}
              {a.secrets.from_session_context.map((s, i) => (
                <li key={`ctx-${s.type}-${i}`} className="flex flex-wrap items-center gap-1.5 text-fg">
                  <span className="font-mono">{s.type}</span> was previously seen in this session's context
                  {s.context_item_id && (
                    <>
                      in <EntityLink type="context_item" id={s.context_item_id} />
                    </>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        {a.resources.length > 0 && (
          <div>
            <div className="label-caps mb-2">Resources ({a.resources.length})</div>
            <ul className="divide-y divide-border/70 rounded-md border border-border">
              {a.resources.map((r, i) => (
                <li key={`${r.kind}:${r.id}:${i}`} className="flex items-start gap-2 px-3 py-2 text-xs">
                  <span className="w-16 shrink-0 text-fg-faint">{humanize(r.kind)}</span>
                  <span className="min-w-0 flex-1 break-all font-mono text-fg">{r.id}</span>
                  {r.sensitive && (
                    <Badge tone="high" title={r.reason ?? "Flagged as sensitive"}>
                      Sensitive
                    </Badge>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="space-y-1.5">
          <JsonView value={a.arguments} title="Arguments (redacted before storage)" defaultExpandDepth={2} maxHeightClassName="max-h-80" />
          {a.argument_hash && (
            <div className="flex items-center gap-1.5 text-2xs text-fg-faint">
              Argument hash <Mono title={a.argument_hash}>{a.argument_hash.slice(0, 16)}…</Mono>
              <CopyButton size="xs" label="Copy argument hash" value={a.argument_hash} />
            </div>
          )}
        </div>
      </div>
    </Section>
  );
}

function DestinationBlock({ destination: d }: { destination: DestinationDetail }) {
  const atDecision = d.classification_at_decision ?? d.classification;
  const changed = d.classification_at_decision && d.classification_at_decision !== d.classification;
  return (
    <div className="rounded-md border border-border">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="label-caps">Destination</span>
          <EntityLink type="destination" id={d.id} label={d.identifier} />
          <span className="text-2xs text-fg-faint">{humanize(d.kind)}</span>
        </div>
        <div className="flex items-center gap-1.5 text-2xs text-fg-faint">
          {changed ? (
            <>
              was <TrustBadge level={atDecision} /> now <TrustBadge level={d.classification} />
            </>
          ) : (
            <TrustBadge level={atDecision} />
          )}
        </div>
      </div>
      {d.checks.length > 0 && (
        <ul className="divide-y divide-border/60" aria-label="Destination checks">
          {d.checks.map((c, i) => (
            <CheckRow key={`${c.check}-${i}`} check={c} />
          ))}
        </ul>
      )}
      <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-border px-3 py-2 text-2xs text-fg-faint">
        <span>{pluralize(d.transfer_count, "earlier transfer")}</span>
        <span>{pluralize(d.blocked_count, "blocked call")}</span>
        <span>{pluralize(d.sensitive_transfer_count, "sensitive transfer")}</span>
        {d.first_seen_at && <span>first seen {formatDateTime(d.first_seen_at)}</span>}
        <span title={d.id}>{shortId(d.id)}</span>
      </div>
    </div>
  );
}

function CheckRow({ check }: { check: DestinationCheck }) {
  const meta = CHECK_META[check.result] ?? CHECK_META.unknown;
  const Icon = meta.icon;
  return (
    <li className="flex items-start gap-2 px-3 py-1.5 text-xs">
      <Icon className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", TONE_CLASSES[meta.tone].text)} aria-label={meta.label} />
      <span className="w-36 shrink-0 text-fg">{humanize(check.check)}</span>
      <span className="min-w-0 flex-1 text-fg-muted">{check.detail ?? meta.label}</span>
    </li>
  );
}
