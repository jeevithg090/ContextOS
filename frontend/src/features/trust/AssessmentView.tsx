/** Renders a trust assessment: level, capabilities, the deciding rule, every matching rule in
 * precedence order, the explanation and (for destinations) checks plus what was NOT verified. */
import { ShieldQuestion } from "lucide-react";
import { Badge, TrustBadge } from "@/components/ui";
import { EntityLink, Section } from "@/components/data";
import { cn } from "@/lib/format";
import { CapabilityChips, CheckList, ReasonList } from "./components";
import { sourceTypeLabel } from "./meta";
import type { Assessment, ExistingRecord, RuleRef } from "./types";

function RuleLine({ rule, deciding }: { rule: RuleRef; deciding: boolean }) {
  return (
    <li className={cn("flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2 text-[13px]", deciding && "bg-accent/[0.06]")}>
      <span className="num w-12 shrink-0 text-2xs text-fg-faint" title="Priority (higher wins)">
        P{rule.priority}
      </span>
      <span className="min-w-0 flex-1 truncate font-medium text-fg">{rule.name}</span>
      {rule.is_draft && <Badge tone="accent">Draft</Badge>}
      <code className="truncate font-mono text-2xs text-fg-muted" title={`${rule.match_field} pattern`}>
        {rule.match_field}: {rule.pattern}
      </code>
      {rule.source_type && <span className="text-2xs text-fg-faint">{sourceTypeLabel(rule.source_type)} only</span>}
      <TrustBadge level={rule.trust_level} />
      {deciding ? <Badge tone="ok">Decides</Badge> : <span className="text-2xs text-fg-faint">Overridden</span>}
    </li>
  );
}

export function MatchingRules({ assessment }: { assessment: Assessment }) {
  if (!assessment.matching_rules.length)
    return <p className="text-xs text-fg-muted">No trust rule matches, so the default for this kind of {assessment.scope} applies.</p>;
  const decider = assessment.matched_rule;
  const decidingIndex = decider ? assessment.matching_rules.findIndex((r) => r.id === decider.id && r.is_draft === decider.is_draft) : -1;
  return (
    <div className="space-y-1.5">
      <ol className="divide-y divide-border/70 overflow-hidden rounded-md border border-border" aria-label="Matching rules in precedence order">
        {assessment.matching_rules.map((r, i) => (
          <RuleLine key={`${r.id ?? "draft"}-${i}`} rule={r} deciding={i === decidingIndex} />
        ))}
      </ol>
      {decidingIndex === -1 && <p className="text-2xs text-fg-faint">None of these rules decides: a manual classification takes precedence over rules.</p>}
    </div>
  );
}

export function AssessmentView({ assessment, compact = false }: { assessment: Assessment; compact?: boolean }) {
  const isDestination = assessment.scope === "destination";
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <TrustBadge level={assessment.level} />
        <CapabilityChips capabilities={assessment.capabilities} wrap />
        <code className="min-w-0 truncate font-mono text-xs text-fg-muted" title="Canonical identifier">
          {assessment.canonical_identifier || "—"}
        </code>
        {assessment.kind && <span className="text-2xs text-fg-faint">as {assessment.kind}</span>}
      </div>
      <Section variant="plain" title="Why">
        <ReasonList reasons={assessment.reasons} />
      </Section>
      {!compact && (
        <Section variant="plain" title="Matching rules" description="Highest priority first; on a tie the more restrictive level wins.">
          <MatchingRules assessment={assessment} />
        </Section>
      )}
      {isDestination && (
        <>
          <Section variant="plain" title="Checks performed" description="Based on the destination's name or address only.">
            <CheckList checks={assessment.checks} />
          </Section>
          <NotVerified items={assessment.not_verified} />
        </>
      )}
    </div>
  );
}

export function NotVerified({ items }: { items: string[] }) {
  if (!items.length) return null;
  return (
    <div className="rounded-md border border-warn/30 bg-warn/[0.06] px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-xs font-medium text-warn">
        <ShieldQuestion className="h-3.5 w-3.5" aria-hidden />
        What ContextOS did not verify
      </div>
      <ul className="mt-1.5 list-disc space-y-1 pl-5 text-xs text-fg-muted">
        {items.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
    </div>
  );
}

/** "This identifier is already in your inventory" panel for dry-run results. */
export function ExistingRecordView({ existing }: { existing: ExistingRecord }) {
  const changes = existing.with_history.level !== existing.current_level;
  return (
    <div className="rounded-md border border-border bg-surface-2/40 p-3">
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <span className="text-fg-muted">Already recorded:</span>
        <EntityLink type={existing.type} id={existing.id} label={existing.with_history.canonical_identifier} />
        <span className="text-fg-faint">currently</span>
        <TrustBadge level={existing.current_level} />
        {existing.manually_classified && <Badge tone="accent">Manual</Badge>}
      </div>
      <p className="mt-1.5 text-xs text-fg-muted">
        With its recorded history ({existing.type === "source" ? `${existing.finding_count} unreviewed finding(s), ${existing.observation_count} observation(s)` : `${existing.transfer_count} transfer(s)`}),
        re-assessing it with these rules gives <TrustBadge level={existing.with_history.level} className="mx-0.5" />
        {changes ? " — a change from its stored classification." : " — the same as stored."}
      </p>
      {changes && <ReasonList reasons={existing.with_history.reasons} className="mt-2" />}
    </div>
  );
}
