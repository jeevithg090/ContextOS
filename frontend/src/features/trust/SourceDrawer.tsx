/** Source detail: classification and why, evidence downgrades, manual classification, findings,
 * recent observations and the trust history recorded in the audit trail. */
import { useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Badge, Button, Drawer, EmptyState, ErrorState, KeyValue, LoadingRows, SeverityBadge, SimulationBadge, StatusBadge, TrustBadge, useToast } from "@/components/ui";
import { ConfirmDialog, CopyButton, EntityLink, Section, Timeline, type TimelineItem } from "@/components/data";
import { useAuth } from "@/features/auth/AuthProvider";
import { ApiError } from "@/lib/api";
import { FINDING_CATEGORY_LABELS, TRUST_META, trustTone } from "@/lib/domain";
import { formatDateTime, formatNumber, pluralize, timeAgo } from "@/lib/format";
import { errorMessage, useReassessSource, useTrustSource } from "./api";
import { CapabilityChips, ReasonList } from "./components";
import { sourceTypeLabel } from "./meta";
import { SourceClassifyForm } from "./SourceClassifyForm";
import type { TrustSourceDetail } from "./types";

export function SourceDrawer({ sourceId, onClose }: { sourceId: string; onClose: () => void }) {
  const source = useTrustSource(sourceId);
  const data = source.data;
  return (
    <Drawer
      open
      onOpenChange={(open) => !open && onClose()}
      title={data ? data.display_name || data.identifier : "Source"}
      subtitle={data ? `${sourceTypeLabel(data.source_type)} · first seen ${timeAgo(data.first_seen_at)}` : undefined}
      actions={data && <ReassessButton source={data} />}
    >
      {source.isLoading ? (
        <LoadingRows rows={8} />
      ) : source.error ? (
        source.error instanceof ApiError && source.error.status === 404 ? (
          <EmptyState title="Source not found" description="It may belong to another organisation or have been removed by retention." />
        ) : (
          <ErrorState error={source.error} onRetry={() => void source.refetch()} />
        )
      ) : data ? (
        <SourceBody source={data} />
      ) : null}
    </Drawer>
  );
}

function ReassessButton({ source }: { source: TrustSourceDetail }) {
  const { can } = useAuth();
  const toast = useToast();
  const reassess = useReassessSource(source.id);
  if (!can("trust:manage")) return null;
  return (
    <Button
      size="sm"
      variant="outline"
      icon={<RefreshCw className="h-3.5 w-3.5" aria-hidden />}
      loading={reassess.isPending}
      onClick={async () => {
        try {
          const saved = await reassess.mutateAsync(false);
          const changed = saved.trust_level !== source.trust_level;
          toast.success(changed ? `Re-assessed: now ${TRUST_META[saved.trust_level].label}` : "Re-assessed: classification unchanged", "Evaluated with the current rules and findings.");
        } catch (err) {
          toast.error("Couldn’t re-assess this source", errorMessage(err));
        }
      }}
      title="Re-run the classification with the current trust rules and findings"
    >
      Re-assess
    </Button>
  );
}

function classifiedBy(source: TrustSourceDetail) {
  if (source.manually_classified) {
    const m = source.manual_classification;
    return m ? `Manually, by ${m.actor_label} ${timeAgo(m.at)}` : "Manually";
  }
  if (source.matched_rule)
    return (
      <Link to={`/trust?tab=rules&rule=${encodeURIComponent(source.matched_rule.id ?? "")}`} className="text-accent hover:underline">
        Rule “{source.matched_rule.name}”
      </Link>
    );
  return "The default for this source type (no rule matches)";
}

function SourceBody({ source }: { source: TrustSourceDetail }) {
  const { can } = useAuth();
  const canManage = can("trust:manage");
  const toast = useToast();
  const reassess = useReassessSource(source.id);
  const [confirmReset, setConfirmReset] = useState(false);
  const downgrade = source.evidence_downgrade;

  const history: TimelineItem[] = source.history.map((h) => ({
    id: h.id,
    time: h.at,
    tone: h.to_level ? trustTone(h.to_level) : "neutral",
    title: h.summary,
    description: (
      <>
        {h.actor_label}
        {h.note && <span className="block text-fg-muted">“{h.note}”</span>}
      </>
    ),
  }));

  return (
    <div className="space-y-5 p-5">
      <section aria-label="Classification" className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <TrustBadge level={source.trust_level} />
          {source.manually_classified && <Badge tone="accent">Manual</Badge>}
          <CapabilityChips capabilities={source.trust_capabilities} wrap />
        </div>
        <p className="text-xs text-fg-muted">Classified by: {classifiedBy(source)}</p>
        {downgrade && (
          <div role="note" className="flex gap-2.5 rounded-md border border-trust-suspicious/30 bg-trust-suspicious/[0.07] px-3 py-2.5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-trust-suspicious" aria-hidden />
            <div className="space-y-1 text-xs">
              <div className="flex flex-wrap items-center gap-1.5 font-medium text-fg">
                Evidence downgrade: <TrustBadge level={downgrade.level_without_evidence} /> → <TrustBadge level={downgrade.level} />
              </div>
              <p className="text-fg-muted">{downgrade.explanation}</p>
            </div>
          </div>
        )}
      </section>

      <Section variant="plain" title="Why it has this classification">
        <ReasonList reasons={source.trust_reasons} />
      </Section>

      {canManage && (
        <Section
          title="Classify manually"
          description="Overrides trust rules for this source. It never overrides recorded evidence."
          actions={
            source.manually_classified && (
              <Button size="xs" variant="ghost" onClick={() => setConfirmReset(true)}>
                Return to rules
              </Button>
            )
          }
        >
          <SourceClassifyForm key={`${source.id}:${source.manual_classification?.at ?? "none"}`} source={source} />
        </Section>
      )}

      <Section variant="plain" title={`Findings (${formatNumber(source.findings_total)})`} description="Findings marked false positive stop counting as evidence once the source is re-assessed.">
        {source.findings.length === 0 ? (
          <p className="text-xs text-fg-muted">No findings were raised on content from this source.</p>
        ) : (
          <ul className="divide-y divide-border/70 rounded-md border border-border">
            {source.findings.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-[13px]">
                <SeverityBadge severity={f.severity} />
                <span className="min-w-0 flex-1">
                  <EntityLink type="finding" id={f.id} label={f.title} showIcon={false} />
                  <span className="block text-2xs text-fg-faint">
                    {FINDING_CATEGORY_LABELS[f.category] ?? f.category} · {pluralize(f.occurrence_count, "occurrence")} · {timeAgo(f.last_seen_at)}
                  </span>
                </span>
                {f.is_simulation && <SimulationBadge />}
                <StatusBadge status={f.status} />
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section variant="plain" title="Recent observations" description="Trust shown is what each item had when it was ingested.">
        {source.recent_items.length === 0 ? (
          <p className="text-xs text-fg-muted">No context items are stored for this source (they may have been removed by retention).</p>
        ) : (
          <ul className="divide-y divide-border/70 rounded-md border border-border">
            {source.recent_items.map((item) => (
              <li key={item.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-[13px]">
                <EntityLink type="context_item" id={item.id} />
                <EntityLink type="agent" id={item.agent_id} label={item.agent_name} />
                <EntityLink type="session" id={item.session_id} />
                <span className="ml-auto flex items-center gap-1.5">
                  {item.is_simulation && <SimulationBadge />}
                  {item.max_severity && <SeverityBadge severity={item.max_severity} />}
                  <TrustBadge level={item.trust_level} />
                  <span className="w-20 text-right text-2xs text-fg-faint" title={formatDateTime(item.received_at)}>
                    {timeAgo(item.received_at)}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section variant="plain" title="Trust history" description="From the tamper-evident audit trail.">
        <Timeline items={history} timeFormat="datetime" dense emptyLabel="No trust changes have been recorded for this source." aria-label="Trust history" />
      </Section>

      <Section variant="plain" title="Details">
        <KeyValue
          items={[
            {
              label: "Identifier",
              value: (
                <span className="inline-flex items-center gap-1">
                  <span className="break-all font-mono text-xs">{source.identifier}</span>
                  <CopyButton value={source.identifier} label="Copy identifier" />
                </span>
              ),
            },
            { label: "Domain", value: source.domain ?? "—" },
            { label: "Type", value: sourceTypeLabel(source.source_type) },
            { label: "Observations", value: formatNumber(source.observation_count) },
            { label: "First seen", value: formatDateTime(source.first_seen_at) },
            { label: "Last seen", value: formatDateTime(source.last_seen_at) },
            { label: "Source id", value: <span className="font-mono text-xs">{source.id}</span> },
          ]}
        />
      </Section>

      <ConfirmDialog
        open={confirmReset}
        onOpenChange={setConfirmReset}
        title="Return this source to rule-based classification?"
        description="The manual classification is cleared and the source is re-assessed with the current trust rules."
        confirmLabel="Clear manual classification"
        onConfirm={async () => {
          const saved = await reassess.mutateAsync(true);
          toast.success(`Now classified by rules: ${TRUST_META[saved.trust_level].label}`);
        }}
      >
        <p>The change is recorded in the audit trail. You can classify it manually again at any time.</p>
      </ConfirmDialog>
    </div>
  );
}
