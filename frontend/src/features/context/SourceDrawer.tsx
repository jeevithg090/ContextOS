/**
 * Side panel for one context source: why it has its trust classification, what it delivered, who
 * consumed it and what it triggered. Trust changes are made in the Trust Centre (linked).
 */
import { ShieldCheck } from "lucide-react";
import { Badge, Drawer, EmptyState, ErrorState, KeyValue, LoadingRows, SeverityBadge, TrustBadge } from "@/components/ui";
import { EntityLink, InlineStat, entityHref } from "@/components/data";
import { humanize } from "@/lib/domain";
import { formatDateTime, formatNumber, pluralize, timeAgo } from "@/lib/format";
import { isNotFound, useContextSource } from "./api";
import { FindingList } from "./DetectionList";
import { sourceTypeMeta } from "./meta";
import { ButtonLink, DetectionCell, DrawerSection } from "./parts";
import type { ContextSourceDetail } from "./types";

export function SourceDrawer({ sourceId, includeSimulated, onClose, onOpenItem }: { sourceId: string | null; includeSimulated: boolean; onClose: () => void; onOpenItem: (id: string) => void }) {
  const query = useContextSource(sourceId, includeSimulated);
  const source = query.data;
  return (
    <Drawer
      open={!!sourceId}
      onOpenChange={(open) => !open && onClose()}
      title={source ? source.display_name || source.identifier : "Context source"}
      subtitle={source ? `${sourceTypeMeta(source.source_type).label} · last seen ${timeAgo(source.last_seen_at)}` : undefined}
      actions={source && <ButtonLink to={entityHref("source", source.id) ?? "/trust"} icon={<ShieldCheck className="h-3.5 w-3.5" aria-hidden />}>Trust Centre</ButtonLink>}
    >
      {query.isLoading ? (
        <LoadingRows rows={8} />
      ) : query.error ? (
        isNotFound(query.error) ? (
          <EmptyState title="Source not found" description="It may have been removed, or it belongs to a different organisation." />
        ) : (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        )
      ) : source ? (
        <SourceBody source={source} onOpenItem={onOpenItem} />
      ) : null}
    </Drawer>
  );
}

function SourceBody({ source, onOpenItem }: { source: ContextSourceDetail; onOpenItem: (id: string) => void }) {
  return (
    <>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-border px-5 py-3">
        <InlineStat label="Items" value={formatNumber(source.item_count)} hint="Context items received from this source" />
        <InlineStat label="Sessions" value={formatNumber(source.session_count)} />
        <InlineStat label="Agents" value={formatNumber(source.agent_count)} />
        <InlineStat label="With detections" value={formatNumber(source.items_with_detections)} tone={source.items_with_detections ? "high" : undefined} />
        <InlineStat label="Open findings" value={formatNumber(source.open_finding_count)} tone={source.open_finding_count ? "high" : undefined} />
      </div>

      <DrawerSection title="Trust classification" description="The current classification. Each context item also keeps the trust it had when it was received.">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <TrustBadge level={source.trust_level} />
          {source.trust_capabilities.map((c) => (
            <Badge key={c} tone="neutral" title="What content from this source may do">
              {humanize(c)}
            </Badge>
          ))}
          {source.manually_classified && <Badge tone="accent">Set by a person</Badge>}
        </div>
        {source.trust_reasons.length > 0 ? (
          <ul className="list-disc space-y-1 pl-4 text-xs text-fg-muted" aria-label="Why it has this classification">
            {source.trust_reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-fg-muted">No explanation was recorded for this classification.</p>
        )}
        {source.trust_rule && (
          <p className="mt-2 text-xs text-fg-muted">
            Matched trust rule <span className="text-fg">{source.trust_rule.name}</span> (<span className="font-mono">{source.trust_rule.pattern}</span> →{" "}
            {source.trust_rule.trust_level}
            {source.trust_rule.enabled ? "" : ", now disabled"}).
          </p>
        )}
      </DrawerSection>

      <DrawerSection title="Identity">
        <KeyValue
          items={[
            { label: "Identifier", value: <span className="break-all font-mono text-xs">{source.identifier}</span> },
            ...(source.domain ? [{ label: "Domain", value: source.domain }] : []),
            ...(source.owner ? [{ label: "Owner", value: source.owner }] : []),
            { label: "First seen", value: formatDateTime(source.first_seen_at) },
            { label: "Last seen", value: formatDateTime(source.last_seen_at) },
            { label: "Observations", value: formatNumber(source.observation_count) },
          ]}
        />
      </DrawerSection>

      <DrawerSection title="Consumed by">
        {source.consumers.length === 0 ? (
          <p className="text-xs text-fg-muted">No agent has received content from this source in the selected data.</p>
        ) : (
          <ul className="divide-y divide-border/70" aria-label="Agents that received this source">
            {source.consumers.map((c) => (
              <li key={c.agent.id} className="flex items-center justify-between gap-3 py-2 first:pt-0 last:pb-0 text-xs">
                <EntityLink type="agent" id={c.agent.id} label={c.agent.name} />
                <span className="num text-fg-muted">
                  {pluralize(c.item_count, "item")} · {pluralize(c.session_count, "session")} · {timeAgo(c.last_received_at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </DrawerSection>

      <DrawerSection title="Findings">
        {source.max_finding_severity && (
          <p className="mb-2 flex items-center gap-1.5 text-xs text-fg-muted">
            Worst severity recorded <SeverityBadge severity={source.max_finding_severity} />
          </p>
        )}
        <FindingList findings={source.findings} emptyLabel="No findings were raised from this source." />
      </DrawerSection>

      <DrawerSection title="Recent items" description={source.item_count > source.recent_items.length ? `The ${source.recent_items.length} most recent of ${formatNumber(source.item_count)}.` : undefined}>
        {source.recent_items.length === 0 ? (
          <p className="text-xs text-fg-muted">No items in the selected data.</p>
        ) : (
          <ul className="divide-y divide-border/70" aria-label="Recent items">
            {source.recent_items.map((item) => (
              <li key={item.id}>
                <button type="button" onClick={() => onOpenItem(item.id)} className="flex w-full items-center gap-3 py-2 text-left text-xs hover:bg-surface-2/60 focus-visible:bg-surface-2/60">
                  <span className="w-28 shrink-0 text-fg-muted" title={formatDateTime(item.received_at)}>
                    {timeAgo(item.received_at)}
                  </span>
                  <TrustBadge level={item.trust_level} />
                  <DetectionCell detection={item.detection} />
                  <span className="ml-auto truncate text-fg-faint">{item.agent.name ?? item.agent.id}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </DrawerSection>
    </>
  );
}
