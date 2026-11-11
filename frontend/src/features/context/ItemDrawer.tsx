/**
 * Side panel for one context item: what it was, where it came from, what detection found in it and
 * how it connects to its session. Everything shown was redacted before storage.
 */
import { ReceiptText } from "lucide-react";
import { DecisionBadge, Drawer, EmptyState, EnforcementBadge, ErrorState, KeyValue, LoadingRows, Mono, SimulationBadge, TrustBadge } from "@/components/ui";
import { CodeBlock, CopyButton, EntityLink, JsonView, entityHref } from "@/components/data";
import { formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { isNotFound, useContextItem } from "./api";
import { DetectionList, FindingList } from "./DetectionList";
import { formatLength, sourceTypeMeta } from "./meta";
import { ButtonLink, DetectionCell, DrawerSection, SensitivityBadge } from "./parts";
import { ProvenanceChain } from "./ProvenanceChain";
import { RedactionLegend } from "./RedactionLegend";
import type { ContextItemDetail } from "./types";

export function ItemDrawer({ itemId, onClose }: { itemId: string | null; onClose: () => void }) {
  const query = useContextItem(itemId);
  const item = query.data;
  const title = item ? item.source.display_name || item.source.identifier : "Context item";
  const subtitle = item ? `${sourceTypeMeta(item.source.source_type).label} · received ${timeAgo(item.received_at)}` : undefined;

  return (
    <Drawer
      open={!!itemId}
      onOpenChange={(open) => !open && onClose()}
      title={title}
      subtitle={subtitle}
      actions={item && <ButtonLink to={entityHref("context_item", item.id) ?? "#"} icon={<ReceiptText className="h-3.5 w-3.5" aria-hidden />}>Receipt</ButtonLink>}
    >
      {query.isLoading ? (
        <LoadingRows rows={8} />
      ) : query.error ? (
        isNotFound(query.error) ? (
          <EmptyState title="Context item not found" description="It may have been deleted, or it belongs to a different organisation." />
        ) : (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        )
      ) : item ? (
        <ItemBody item={item} />
      ) : null}
    </Drawer>
  );
}

function ItemBody({ item }: { item: ContextItemDetail }) {
  const trustChanged = item.source.trust_level !== item.trust_level;
  return (
    <>
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-5 py-3">
        <TrustBadge level={item.trust_level} />
        {trustChanged && (
          <span className="inline-flex items-center gap-1 text-2xs text-fg-muted">
            source now <TrustBadge level={item.source.trust_level} />
          </span>
        )}
        <SensitivityBadge sensitivity={item.sensitivity} containsSecrets={item.contains_secrets} />
        <DetectionCell detection={item.detection} />
        {item.is_simulation && <SimulationBadge />}
      </div>

      <DrawerSection title="Where it came from">
        <KeyValue
          items={[
            { label: "Source", value: <EntityLink type="source" id={item.source.id} label={item.source.identifier} /> },
            { label: "Agent", value: <EntityLink type="agent" id={item.agent.id} label={item.agent.name} /> },
            { label: "Session", value: <EntityLink type="session" id={item.session.id} label={item.session.external_session_id} /> },
            ...(item.tool_invocation
              ? [{
                  label: "Returned by",
                  value: (
                    <span className="inline-flex flex-wrap items-center gap-1.5">
                      <EntityLink type="tool_invocation" id={item.tool_invocation.id} label={item.tool_invocation.tool_name} sessionId={item.session.id} />
                      {item.tool_invocation.decision && <DecisionBadge decision={item.tool_invocation.decision} />}
                      <EnforcementBadge mode={item.tool_invocation.enforcement} />
                    </span>
                  ),
                }]
              : []),
            ...(item.origin_agent ? [{ label: "Sent by agent", value: <EntityLink type="agent" id={item.origin_agent.id} label={item.origin_agent.name} /> }] : []),
            { label: "Collected via", value: <Mono>{item.collected_via}</Mono> },
            { label: "Received", value: <span title="Server clock — authoritative">{formatDateTime(item.received_at)} <span className="text-fg-faint">(server)</span></span> },
            { label: "Reported", value: <span title="Client-reported collection time — not trusted">{formatDateTime(item.collected_at)} <span className="text-fg-faint">(client)</span></span> },
            { label: "Content", value: `${item.content_type} · ${formatLength(item.content_length)}` },
            {
              label: "SHA-256",
              value: item.content_hash ? (
                <span className="inline-flex min-w-0 items-center gap-1">
                  <Mono className="truncate">{item.content_hash}</Mono>
                  <CopyButton size="xs" value={item.content_hash} label="Copy content hash" />
                </span>
              ) : (
                "—"
              ),
            },
          ]}
        />
      </DrawerSection>

      <DrawerSection title="Observed provenance">
        <ProvenanceChain item={item} />
      </DrawerSection>

      <DrawerSection
        title="Redacted preview"
        description={item.preview_truncated ? `Showing the first part of ${formatNumber(item.content_length)} characters.` : undefined}
      >
        <div className="space-y-2">
          {item.redacted_preview ? (
            <CodeBlock code={item.redacted_preview} language={item.content_type} wrap maxHeight={260} />
          ) : (
            <p className="rounded-md border border-dashed border-border px-3 py-3 text-xs text-fg-muted">
              {item.content_length === 0 ? "The content was empty." : "No preview was stored: previews are disabled for this organisation, so only the hash and length were kept."}
            </p>
          )}
          <RedactionLegend secretTypes={item.secret_types} fingerprintCount={item.secret_fingerprint_count} previewStored={item.preview_stored} />
        </div>
      </DrawerSection>

      <DrawerSection title="Detections" description={item.detection.hit_count ? `Score ${item.detection.score.toFixed(2)} (0 – 1) across ${item.detection.hit_count} rule hits.` : undefined}>
        <DetectionList detection={item.detection} />
      </DrawerSection>

      <DrawerSection title="Findings">
        <FindingList findings={item.findings} />
      </DrawerSection>

      {Object.keys(item.item_metadata).length > 0 && (
        <DrawerSection title="Metadata">
          <JsonView value={item.item_metadata} />
        </DrawerSection>
      )}
    </>
  );
}
