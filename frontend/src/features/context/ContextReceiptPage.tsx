/**
 * Context Receipt (/context/:itemId) — a signed record of what ContextOS observed about one piece of
 * context: content hash, source and trust at ingest, collection method, timestamps and detections.
 * The server re-verifies the signature on every read; a tampered record shows INVALID. The page
 * states plainly what the receipt proves and what it does not (it never proves the model acted on it).
 */
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Check, Download, FileSearch, X } from "lucide-react";
import { Badge, Button, Card, EmptyState, ErrorState, KeyValue, Mono, PageHeader, SimulationBadge, Skeleton, TrustBadge } from "@/components/ui";
import { CopyButton, EntityLink, Section } from "@/components/data";
import { useDocumentTitle } from "@/hooks";
import { downloadFile } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { isNotFound, useContextReceipt } from "./api";
import { FindingList } from "./DetectionList";
import { describeSkew, receiptExport, receiptFilename, sourceTypeMeta } from "./meta";
import { ButtonLink } from "./parts";
import { ReceiptFieldsTable } from "./receipt/ReceiptFieldsTable";
import { SubsequentEvents } from "./receipt/SubsequentEvents";
import { VerificationBanner } from "./receipt/VerificationBanner";
import type { ContextReceipt } from "./types";

const FIRST_EVENTS = 10;
const MAX_EVENTS = 50;

export function ContextReceiptPage() {
  const { itemId } = useParams<{ itemId: string }>();
  const [eventsLimit, setEventsLimit] = useState(FIRST_EVENTS);
  const query = useContextReceipt(itemId, eventsLimit);
  const receiptSource = query.data?.related.source;
  useDocumentTitle(receiptSource ? `Receipt · ${receiptSource.display_name || receiptSource.identifier}` : null);
  const back = (
    <Link to="/context" className="mb-3 inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg">
      <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Context Explorer
    </Link>
  );

  if (query.isLoading) {
    return (
      <div aria-busy="true" aria-label="Loading receipt">
        {back}
        <Skeleton className="mb-2 h-6 w-1/3" />
        <Skeleton className="mb-6 h-4 w-2/3" />
        <Skeleton className="mb-4 h-16 w-full" />
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
          <Skeleton className="h-96" />
          <Skeleton className="h-96" />
        </div>
      </div>
    );
  }
  if (query.error || !query.data) {
    return (
      <>
        {back}
        <Card>
          {isNotFound(query.error) ? (
            <EmptyState
              icon={<FileSearch className="h-5 w-5" aria-hidden />}
              title="Receipt not found"
              description="No context item with this id exists in your organisation."
              action={<ButtonLink to="/context">Open the Context Explorer</ButtonLink>}
            />
          ) : (
            <ErrorState error={query.error} onRetry={() => void query.refetch()} />
          )}
        </Card>
      </>
    );
  }

  const receipt = query.data;
  return (
    <>
      {back}
      <ReceiptHeader receipt={receipt} />
      <div className="space-y-4">
        <VerificationBanner receipt={receipt} />
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
          <div className="min-w-0 space-y-4">
            <Statement receipt={receipt} />
            <Section title="Signed fields" description="Exactly what the signature covers. The content itself is never stored, so it is not part of the receipt." flush>
              <ReceiptFieldsTable receipt={receipt} />
            </Section>
            <Section title="What happened next in the session">
              <SubsequentEvents
                related={receipt.related}
                sessionId={receipt.related.session.id}
                loadingMore={query.isFetching && eventsLimit > FIRST_EVENTS}
                onShowMore={eventsLimit < MAX_EVENTS ? () => setEventsLimit(MAX_EVENTS) : undefined}
              />
            </Section>
          </div>
          <Aside receipt={receipt} />
        </div>
      </div>
    </>
  );
}

function ReceiptHeader({ receipt }: { receipt: ContextReceipt }) {
  const source = receipt.related.source;
  const hash = receipt.receipt.content_hash;
  return (
    <PageHeader
      eyebrow={
        <span className="inline-flex items-center gap-2">
          Context Receipt {receipt.is_simulation && <SimulationBadge />}
        </span>
      }
      title={source.display_name || source.identifier}
      description={receipt.statement.summary}
      actions={
        <>
          {hash && (
            <CopyButton value={hash} label="Copy content hash" className="h-7 rounded border border-border-strong px-2.5 text-xs text-fg hover:bg-surface-2">
              Copy hash
            </CopyButton>
          )}
          <Button
            size="sm"
            variant="primary"
            icon={<Download className="h-3.5 w-3.5" aria-hidden />}
            onClick={() => downloadFile(receiptFilename(receipt.receipt.context_item_id ?? "item"), receiptExport(receipt))}
          >
            Export receipt
          </Button>
        </>
      }
    />
  );
}

function Statement({ receipt }: { receipt: ContextReceipt }) {
  const { proves, does_not_prove } = receipt.statement;
  return (
    <Section title="What this receipt attests to">
      <div className="grid gap-5 md:grid-cols-2">
        <div className="min-w-0">
          <h3 className="label-caps mb-2 text-ok">It shows</h3>
          <ul className="space-y-2" aria-label="What the receipt proves">
            {proves.map((line, i) => (
              <li key={i} className="flex min-w-0 gap-2 text-xs leading-relaxed text-fg [overflow-wrap:anywhere]">
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ok" aria-hidden />
                {line}
              </li>
            ))}
          </ul>
        </div>
        <div className="min-w-0">
          <h3 className="label-caps mb-2">It does not show</h3>
          <ul className="space-y-2" aria-label="What the receipt does not prove">
            {does_not_prove.map((line, i) => (
              <li key={i} className="flex min-w-0 gap-2 text-xs leading-relaxed text-fg-muted [overflow-wrap:anywhere]">
                <X className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
                {line}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Section>
  );
}

function Aside({ receipt }: { receipt: ContextReceipt }) {
  const { related, timestamps, receipt: fields } = receipt;
  const SourceIcon = sourceTypeMeta(related.source.source_type).icon;
  const trustNow = related.source.trust_level;
  const trustThen = fields.source.trust_level_at_ingest;
  return (
    <aside className="space-y-4" aria-label="Receipt context">
      <Section title="Source & trust">
        <div className="flex items-start gap-2">
          <SourceIcon className="mt-0.5 h-4 w-4 shrink-0 text-fg-muted" aria-hidden />
          <div className="min-w-0">
            <EntityLink type="source" id={related.source.id} label={related.source.identifier} showIcon={false} className="break-all" />
            <div className="text-2xs text-fg-faint">{sourceTypeMeta(related.source.source_type).label}</div>
          </div>
        </div>
        <KeyValue
          className="mt-3"
          items={[
            { label: "At ingest", value: <TrustBadge level={trustThen} /> },
            { label: "Now", value: <span className="inline-flex items-center gap-1.5"><TrustBadge level={trustNow} />{trustNow !== trustThen && <span className="text-2xs text-fg-faint">reclassified since</span>}</span> },
          ]}
        />
      </Section>

      <Section title="Collection & time">
        <KeyValue
          items={[
            { label: "Collected via", value: <Mono>{fields.collected_via ?? "—"}</Mono> },
            { label: "Received", value: <span>{formatDateTime(timestamps.received_at)} <Badge tone="ok">authoritative</Badge></span> },
            { label: "Reported", value: <span>{formatDateTime(timestamps.collected_at)} <Badge tone="neutral">client</Badge></span> },
          ]}
        />
        <p className="mt-2 text-2xs text-fg-faint">{describeSkew(timestamps.skew_seconds)}. {timestamps.explanation}</p>
      </Section>

      <Section title="Related">
        <KeyValue
          items={[
            { label: "Agent", value: <EntityLink type="agent" id={related.agent.id} label={related.agent.name} /> },
            { label: "Session", value: <EntityLink type="session" id={related.session.id} label={related.session.external_session_id} /> },
            ...(related.tool_invocation
              ? [{ label: "Tool call", value: <EntityLink type="tool_invocation" id={related.tool_invocation.id} label={related.tool_invocation.tool_name} sessionId={related.session.id} /> }]
              : []),
            {
              label: "Explore",
              value: (
                <Link to={`/context?item=${encodeURIComponent(fields.context_item_id ?? "")}`} className="text-accent hover:text-accent-strong hover:underline">
                  Open in Context Explorer
                </Link>
              ),
            },
          ]}
        />
        <h3 className="label-caps mb-2 mt-4">Findings</h3>
        <FindingList findings={related.findings} />
      </Section>

      <Section title="Signature">
        {receipt.signature ? (
          <div className="flex items-start gap-1">
            <Mono className="min-w-0 break-all">{receipt.signature}</Mono>
            <CopyButton size="xs" value={receipt.signature} label="Copy signature" />
          </div>
        ) : (
          <p className="text-xs text-fg-muted">No signature was recorded.</p>
        )}
        <p className="mt-2 text-2xs text-fg-faint">Only this ContextOS server can verify it (keyed HMAC, not a public-key signature).</p>
      </Section>
    </aside>
  );
}
