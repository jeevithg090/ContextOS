/**
 * The exact fields the receipt signature covers, each with a plain-language note on what it means.
 * Values are shown as recorded; when the signature is invalid they are flagged as unverified.
 */
import type { ReactNode } from "react";
import { Mono, SeverityBadge, TrustBadge } from "@/components/ui";
import { CopyButton, EntityLink } from "@/components/data";
import { cn, formatDateTime, formatNumber } from "@/lib/format";
import { sensitivityMeta, sourceTypeMeta } from "../meta";
import type { ContextReceipt } from "../types";

interface Row {
  field: string;
  label: string;
  value: ReactNode;
  note: string;
}

export function ReceiptFieldsTable({ receipt }: { receipt: ContextReceipt }) {
  const r = receipt.receipt;
  const sessionId = r.session_id;
  const id = (type: string, value: string | null, label?: string | null) => (value ? <EntityLink type={type} id={value} label={label} sessionId={sessionId} /> : <span className="text-fg-faint">—</span>);
  const rows: Row[] = [
    { field: "context_item_id", label: "Item", value: <Mono>{r.context_item_id ?? "—"}</Mono>, note: "The context item this receipt describes." },
    { field: "source.type", label: "Source type", value: sourceTypeMeta(r.source.type).label, note: "What kind of source the content came from." },
    { field: "source.identifier", label: "Source", value: <span className="break-all font-mono text-xs">{r.source.identifier ?? "—"}</span>, note: "As reported by the integration, or derived by ContextOS from the tool call." },
    { field: "source.trust_level_at_ingest", label: "Trust at ingest", value: <TrustBadge level={r.source.trust_level_at_ingest} />, note: "Classification when the content arrived; later reclassification does not change it." },
    { field: "agent_id", label: "Agent", value: id("agent", r.agent_id, receipt.related.agent.name), note: "The agent the content was delivered to." },
    { field: "session_id", label: "Session", value: id("session", r.session_id, receipt.related.session.external_session_id), note: "The agent session it entered." },
    { field: "event_id", label: "Event", value: <Mono>{r.event_id ?? "—"}</Mono>, note: "The ingested event that carried the content." },
    { field: "collected_via", label: "Collected via", value: <Mono>{r.collected_via ?? "—"}</Mono>, note: "The hook or callback that observed it." },
    { field: "collected_at", label: "Collected (client)", value: formatDateTime(r.collected_at), note: "Reported by the integration — not trusted." },
    { field: "received_at", label: "Received (server)", value: formatDateTime(r.received_at), note: "ContextOS’s own clock — authoritative." },
    {
      field: "content_hash",
      label: "SHA-256",
      value: r.content_hash ? (
        <span className="inline-flex min-w-0 items-center gap-1">
          <Mono className="break-all">{r.content_hash}</Mono>
          <CopyButton size="xs" value={r.content_hash} label="Copy content hash" />
        </span>
      ) : (
        "—"
      ),
      note: "Hash of the raw content before redaction. Hash your copy of the content to compare.",
    },
    { field: "content_length", label: "Length", value: `${formatNumber(r.content_length)} characters`, note: "Length of the raw content." },
    { field: "content_type", label: "Content type", value: <Mono>{r.content_type ?? "—"}</Mono>, note: "Declared media type." },
    { field: "sensitivity", label: "Sensitivity", value: sensitivityMeta(r.sensitivity).label, note: "ContextOS’s sensitivity classification at ingest." },
    { field: "contains_secrets", label: "Contains secrets", value: r.contains_secrets ? "Yes" : "No", note: "Whether a credential was detected (and redacted before storage)." },
    { field: "secret_fingerprint_count", label: "Secret fingerprints", value: formatNumber(r.secret_fingerprint_count), note: "Count only — fingerprint values are never shown." },
    {
      field: "detection",
      label: "Detection",
      value: r.detection.rule_ids.length ? (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={r.detection.max_severity} />
          <span className="num text-xs">score {r.detection.score.toFixed(2)}</span>
          <Mono>{r.detection.rule_ids.join(", ")}</Mono>
        </span>
      ) : (
        "No rule matched"
      ),
      note: "Rules that matched at ingest, the worst severity and the aggregate score (0 – 1).",
    },
    { field: "tool_invocation_id", label: "Returned by", value: id("tool_invocation", r.tool_invocation_id, receipt.related.tool_invocation?.tool_name), note: "The tool call whose result this was, if any." },
    { field: "receipt_version", label: "Receipt version", value: <Mono>{r.receipt_version}</Mono>, note: "Version of the canonical receipt format." },
  ];
  const unverified = receipt.verification.status !== "valid";

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-[13px]" aria-label="Signed receipt fields">
        <thead className="border-b border-border text-2xs uppercase tracking-[0.06em] text-fg-faint">
          <tr>
            <th scope="col" className="px-4 py-2 font-medium">Field</th>
            <th scope="col" className="px-4 py-2 font-medium">Value{unverified && " (unverified)"}</th>
            <th scope="col" className="hidden px-4 py-2 font-medium md:table-cell">Meaning</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.field} className="border-b border-border/70 align-top last:border-0">
              <th scope="row" className="whitespace-nowrap px-4 py-2 text-left font-normal">
                <div className="text-fg-muted">{row.label}</div>
                <div className="font-mono text-2xs text-fg-faint">{row.field}</div>
              </th>
              <td className={cn("min-w-0 px-4 py-2 text-fg", unverified && "text-fg-muted")}>{row.value}</td>
              <td className="hidden px-4 py-2 text-xs text-fg-muted md:table-cell">{row.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="px-4 py-2 text-2xs text-fg-faint">
        Canonical form (receipt version {receipt.receipt.receipt_version}): these keys as JSON with sorted keys and compact separators. The signature is computed over that text, so changing any value invalidates it.
      </p>
    </div>
  );
}
