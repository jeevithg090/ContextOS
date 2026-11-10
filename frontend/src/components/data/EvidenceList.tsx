import type { ReactNode } from "react";
import { cn } from "@/lib/format";
import { EntityLink } from "./EntityLink";
import { RedactedText } from "./Redacted";
import { entityTypeLabel } from "./entityRoutes";

/** Shape of SecurityFinding.evidence items written by the detection/risk engines. */
export interface EvidenceItem {
  type: string;
  id?: string | null;
  /** Redacted excerpt of the content that triggered the finding. */
  excerpt?: string | null;
  /** Plain-language explanation of why this item counts as evidence. */
  detail?: string | null;
  /** Lets tool-call / decision evidence link into its session. */
  session_id?: string | null;
  label?: string | null;
}

export interface EvidenceListProps {
  /** Raw evidence array from the API; malformed entries are skipped rather than crashing. */
  evidence: unknown[] | null | undefined;
  /** Session the evidence belongs to, used when an item has no session_id of its own. */
  sessionId?: string | null;
  emptyLabel?: ReactNode;
  className?: string;
}

function toEvidence(raw: unknown): EvidenceItem | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.type !== "string" || !r.type) return null;
  const str = (v: unknown) => (typeof v === "string" && v ? v : null);
  return { type: r.type, id: str(r.id), excerpt: str(r.excerpt), detail: str(r.detail), session_id: str(r.session_id), label: str(r.label) };
}

/** Evidence behind a finding: the linked record, the redacted excerpt and why it matters. */
export function EvidenceList({ evidence, sessionId, emptyLabel = "No evidence was recorded for this finding.", className }: EvidenceListProps) {
  const items = (evidence ?? []).map(toEvidence).filter((e): e is EvidenceItem => e !== null);
  if (items.length === 0) return <p className={cn("text-xs text-fg-muted", className)}>{emptyLabel}</p>;

  return (
    <ol className={cn("space-y-3", className)} aria-label="Evidence">
      {items.map((item, i) => (
        <li key={`${item.type}:${item.id ?? i}`} className="rounded-md border border-border bg-surface-2/40 p-3">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
            <span className="num text-2xs text-fg-faint">#{i + 1}</span>
            <span className="label-caps">{entityTypeLabel(item.type)}</span>
            {item.id && <EntityLink type={item.type} id={item.id} label={item.label} sessionId={item.session_id ?? sessionId} />}
          </div>
          {item.excerpt && (
            <blockquote className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded border-l-2 border-border-strong bg-surface-2 px-3 py-2 font-mono text-xs leading-5 text-fg">
              <RedactedText text={item.excerpt} />
            </blockquote>
          )}
          {item.detail && <p className="mt-2 text-xs text-fg-muted">{item.detail}</p>}
        </li>
      ))}
    </ol>
  );
}
