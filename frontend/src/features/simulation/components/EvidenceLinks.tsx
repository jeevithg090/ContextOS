import { EntityLink, entityTypeLabel } from "@/components/data";
import { cn } from "@/lib/format";
import { evidenceEntityType } from "../logic";
import type { ResultEvidence } from "../types";

/**
 * Records a check or step points at (findings, policy decisions, tool calls, context items,
 * approvals, incidents …). Tool calls and policy decisions open inside the run's session.
 */
export function EvidenceLinks({ evidence, sessionId, className }: { evidence: ResultEvidence[] | null | undefined; sessionId: string | null; className?: string }) {
  const items = (Array.isArray(evidence) ? evidence : []).filter((e) => e && typeof e.type === "string" && typeof e.id === "string" && e.id);
  if (items.length === 0) return null;
  return (
    <ul className={cn("flex flex-wrap items-center gap-x-3 gap-y-1 text-xs", className)} aria-label="Evidence">
      {items.map((e) => (
        <li key={`${e.type}:${e.id}`} className="inline-flex min-w-0 items-center gap-1">
          <span className="text-fg-faint">{entityTypeLabel(evidenceEntityType(e.type))}</span>
          <EntityLink type={evidenceEntityType(e.type)} id={e.id} sessionId={sessionId} showIcon={false} />
        </li>
      ))}
    </ul>
  );
}
