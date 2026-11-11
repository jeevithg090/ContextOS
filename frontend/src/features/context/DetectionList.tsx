/** Detection-rule hits recorded on a context item, each with its plain-language explanation. */
import { ShieldCheck } from "lucide-react";
import { Badge, SeverityBadge } from "@/components/ui";
import { EntityLink, RedactedText } from "@/components/data";
import { FINDING_CATEGORY_LABELS, humanize } from "@/lib/domain";
import { cn } from "@/lib/format";
import { techniqueLabel } from "./meta";
import type { DetectionDetail, FindingRef } from "./types";

export function DetectionList({ detection, className }: { detection: DetectionDetail; className?: string }) {
  if (detection.hits.length === 0) {
    return (
      <div className={cn("flex items-center gap-2 rounded-md border border-border bg-surface-2/40 px-3 py-2.5 text-xs text-fg-muted", className)}>
        <ShieldCheck className="h-3.5 w-3.5 text-ok" aria-hidden />
        No detection rule matched this content. That lowers, but does not rule out, the chance it contains manipulative instructions.
      </div>
    );
  }
  return (
    <div className={cn("space-y-2", className)}>
      {detection.findings_suppressed_reason && <p className="text-xs text-fg-muted">{detection.findings_suppressed_reason}</p>}
      <ol className="space-y-2" aria-label="Detection hits">
        {detection.hits.map((hit) => (
          <li key={hit.rule_id} className="rounded-md border border-border bg-surface-2/40 p-3">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <SeverityBadge severity={hit.severity} />
              <span className="text-[13px] font-medium text-fg">{hit.title}</span>
              <span className="font-mono text-2xs text-fg-faint">{hit.rule_id}</span>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-2xs text-fg-muted">
              <Badge tone="neutral">{FINDING_CATEGORY_LABELS[hit.category] ?? humanize(hit.category)}</Badge>
              <Badge tone={hit.technique === "plain" ? "neutral" : "warn"} title="How the text was revealed to the detector">
                {techniqueLabel(hit.technique)}
              </Badge>
              <span className="num">confidence {Math.round(hit.confidence * 100)}%</span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-fg-muted">{hit.explanation}</p>
            {hit.excerpt && (
              <blockquote className="mt-2 whitespace-pre-wrap break-words rounded border-l-2 border-sev-high/50 bg-surface px-2.5 py-1.5 font-mono text-2xs leading-5 text-fg">
                <RedactedText text={hit.excerpt} />
              </blockquote>
            )}
            {hit.finding_id && (
              <div className="mt-2 text-xs">
                <EntityLink type="finding" id={hit.finding_id} label="Open the finding" />
              </div>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function FindingList({ findings, emptyLabel = "No findings were raised from this content." }: { findings: FindingRef[]; emptyLabel?: string }) {
  if (findings.length === 0) return <p className="text-xs text-fg-muted">{emptyLabel}</p>;
  return (
    <ul className="divide-y divide-border/70" aria-label="Findings">
      {findings.map((f) => (
        <li key={f.id} className="flex items-center gap-2 py-2 first:pt-0 last:pb-0">
          <SeverityBadge severity={f.severity} />
          <div className="min-w-0 flex-1">
            <EntityLink type="finding" id={f.id} label={f.title} showIcon={false} className="text-[13px]" />
            <div className="text-2xs text-fg-faint">
              {FINDING_CATEGORY_LABELS[f.category] ?? humanize(f.category)} · {humanize(f.status)}
              {f.incident_id && (
                <>
                  {" · "}
                  <EntityLink type="incident" id={f.incident_id} label="incident" showIcon={false} />
                </>
              )}
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}
