import type { ReactNode } from "react";
import { ChevronRight, Lightbulb } from "lucide-react";
import { Badge, ErrorState, Mono, Skeleton } from "@/components/ui";
import { EntityLink, ScoreRing, Section } from "@/components/data";
import { TONE_CLASSES, type Tone } from "@/lib/domain";
import { cn, formatDateTime, timeAgo } from "@/lib/format";
import { useAgentPosture } from "../api";
import { integrationLabel, toolCategoryLabel } from "../meta";
import type { PostureDimension, PostureEvidence } from "../types";

function ratioTone(score: number, max: number): Tone {
  const r = max > 0 ? score / max : 1;
  if (r >= 0.9) return "ok";
  if (r >= 0.6) return "medium";
  return "high";
}

function EvidenceRef({ ev }: { ev: PostureEvidence }): ReactNode {
  switch (ev.type) {
    case "policy":
      return <EntityLink type="policy" id={ev.id} label={ev.detail.split(":")[0]} />;
    case "finding":
      return <EntityLink type="finding" id={ev.id} />;
    case "tool_category":
      return <Badge>{toolCategoryLabel(ev.id)}</Badge>;
    case "tool":
      return <Mono className="text-fg">{ev.id}</Mono>;
    case "integration":
      return <span className="text-fg">{integrationLabel(ev.id)}</span>;
    default:
      return null;
  }
}

function Dimension({ d }: { d: PostureDimension }) {
  const tone = ratioTone(d.score, d.max_score);
  const pct = d.max_score > 0 ? Math.round((d.score / d.max_score) * 100) : 100;
  const notAssessed = d.explanation.startsWith("Not assessed yet");
  return (
    <li className="py-2.5">
      <details className="group">
        <summary className="flex cursor-pointer list-none items-start gap-3 rounded focus-visible:outline-offset-2 [&::-webkit-details-marker]:hidden">
          <ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint transition-transform group-open:rotate-90" aria-hidden />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-3">
              <span className="text-[13px] font-medium text-fg">{d.label}</span>
              {notAssessed && <Badge>Not assessed yet</Badge>}
              <span className="ml-auto flex items-center gap-2">
                <span className="hidden h-1.5 w-24 overflow-hidden rounded-full bg-surface-3 sm:block" aria-hidden>
                  <span className={cn("block h-full rounded-full", TONE_CLASSES[tone].dot)} style={{ width: `${pct}%` }} />
                </span>
                <span className={cn("num w-12 text-right font-mono text-xs", TONE_CLASSES[tone].text)}>
                  {d.score}/{d.max_score}
                </span>
              </span>
            </div>
            <p className="mt-0.5 text-xs text-fg-muted">{d.explanation}</p>
          </div>
        </summary>
        <div className="ml-6 mt-2 space-y-2">
          {d.recommendation && (
            <p className="flex gap-2 rounded border border-border bg-surface-2/60 px-3 py-2 text-xs text-fg">
              <Lightbulb className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />
              {d.recommendation}
            </p>
          )}
          {d.evidence.length > 0 ? (
            <ul className="space-y-1" aria-label={`Evidence for ${d.label}`}>
              {d.evidence.map((ev, i) => (
                <li key={`${ev.type}:${ev.id}:${i}`} className="flex flex-wrap items-center gap-2 text-xs">
                  <EvidenceRef ev={ev} />
                  <span className="text-fg-muted">{ev.type === "policy" ? ev.detail.split(":").slice(1).join(":").trim() : ev.detail}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-fg-faint">No individual records contributed to this dimension.</p>
          )}
        </div>
      </details>
    </li>
  );
}

/** Explainable posture: score ring, the engine's summary and every dimension with evidence and a fix hint. */
export function PosturePanel({ agentId }: { agentId: string }) {
  const posture = useAgentPosture(agentId);
  const p = posture.data;
  return (
    <Section
      title="Security posture"
      description="Computed now from this agent's declared and observed tools, your policies and trust rules, and its recorded activity. Higher is better."
      actions={p && <time dateTime={p.computed_at} title={formatDateTime(p.computed_at)} className="text-2xs text-fg-faint">Computed {timeAgo(p.computed_at)}</time>}
    >
      {posture.isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      ) : posture.error || !p ? (
        <ErrorState error={posture.error} onRetry={() => posture.refetch()} />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-5">
            <ScoreRing score={p.score} grade={p.grade} label={`Posture of this agent: ${p.score} of 100`} />
            <div className="min-w-0 flex-1 space-y-2">
              <p className="text-[13px] text-fg">{p.summary}</p>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-2xs text-fg-muted">
                <span>
                  <span className="num text-fg">{p.basis.enabled_policy_count}</span> enabled policies
                </span>
                <span>
                  <span className="num text-fg">{p.basis.trust_rule_count}</span> trust rules
                </span>
                <span>
                  <span className="num text-fg">{p.basis.observed_tool_count}</span> observed / <span className="num text-fg">{p.basis.declared_tool_count}</span> declared tools
                </span>
                <span>
                  <span className="num text-fg">{p.basis.sessions_with_trifecta}</span> of <span className="num text-fg">{p.basis.total_sessions}</span> sessions with all trifecta conditions
                </span>
              </div>
            </div>
          </div>
          <ul className="mt-4 divide-y divide-border/70 border-t border-border/70" aria-label="Posture dimensions">
            {p.dimensions.map((d) => (
              <Dimension key={d.key} d={d} />
            ))}
          </ul>
        </>
      )}
    </Section>
  );
}
