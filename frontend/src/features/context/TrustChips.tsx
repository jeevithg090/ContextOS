/**
 * Trust distribution of the items matching the current filters, as toggle chips. Counts come from
 * GET /context/facets, where each facet ignores its own filter — so selecting "Suspicious" narrows the
 * list but still shows how many items sit at every other level.
 */
import type { ReactNode } from "react";
import { KeyRound, ShieldAlert } from "lucide-react";
import { Skeleton } from "@/components/ui";
import { TONE_CLASSES, TRUST_LEVELS, TRUST_META, type Tone } from "@/lib/domain";
import { cn, formatNumber } from "@/lib/format";
import type { ContextFacets } from "./types";

interface TrustChipsProps {
  facets: ContextFacets | undefined;
  loading: boolean;
  selected: string[];
  onToggle: (level: string) => void;
  onClear: () => void;
  detectionsOnly: boolean;
  onToggleDetections: () => void;
  secretsOnly: boolean;
  onToggleSecrets: () => void;
}

export function TrustChips({ facets, loading, selected, onToggle, onClear, detectionsOnly, onToggleDetections, secretsOnly, onToggleSecrets }: TrustChipsProps) {
  if (loading && !facets) {
    return (
      <div className="flex flex-wrap gap-2 pb-3" aria-hidden>
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-7 w-24" />
        ))}
      </div>
    );
  }
  const counts = new Map((facets?.by_trust_level ?? []).map((f) => [f.value, f.count]));
  const all = Array.from(counts.values()).reduce((a, b) => a + b, 0);

  return (
    <div className="flex flex-wrap items-center gap-1.5 pb-3" role="group" aria-label="Filter by trust at ingest">
      <span className="mr-1 text-xs text-fg-faint">Trust at ingest</span>
      <Chip label="All" count={all} pressed={selected.length === 0} onClick={onClear} />
      {TRUST_LEVELS.map((level) => {
        const count = counts.get(level) ?? 0;
        const pressed = selected.includes(level);
        return (
          <Chip
            key={level}
            label={TRUST_META[level].label}
            title={TRUST_META[level].description}
            tone={TRUST_META[level].tone}
            count={count}
            pressed={pressed}
            disabled={count === 0 && !pressed}
            onClick={() => onToggle(level)}
          />
        );
      })}
      <span className="mx-1.5 h-4 w-px bg-border" aria-hidden />
      <Chip
        label="With detections"
        icon={<ShieldAlert className="h-3.5 w-3.5" aria-hidden />}
        title="Items where a prompt-injection, credential-seeking or exfiltration rule matched"
        tone="high"
        count={facets?.with_detections ?? 0}
        pressed={detectionsOnly}
        disabled={!detectionsOnly && !facets?.with_detections}
        onClick={onToggleDetections}
      />
      <Chip
        label="Contains secrets"
        icon={<KeyRound className="h-3.5 w-3.5" aria-hidden />}
        title="Items where a credential was detected (and redacted before storage)"
        tone="medium"
        count={facets?.with_secrets ?? 0}
        pressed={secretsOnly}
        disabled={!secretsOnly && !facets?.with_secrets}
        onClick={onToggleSecrets}
      />
    </div>
  );
}

function Chip({ label, count, pressed, onClick, tone, title, disabled, icon }: { label: string; count: number; pressed: boolean; onClick: () => void; tone?: Tone; title?: string; disabled?: boolean; icon?: ReactNode }) {
  const t = tone ? TONE_CLASSES[tone] : null;
  return (
    <button
      type="button"
      aria-pressed={pressed}
      title={title}
      disabled={disabled}
      onClick={onClick}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-40",
        pressed ? cn("text-fg", t ? cn(t.bg, t.border) : "border-accent/40 bg-accent/10") : "border-border bg-surface-2/60 text-fg-muted hover:border-border-strong hover:text-fg",
      )}
    >
      {icon ? <span className={cn(t?.text)}>{icon}</span> : t && <span className={cn("h-1.5 w-1.5 rounded-full", t.dot)} aria-hidden />}
      {label}
      <span className={cn("num text-2xs", pressed ? "text-fg-muted" : "text-fg-faint")}>{formatNumber(count)}</span>
    </button>
  );
}
