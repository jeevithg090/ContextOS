/**
 * Small controls shared by the AI screens: the persistent privacy note, labelled switch, sentence
 * chips input, section-kind badge and legend, and the token budget meter.
 */
import { useId, useState, type KeyboardEvent, type ReactNode } from "react";
import * as RadixSwitch from "@radix-ui/react-switch";
import { ShieldCheck, X } from "lucide-react";
import { Badge } from "@/components/ui";
import { TONE_CLASSES } from "@/lib/domain";
import { cn } from "@/lib/format";
import { budgetLevel, formatCount, kindMeta, SECTION_KIND_META, SECTION_KIND_ORDER, TOKEN_ESTIMATE_NOTE } from "./meta";
import type { SectionKind } from "./types";

export const PRIVACY_HEADLINE = "Nothing is sent to an external AI provider. You copy the prompt into your coding agent.";

/** Server detail without the sentence the headline already states. */
function extraDetail(detail: string | null | undefined): string {
  return (detail ?? "")
    .split(/(?<=\.)\s+/)
    .filter((sentence) => !/external AI provider/i.test(sentence))
    .join(" ")
    .trim();
}

/** Persistent statement of where prompts are generated and where they go. */
export function PrivacyNote({ detail: rawDetail, className }: { detail?: string | null; className?: string }) {
  const detail = extraDetail(rawDetail);
  return (
    <div role="note" aria-label="Privacy" className={cn("flex items-start gap-2.5 rounded-md border border-trust-trusted/30 bg-trust-trusted/[0.06] px-3 py-2", className)}>
      <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-trust-trusted" aria-hidden />
      <div className="min-w-0 text-xs">
        <p className="font-medium text-fg">{PRIVACY_HEADLINE}</p>
        {detail && <p className="mt-0.5 text-fg-muted">{detail}</p>}
      </div>
    </div>
  );
}

/** Switch with a visible label and description; the whole row is clickable. */
export function LabelledSwitch({
  label,
  description,
  checked,
  onCheckedChange,
  disabled,
  disabledReason,
}: {
  label: string;
  description?: ReactNode;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  /** Shown instead of the description when disabled (e.g. "This mode is read-only"). */
  disabledReason?: string;
}) {
  const id = useId();
  const descId = `${id}-desc`;
  return (
    <div className={cn("flex items-start justify-between gap-3", disabled && "opacity-70")}>
      <div className="min-w-0">
        <label htmlFor={id} className={cn("text-[13px] text-fg", disabled ? "cursor-not-allowed" : "cursor-pointer")}>
          {label}
        </label>
        {(disabled && disabledReason) || description ? (
          <p id={descId} className={cn("mt-0.5 text-2xs", disabled && disabledReason ? "text-warn" : "text-fg-faint")}>
            {disabled && disabledReason ? disabledReason : description}
          </p>
        ) : null}
      </div>
      <RadixSwitch.Root
        id={id}
        checked={checked}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        aria-describedby={descId}
        className={cn(
          "relative mt-0.5 inline-flex h-4 w-7 shrink-0 items-center rounded-full border transition-colors disabled:cursor-not-allowed",
          checked ? "border-accent/60 bg-accent/80" : "border-border-strong bg-surface-3",
        )}
      >
        <RadixSwitch.Thumb className={cn("block h-3 w-3 rounded-full bg-fg shadow transition-transform", checked ? "translate-x-[13px]" : "translate-x-[1px]")} />
      </RadixSwitch.Root>
    </div>
  );
}

/**
 * List of sentences (constraints, file paths) shown as removable chips. Enter adds the typed text;
 * Backspace in an empty box removes the last chip. Duplicates are ignored.
 */
export function ChipsInput({
  values,
  onChange,
  label,
  placeholder,
  maxItems,
  maxLength,
  mono = false,
  disabled,
  hint,
}: {
  values: string[];
  onChange: (values: string[]) => void;
  label: string;
  placeholder?: string;
  maxItems?: number;
  maxLength?: number;
  mono?: boolean;
  disabled?: boolean;
  hint?: ReactNode;
}) {
  const id = useId();
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const full = maxItems !== undefined && values.length >= maxItems;

  const add = () => {
    const value = text.trim();
    if (!value) return;
    if (maxLength !== undefined && value.length > maxLength) return setError(`Each entry can be at most ${maxLength} characters.`);
    if (full) return setError(`At most ${maxItems} entries.`);
    if (values.some((v) => v.toLowerCase() === value.toLowerCase())) return setError("That entry is already in the list.");
    onChange([...values, value]);
    setText("");
    setError(null);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      add();
    } else if (e.key === "Backspace" && !text && values.length > 0) {
      onChange(values.slice(0, -1));
    }
  };

  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-xs font-medium text-fg-muted">
        {label}
      </label>
      {values.length > 0 && (
        <ul className="flex flex-wrap gap-1.5" aria-label={`${label} list`}>
          {values.map((value, index) => (
            <li key={`${value}-${index}`} className="inline-flex max-w-full items-start gap-1 rounded border border-border-strong bg-surface-2 py-0.5 pl-2 pr-0.5 text-xs text-fg">
              <span className={cn("min-w-0 break-words", mono && "font-mono text-2xs")}>{value}</span>
              <button
                type="button"
                disabled={disabled}
                onClick={() => onChange(values.filter((_, i) => i !== index))}
                aria-label={`Remove “${value}”`}
                className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded text-fg-faint hover:bg-surface-3 hover:text-fg disabled:opacity-50"
              >
                <X className="h-3 w-3" aria-hidden />
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="flex gap-1.5">
        <input
          id={id}
          value={text}
          disabled={disabled || full}
          placeholder={full ? `Limit of ${maxItems} reached` : placeholder}
          onChange={(e) => {
            setText(e.target.value);
            setError(null);
          }}
          onKeyDown={onKeyDown}
          className={cn(
            "h-8 w-full rounded border border-border-strong bg-surface-2 px-2.5 text-[13px] text-fg placeholder:text-fg-faint focus:border-accent/60 focus:outline-none disabled:opacity-60",
            mono && "font-mono text-xs",
          )}
        />
        <button
          type="button"
          onClick={add}
          disabled={disabled || full || !text.trim()}
          className="h-8 shrink-0 rounded border border-border-strong px-2.5 text-xs text-fg hover:bg-surface-2 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Add
        </button>
      </div>
      {error ? <p className="text-2xs text-danger">{error}</p> : hint ? <p className="text-2xs text-fg-faint">{hint}</p> : null}
    </div>
  );
}

/** Badge for a section kind or pack-item category (fact / evidence / assumption / hypothesis …). */
export function KindBadge({ kind, className }: { kind: string; className?: string }) {
  const meta = kindMeta(kind);
  return (
    <Badge tone={meta.tone} dot className={className} title={meta.description}>
      {meta.label}
    </Badge>
  );
}

/** Explains the kind colours once per screen, so facts and hypotheses are never confused. */
export function KindLegend({ kinds = SECTION_KIND_ORDER, className }: { kinds?: SectionKind[]; className?: string }) {
  return (
    <dl className={cn("grid gap-x-4 gap-y-1.5 text-2xs sm:grid-cols-2 xl:grid-cols-3", className)} aria-label="What the section labels mean">
      {kinds.map((kind) => {
        const meta = SECTION_KIND_META[kind];
        return (
          <div key={kind} className="flex min-w-0 items-start gap-1.5">
            <dt className="shrink-0">
              <span className={cn("mt-1 inline-block h-1.5 w-1.5 rounded-full", TONE_CLASSES[meta.tone].dot)} aria-hidden />
              <span className={cn("ml-1.5 font-medium", TONE_CLASSES[meta.tone].text)}>{meta.label}</span>
            </dt>
            <dd className="min-w-0 text-fg-muted">{meta.description}</dd>
          </div>
        );
      })}
    </dl>
  );
}

/** Estimated pack tokens against the profile's budget. */
export function TokenBudgetMeter({ estimate, budget, label = "Context pack budget", compact = false }: { estimate: number; budget: number; label?: string; compact?: boolean }) {
  const level = budgetLevel(estimate, budget);
  const ratio = budget > 0 ? estimate / budget : 0;
  const pct = Math.round(ratio * 100);
  const tone = level === "over" ? "danger" : level === "near" ? "warn" : "ok";
  const text = `~${formatCount(estimate)} of ${formatCount(budget)} tokens`;
  return (
    <div className="min-w-0" title={TOKEN_ESTIMATE_NOTE}>
      <div className="flex items-baseline justify-between gap-2 text-2xs">
        <span className="text-fg-faint">{label}</span>
        <span className={cn("num", level === "ok" ? "text-fg-muted" : TONE_CLASSES[tone].text)}>
          {text} · {pct}%{level === "over" ? " — over budget" : ""}
        </span>
      </div>
      <div
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={budget}
        aria-valuenow={Math.min(estimate, budget)}
        aria-valuetext={`${text}, ${pct}% of budget${level === "over" ? ", over budget" : ""}`}
        className={cn("mt-1 overflow-hidden rounded-full bg-surface-3", compact ? "h-1" : "h-1.5")}
      >
        <div className={cn("h-full rounded-full transition-[width]", TONE_CLASSES[tone].dot)} style={{ width: `${Math.min(100, Math.max(ratio > 0 ? 2 : 0, pct))}%` }} />
      </div>
    </div>
  );
}
