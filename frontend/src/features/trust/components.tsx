/** Small Trust Centre building blocks: capability chips and picker, level distribution bar, check
 * result icons, reason lists and a switch. */
import * as RadixSwitch from "@radix-ui/react-switch";
import { AlertTriangle, CheckCircle2, CircleHelp, XCircle } from "lucide-react";
import { Badge } from "@/components/ui";
import { TONE_CLASSES, TRUST_LEVELS, TRUST_META, trustTone, type TrustLevel } from "@/lib/domain";
import { cn, formatNumber } from "@/lib/format";
import { CAPABILITY_META, CHECK_RESULT_META, allowedCapabilities, capabilityAllowed, checkLabel, defaultCapabilities } from "./meta";
import type { AppliesTo, Capability, Check, CheckResult } from "./types";

const CORE: Capability[] = ["read", "instruct", "execute"];

/** Granted capabilities stand out; the core three are always listed so "cannot instruct" is visible. */
export function CapabilityChips({ capabilities, className, wrap = false }: { capabilities: Capability[] | string[]; className?: string; wrap?: boolean }) {
  const granted = new Set(capabilities as string[]);
  const shown = [...CORE, ...(["credential_access", "send"] as Capability[]).filter((c) => granted.has(c))];
  const summary = shown.map((c) => `${granted.has(c) ? "can" : "cannot"} ${CAPABILITY_META[c].label.toLowerCase()}`).join(", ");
  return (
    <span className={cn("inline-flex items-center gap-1", wrap ? "flex-wrap" : "flex-nowrap whitespace-nowrap", className)} aria-label={summary} title={summary}>
      {shown.map((c) =>
        granted.has(c) ? (
          <Badge key={c} tone={c === "read" || c === "send" ? "neutral" : "accent"}>
            {CAPABILITY_META[c].label}
          </Badge>
        ) : (
          <span key={c} aria-hidden className="inline-flex h-5 items-center rounded border border-dashed border-border px-1.5 text-2xs text-fg-faint line-through decoration-fg-faint/60">
            {CAPABILITY_META[c].label}
          </span>
        ),
      )}
    </span>
  );
}

/** Checkbox list of capabilities; options a level cannot grant are disabled with the reason. */
export function CapabilityPicker({
  level,
  appliesTo,
  value,
  onChange,
  disabled,
}: {
  level: TrustLevel;
  appliesTo: AppliesTo;
  value: Capability[];
  onChange: (caps: Capability[]) => void;
  disabled?: boolean;
}) {
  const toggle = (cap: Capability, on: boolean) => onChange(on ? Array.from(new Set([...value, cap])) : value.filter((c) => c !== cap));
  const noneChosen = !value.some((c) => capabilityAllowed(level, c));
  const defaults = defaultCapabilities(level, appliesTo);
  return (
    <div className="space-y-1.5">
      <fieldset className="grid gap-1.5 sm:grid-cols-2" disabled={disabled}>
        <legend className="sr-only">Capabilities</legend>
        {allowedCapabilities(appliesTo).map((cap) => {
          const allowed = capabilityAllowed(level, cap);
          const checked = value.includes(cap);
          return (
            <label
              key={cap}
              className={cn(
                "flex cursor-pointer items-start gap-2 rounded border border-border px-2.5 py-2 text-[13px]",
                checked && allowed && "border-accent/40 bg-accent/[0.06]",
                (!allowed || disabled) && "cursor-not-allowed opacity-55",
              )}
            >
              <input
                type="checkbox"
                className="mt-0.5 h-3.5 w-3.5 accent-[rgb(var(--accent))]"
                checked={checked && allowed}
                disabled={!allowed || disabled}
                onChange={(e) => toggle(cap, e.target.checked)}
              />
              <span className="min-w-0">
                <span className="block font-medium text-fg">{CAPABILITY_META[cap].label}</span>
                <span className="block text-2xs text-fg-muted">
                  {allowed ? CAPABILITY_META[cap].description : level === "BLOCKED" ? "BLOCKED grants nothing." : cap === "send" ? "Only TRUSTED or APPROVED destinations." : `${TRUST_META[level].label} content is data only.`}
                </span>
              </span>
            </label>
          );
        })}
      </fieldset>
      {noneChosen && defaults.length > 0 && (
        <p className="text-2xs text-fg-faint" role="note">
          Nothing selected: the {TRUST_META[level].label} defaults apply ({defaults.map((c) => CAPABILITY_META[c].label).join(", ")}).
        </p>
      )}
    </div>
  );
}

/** Stacked bar of how many records sit at each trust level, with a clickable legend. */
export function LevelDistribution({
  byLevel,
  total,
  label,
  onSelect,
}: {
  byLevel: Partial<Record<TrustLevel, number>>;
  total: number;
  label: string;
  onSelect?: (level: TrustLevel) => void;
}) {
  return (
    <div>
      <div className="flex h-2 w-full overflow-hidden rounded-full bg-surface-3" role="img" aria-label={`${label}: ${TRUST_LEVELS.map((l) => `${byLevel[l] ?? 0} ${TRUST_META[l].label}`).join(", ")}`}>
        {total > 0 &&
          TRUST_LEVELS.map((level) => {
            const n = byLevel[level] ?? 0;
            if (!n) return null;
            return <span key={level} className={cn("h-full", TONE_CLASSES[trustTone(level)].dot)} style={{ width: `${(n / total) * 100}%` }} title={`${TRUST_META[level].label}: ${n}`} />;
          })}
      </div>
      <ul className="mt-2.5 grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3">
        {TRUST_LEVELS.map((level) => {
          const n = byLevel[level] ?? 0;
          const content = (
            <>
              <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", TONE_CLASSES[trustTone(level)].dot)} aria-hidden />
              <span className="truncate text-fg-muted">{TRUST_META[level].label}</span>
              <span className={cn("num ml-auto font-medium", n ? "text-fg" : "text-fg-faint")}>{formatNumber(n)}</span>
            </>
          );
          return (
            <li key={level}>
              {onSelect && n > 0 ? (
                <button type="button" onClick={() => onSelect(level)} className="flex w-full items-center gap-1.5 rounded px-1 py-0.5 text-left text-xs hover:bg-surface-2" aria-label={`Show ${n} ${TRUST_META[level].label} ${label.toLowerCase()}`}>
                  {content}
                </button>
              ) : (
                <div className="flex items-center gap-1.5 px-1 py-0.5 text-xs">{content}</div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function CheckIcon({ result, className }: { result: CheckResult | string; className?: string }) {
  const cls = cn("h-4 w-4 shrink-0", className);
  if (result === "pass") return <CheckCircle2 className={cn(cls, "text-ok")} aria-label="Pass" />;
  if (result === "warn") return <AlertTriangle className={cn(cls, "text-warn")} aria-label="Warning" />;
  if (result === "fail") return <XCircle className={cn(cls, "text-danger")} aria-label="Fail" />;
  return <CircleHelp className={cn(cls, "text-fg-faint")} aria-label="Not checked" />;
}

/** Destination checks with pass/warn/fail icons, failures first. */
export function CheckList({ checks }: { checks: Check[] }) {
  if (!checks.length) return <p className="text-xs text-fg-muted">No checks were recorded.</p>;
  const order: Record<string, number> = { fail: 0, warn: 1, unknown: 2, pass: 3 };
  const sorted = [...checks].sort((a, b) => (order[a.result] ?? 2) - (order[b.result] ?? 2));
  return (
    <ul className="divide-y divide-border/70 rounded-md border border-border">
      {sorted.map((c, i) => (
        <li key={`${c.check}-${i}`} className="flex items-start gap-2.5 px-3 py-2">
          <CheckIcon result={c.result} className="mt-0.5" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-x-2 text-[13px] font-medium text-fg">
              {checkLabel(c.check)}
              <span className={cn("text-2xs font-normal", TONE_CLASSES[CHECK_RESULT_META[c.result as CheckResult]?.tone ?? "neutral"].text)}>
                {CHECK_RESULT_META[c.result as CheckResult]?.label ?? c.result}
              </span>
            </div>
            <p className="mt-0.5 text-xs text-fg-muted">{c.detail}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}

/** The engine's explanation, one numbered line per decision step. */
export function ReasonList({ reasons, className }: { reasons: string[]; className?: string }) {
  if (!reasons.length) return <p className="text-xs text-fg-muted">No explanation was recorded.</p>;
  return (
    <ol className={cn("space-y-1.5", className)}>
      {reasons.map((r, i) => (
        <li key={i} className="flex gap-2 text-[13px] leading-relaxed text-fg">
          <span className="num mt-px w-4 shrink-0 text-right text-2xs text-fg-faint">{i + 1}</span>
          <span className="min-w-0">{r}</span>
        </li>
      ))}
    </ol>
  );
}

export function Switch({ checked, onCheckedChange, label, disabled }: { checked: boolean; onCheckedChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <RadixSwitch.Root
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      aria-label={label}
      title={label}
      onClick={(e) => e.stopPropagation()}
      className={cn(
        "relative inline-flex h-4 w-7 shrink-0 items-center rounded-full border transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        checked ? "border-accent/60 bg-accent/80" : "border-border-strong bg-surface-3",
      )}
    >
      <RadixSwitch.Thumb className={cn("block h-3 w-3 rounded-full bg-fg shadow transition-transform", checked ? "translate-x-[13px]" : "translate-x-[1px]")} />
    </RadixSwitch.Root>
  );
}

/** The contextual-trust reminder shown wherever someone grants capabilities. */
export function ContextualTrustNote({ className }: { className?: string }) {
  return (
    <p className={cn("rounded-md border border-border bg-surface-2/60 px-3 py-2 text-xs leading-relaxed text-fg-muted", className)}>
      Trust is contextual: <span className="text-fg">approved for reading does not mean trusted to give instructions.</span> Grant
      “Instruct” or “Execute” only to content your organisation writes and controls. Findings recorded for a source still keep it
      Suspicious, whatever you choose here.
    </p>
  );
}
