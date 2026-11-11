import { useRef, type KeyboardEvent } from "react";
import { Bot, FlaskConical, ListChecks, Microscope, RefreshCcw, Search, ShieldCheck, Wrench, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/format";
import type { ModeInfo, PromptMode } from "./types";

const MODE_ICONS: Record<PromptMode, LucideIcon> = {
  investigate_only: Search,
  root_cause_analysis: Microscope,
  implementation_plan: ListChecks,
  implement_fix: Wrench,
  security_harden: ShieldCheck,
  refactor: RefreshCcw,
  test_and_verify: FlaskConical,
  full_autonomous_remediation: Bot,
};

/** Whether a mode lets the agent modify files, in words. */
export function ModeAccess({ mayModify, className }: { mayModify: boolean; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 text-2xs", mayModify ? "text-warn" : "text-trust-trusted", className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", mayModify ? "bg-warn" : "bg-trust-trusted")} aria-hidden />
      {mayModify ? "May modify files" : "Read-only"}
    </span>
  );
}

/** The eight prompt modes as a radio group of cards (arrow keys move the selection). */
export function ModeCards({ modes, value, onChange, disabled }: { modes: ModeInfo[]; value: PromptMode; onChange: (mode: PromptMode) => void; disabled?: boolean }) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const current = Math.max(0, modes.findIndex((m) => m.key === value));

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const cols = 2;
    let next: number | undefined;
    if (e.key === "ArrowRight") next = (index + 1) % modes.length;
    else if (e.key === "ArrowLeft") next = (index - 1 + modes.length) % modes.length;
    else if (e.key === "ArrowDown") next = Math.min(modes.length - 1, index + cols);
    else if (e.key === "ArrowUp") next = Math.max(0, index - cols);
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = modes.length - 1;
    if (next === undefined) return;
    e.preventDefault();
    refs.current[next]?.focus();
    onChange(modes[next].key);
  };

  return (
    <div role="radiogroup" aria-label="Prompt mode" className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
      {modes.map((mode, i) => {
        const Icon = MODE_ICONS[mode.key] ?? Wrench;
        const selected = mode.key === value;
        return (
          <button
            key={mode.key}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={selected}
            disabled={disabled}
            tabIndex={i === current ? 0 : -1}
            onClick={() => onChange(mode.key)}
            onKeyDown={(e) => onKeyDown(e, i)}
            title={mode.deliverable}
            className={cn(
              "flex min-w-0 flex-col items-start gap-1 rounded-md border px-2.5 py-2 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-60",
              selected ? "border-accent/60 bg-accent/[0.07] shadow-[inset_0_0_0_1px_rgb(var(--accent)/0.35)]" : "border-border hover:border-border-strong hover:bg-surface-2",
            )}
          >
            <span className="flex w-full items-center gap-1.5">
              <Icon className={cn("h-3.5 w-3.5 shrink-0", selected ? "text-accent" : "text-fg-muted")} aria-hidden />
              <span className="truncate text-[13px] font-medium text-fg">{mode.label}</span>
            </span>
            <span className="line-clamp-2 text-2xs leading-snug text-fg-muted">{mode.description}</span>
            <ModeAccess mayModify={mode.may_modify_files} />
          </button>
        );
      })}
    </div>
  );
}
