import { useRef, type KeyboardEvent, type ReactNode } from "react";
import { cn } from "@/lib/format";

export interface SegmentOption<T extends string> {
  value: T;
  label: ReactNode;
  count?: number;
  icon?: ReactNode;
  disabled?: boolean;
}

export interface SegmentedControlProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  options: Array<SegmentOption<T>>;
  "aria-label": string;
  size?: "sm" | "md";
  className?: string;
}

/** Mutually exclusive view switch (radio group semantics, arrow-key navigation). */
export function SegmentedControl<T extends string>({ value, onChange, options, "aria-label": ariaLabel, size = "sm", className }: SegmentedControlProps<T>) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const enabled = options.map((o, i) => (o.disabled ? -1 : i)).filter((i) => i >= 0);
  const currentIndex = options.findIndex((o) => o.value === value);
  const focusIndex = currentIndex >= 0 && !options[currentIndex].disabled ? currentIndex : (enabled[0] ?? -1);

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (enabled.length === 0) return;
    const pos = enabled.indexOf(index);
    let next: number | undefined;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") next = enabled[(pos + 1) % enabled.length];
    else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = enabled[(pos - 1 + enabled.length) % enabled.length];
    else if (e.key === "Home") next = enabled[0];
    else if (e.key === "End") next = enabled[enabled.length - 1];
    if (next === undefined) return;
    e.preventDefault();
    refs.current[next]?.focus();
    onChange(options[next].value);
  };

  return (
    <div role="radiogroup" aria-label={ariaLabel} className={cn("inline-flex items-center gap-0.5 rounded-md border border-border bg-surface-2 p-0.5", className)}>
      {options.map((option, i) => {
        const selected = option.value === value;
        return (
          <button
            key={option.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={selected}
            disabled={option.disabled}
            tabIndex={i === focusIndex ? 0 : -1}
            onClick={() => onChange(option.value)}
            onKeyDown={(e) => onKeyDown(e, i)}
            className={cn(
              "inline-flex items-center gap-1.5 whitespace-nowrap rounded transition-colors disabled:cursor-not-allowed disabled:opacity-40",
              size === "sm" ? "h-6 px-2 text-xs" : "h-7 px-2.5 text-[13px]",
              selected ? "bg-surface-3 text-fg shadow-[inset_0_0_0_1px_rgb(var(--border-strong))]" : "text-fg-muted hover:text-fg",
            )}
          >
            {option.icon && <span className="[&>svg]:h-3.5 [&>svg]:w-3.5" aria-hidden>{option.icon}</span>}
            {option.label}
            {option.count !== undefined && <span className={cn("num rounded px-1 text-2xs", selected ? "bg-surface-2 text-fg-muted" : "text-fg-faint")}>{option.count}</span>}
          </button>
        );
      })}
    </div>
  );
}
