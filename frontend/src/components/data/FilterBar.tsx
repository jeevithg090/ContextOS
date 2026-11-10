import { useId, type ReactNode } from "react";
import { X } from "lucide-react";
import { Select } from "@/components/ui";
import { cn } from "@/lib/format";

export interface FilterBarProps {
  children: ReactNode;
  /** Right-aligned content (result count, view toggles, primary action). */
  actions?: ReactNode;
  /** When provided and `canClear` is true, shows a "Clear filters" control. */
  onClear?: () => void;
  canClear?: boolean;
  className?: string;
  "aria-label"?: string;
}

/** Horizontal row of filters above a list. Wraps on narrow screens. */
export function FilterBar({ children, actions, onClear, canClear = false, className, "aria-label": ariaLabel = "Filters" }: FilterBarProps) {
  return (
    <div role="group" aria-label={ariaLabel} className={cn("flex flex-wrap items-center gap-2 pb-3", className)}>
      {children}
      {onClear && canClear && (
        <button type="button" onClick={onClear} className="inline-flex h-7 items-center gap-1 rounded px-2 text-xs text-fg-muted hover:bg-surface-2 hover:text-fg">
          <X className="h-3.5 w-3.5" aria-hidden />
          Clear filters
        </button>
      )}
      {actions && <div className="ml-auto flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export interface FilterOption {
  value: string;
  label: string;
  count?: number;
}

export interface FilterSelectProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: FilterOption[];
  /** Label of the "no filter" option (value ""). Pass null to omit it. */
  allLabel?: string | null;
  disabled?: boolean;
  className?: string;
}

/** Compact labelled native select — keyboard and screen-reader friendly by default. */
export function FilterSelect({ label, value, onChange, options, allLabel = "All", disabled, className }: FilterSelectProps) {
  const id = useId();
  const active = value !== "";
  return (
    <div className={cn("inline-flex items-center gap-1.5", className)}>
      <label htmlFor={id} className="text-xs text-fg-faint">
        {label}
      </label>
      <Select
        id={id}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        className={cn("!h-7 !w-auto min-w-[96px] !text-xs", active && "border-accent/50 text-fg")}
      >
        {allLabel !== null && <option value="">{allLabel}</option>}
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.count !== undefined ? `${o.label} (${o.count})` : o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}
