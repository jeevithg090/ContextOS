/** Small form building blocks shared by the settings tabs. */
import type { ReactNode } from "react";
import { Lock } from "lucide-react";
import { Button } from "@/components/ui";
import { cn } from "@/lib/format";

export interface ChoiceOption<T extends string> {
  value: T;
  label: ReactNode;
  description: ReactNode;
  badge?: ReactNode;
}

/** Radio group rendered as selectable cards. Native radios keep keyboard and screen-reader behaviour. */
export function ChoiceCards<T extends string>({
  name,
  legend,
  value,
  options,
  onChange,
  disabled,
  columns = 3,
}: {
  name: string;
  legend: string;
  value: T;
  options: ChoiceOption<T>[];
  onChange: (value: T) => void;
  disabled?: boolean;
  columns?: 2 | 3;
}) {
  return (
    <fieldset disabled={disabled} className="min-w-0">
      <legend className="sr-only">{legend}</legend>
      <div className={cn("grid gap-2", columns === 3 ? "sm:grid-cols-3" : "sm:grid-cols-2")}>
        {options.map((option) => {
          const checked = option.value === value;
          return (
            <label
              key={option.value}
              className={cn(
                "relative flex cursor-pointer flex-col gap-1 rounded-md border px-3 py-2.5 transition-colors",
                "has-[:focus-visible]:outline has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-accent",
                checked ? "border-accent/60 bg-accent/[0.06]" : "border-border-strong bg-surface-2/40 hover:bg-surface-2",
                disabled && "cursor-not-allowed opacity-70",
              )}
            >
              <input
                type="radio"
                name={name}
                value={option.value}
                checked={checked}
                onChange={() => onChange(option.value)}
                className="sr-only"
              />
              <span className="flex items-center gap-2">
                <span
                  aria-hidden
                  className={cn(
                    "flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full border",
                    checked ? "border-accent" : "border-border-strong",
                  )}
                >
                  {checked && <span className="h-1.5 w-1.5 rounded-full bg-accent" />}
                </span>
                <span className="text-[13px] font-medium text-fg">{option.label}</span>
                {option.badge && <span className="ml-auto">{option.badge}</span>}
              </span>
              <span className="pl-[22px] text-xs leading-relaxed text-fg-muted">
                {option.description}
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

/** One labelled setting: title + explanation on the left, control on the right (stacks on mobile). */
export function SettingRow({ title, description, htmlFor, children }: { title: string; description: ReactNode; htmlFor?: string; children: ReactNode }) {
  return (
    <div className="grid gap-3 py-4 first:pt-0 last:pb-0 md:grid-cols-[minmax(0,280px)_minmax(0,1fr)] md:gap-8">
      <div className="min-w-0">
        <label htmlFor={htmlFor} className="block text-[13px] font-medium text-fg">
          {title}
        </label>
        <div className="mt-1 text-xs leading-relaxed text-fg-muted">{description}</div>
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

/** Explains why controls are read-only for the current user. */
export function AdminOnlyNotice({ children = "Only owners and admins can change these settings." }: { children?: ReactNode }) {
  return (
    <div className="flex items-center gap-2 rounded border border-border bg-surface-2/60 px-3 py-2 text-xs text-fg-muted">
      <Lock className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
      {children}
    </div>
  );
}

/** Save / discard footer for a settings form. */
export function SaveBar({ dirty, saving, error, onReset, invalid }: { dirty: boolean; saving: boolean; error?: string | null; onReset: () => void; invalid?: boolean }) {
  return (
    <div className={cn("panel sticky bottom-3 z-10 flex flex-wrap items-center justify-end gap-3 px-4 py-2.5 transition-shadow", dirty && "shadow-pop")}>
      {error ? (
        <p role="alert" className="mr-auto text-xs text-danger">
          {error}
        </p>
      ) : (
        <p className="mr-auto text-xs text-fg-faint" aria-live="polite">
          {dirty ? "You have unsaved changes." : "All changes saved."}
        </p>
      )}
      <Button variant="ghost" size="sm" onClick={onReset} disabled={!dirty || saving}>
        Discard
      </Button>
      <Button type="submit" variant="primary" size="sm" loading={saving} disabled={!dirty || invalid}>
        Save changes
      </Button>
    </div>
  );
}
