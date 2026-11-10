/** Small form controls used by the policy editor: a switch, a chip list input and an enum picker. */
import { useState, type KeyboardEvent } from "react";
import * as RadixSwitch from "@radix-ui/react-switch";
import { X } from "lucide-react";
import { cn } from "@/lib/format";

export function Switch({
  checked,
  onCheckedChange,
  label,
  disabled,
  className,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  /** Accessible name, e.g. "Enable Block credential exfiltration". */
  label: string;
  disabled?: boolean;
  className?: string;
}) {
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
        className,
      )}
    >
      <RadixSwitch.Thumb className={cn("block h-3 w-3 rounded-full bg-fg shadow transition-transform", checked ? "translate-x-[13px]" : "translate-x-[1px]")} />
    </RadixSwitch.Root>
  );
}

/** Editable list of short strings shown as chips. Enter or comma adds; Backspace on empty removes. */
export function ChipListInput({
  values,
  onChange,
  placeholder,
  label,
  mono = false,
  disabled,
  id,
}: {
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  label: string;
  mono?: boolean;
  disabled?: boolean;
  id?: string;
}) {
  const [text, setText] = useState("");
  const commit = () => {
    const parts = text
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    if (parts.length) onChange([...values, ...parts.filter((p) => !values.includes(p))]);
    setText("");
  };
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      commit();
    } else if (e.key === "Backspace" && text === "" && values.length) {
      onChange(values.slice(0, -1));
    }
  };
  return (
    <div
      className={cn(
        "flex min-h-8 w-full flex-wrap items-center gap-1 rounded border border-border-strong bg-surface-2 px-1.5 py-1 focus-within:border-accent/60",
        disabled && "opacity-60",
      )}
    >
      {values.map((v) => (
        <span key={v} className={cn("inline-flex h-5 max-w-full items-center gap-1 rounded border border-border-strong bg-surface-3 pl-1.5 pr-0.5 text-2xs text-fg", mono && "font-mono")}>
          <span className="truncate">{v}</span>
          {!disabled && (
            <button type="button" onClick={() => onChange(values.filter((x) => x !== v))} className="rounded p-0.5 text-fg-faint hover:text-fg" aria-label={`Remove ${v}`}>
              <X className="h-3 w-3" aria-hidden />
            </button>
          )}
        </span>
      ))}
      <input
        id={id}
        value={text}
        disabled={disabled}
        aria-label={label}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={onKeyDown}
        onBlur={commit}
        placeholder={values.length ? "" : placeholder}
        className={cn("h-6 min-w-[120px] flex-1 bg-transparent px-1 text-[13px] text-fg placeholder:text-fg-faint focus:outline-none", mono && "font-mono text-xs")}
      />
    </div>
  );
}

/** Toggle chips for picking several values of an enum (keyboard: Tab + Space). */
export function EnumMultiSelect({
  options,
  values,
  onChange,
  label,
  disabled,
}: {
  options: string[];
  values: string[];
  onChange: (values: string[]) => void;
  label: string;
  disabled?: boolean;
}) {
  const folded = new Set(values.map((v) => v.toLowerCase()));
  const unknown = values.filter((v) => !options.some((o) => o.toLowerCase() === v.toLowerCase()));
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {options.map((option) => {
        const on = folded.has(option.toLowerCase());
        return (
          <button
            key={option}
            type="button"
            role="checkbox"
            aria-checked={on}
            disabled={disabled}
            onClick={() => onChange(on ? values.filter((v) => v.toLowerCase() !== option.toLowerCase()) : [...values, option])}
            className={cn(
              "h-6 rounded border px-1.5 font-mono text-2xs transition-colors disabled:cursor-not-allowed",
              on ? "border-accent/70 bg-accent/20 text-fg" : "border-border text-fg-faint hover:border-border-strong hover:text-fg-muted",
            )}
          >
            {option}
          </button>
        );
      })}
      {unknown.map((v) => (
        <button
          key={v}
          type="button"
          disabled={disabled}
          onClick={() => onChange(values.filter((x) => x !== v))}
          className="inline-flex h-6 items-center gap-1 rounded border border-danger/40 px-1.5 font-mono text-2xs text-danger hover:bg-danger/10"
          title="Not an allowed value for this field. Click to remove."
          aria-label={`Remove invalid value ${v}`}
        >
          {v}
          <X className="h-3 w-3" aria-hidden />
        </button>
      ))}
    </div>
  );
}
