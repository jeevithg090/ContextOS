import { useState, type KeyboardEvent } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/format";

export interface ChipsInputProps {
  id?: string;
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  /** Lower-cases entries (labels are compared case-insensitively by policies). */
  lowercase?: boolean;
  maxItems?: number;
  maxLength?: number;
  disabled?: boolean;
  /** Entries that cannot be added (e.g. reserved labels), with the reason shown to the user. */
  reserved?: Record<string, string>;
  "aria-describedby"?: string;
}

/** Free-text list editor: Enter or comma adds an entry, Backspace on an empty field removes the last. */
export function ChipsInput({ id, value, onChange, placeholder, lowercase = false, maxItems = 30, maxLength = 64, disabled, reserved = {}, "aria-describedby": describedBy }: ChipsInputProps) {
  const [text, setText] = useState("");
  const [problem, setProblem] = useState<string | null>(null);

  const commit = (raw: string) => {
    const parts = raw.split(",").map((p) => p.trim().replace(/\s+/g, " ")).filter(Boolean);
    if (parts.length === 0) return;
    const next = [...value];
    for (const part of parts) {
      const entry = lowercase ? part.toLowerCase() : part;
      if (reserved[entry]) {
        setProblem(reserved[entry]);
        continue;
      }
      if (entry.length > maxLength) {
        setProblem(`Entries must be at most ${maxLength} characters.`);
        continue;
      }
      if (next.length >= maxItems) {
        setProblem(`At most ${maxItems} entries.`);
        break;
      }
      if (!next.includes(entry)) next.push(entry);
    }
    onChange(next);
    setText("");
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      commit(text);
    } else if (e.key === "Backspace" && !text && value.length > 0) {
      onChange(value.slice(0, -1));
    }
  };

  return (
    <div>
      <div
        className={cn(
          "flex min-h-8 w-full flex-wrap items-center gap-1 rounded border border-border-strong bg-surface-2 px-1.5 py-1 focus-within:border-accent/60",
          disabled && "opacity-60",
        )}
      >
        {value.map((entry) => (
          <span key={entry} className="inline-flex h-5 items-center gap-1 rounded border border-border-strong bg-surface-3/60 pl-1.5 pr-0.5 font-mono text-2xs text-fg">
            {entry}
            {!disabled && (
              <button type="button" onClick={() => onChange(value.filter((v) => v !== entry))} className="rounded p-0.5 text-fg-faint hover:bg-surface hover:text-fg" aria-label={`Remove ${entry}`}>
                <X className="h-3 w-3" aria-hidden />
              </button>
            )}
          </span>
        ))}
        <input
          id={id}
          value={text}
          disabled={disabled}
          onChange={(e) => {
            setText(e.target.value);
            setProblem(null);
          }}
          onKeyDown={onKeyDown}
          onBlur={() => commit(text)}
          placeholder={value.length === 0 ? placeholder : undefined}
          aria-describedby={describedBy}
          className="h-6 min-w-[120px] flex-1 bg-transparent px-1 text-[13px] text-fg placeholder:text-fg-faint focus:outline-none"
        />
      </div>
      {problem && (
        <p role="alert" className="mt-1 text-2xs text-danger">
          {problem}
        </p>
      )}
    </div>
  );
}
