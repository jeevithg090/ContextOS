import { useEffect, useRef, useState } from "react";
import { Search, X } from "lucide-react";
import { Kbd } from "@/components/ui";
import { cn } from "@/lib/format";
import { useDebounce } from "@/hooks/useDebounce";

export interface SearchInputProps {
  /** Current committed query (e.g. from URL state). External changes are reflected in the box. */
  value: string;
  /** Called with the trimmed-of-nothing query after the user pauses typing, and immediately on clear. */
  onChange: (value: string) => void;
  placeholder?: string;
  debounceMs?: number;
  /** Focus with the "/" key from anywhere on the page (ignored while typing in another field). */
  shortcut?: boolean;
  label?: string;
  className?: string;
  autoFocus?: boolean;
}

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable;
}

export function SearchInput({
  value,
  onChange,
  placeholder = "Search…",
  debounceMs = 250,
  shortcut = true,
  label = "Search",
  className,
  autoFocus,
}: SearchInputProps) {
  const [text, setText] = useState(value);
  const [focused, setFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const lastEmitted = useRef(value);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  const debounced = useDebounce(text, debounceMs);

  // Reflect external resets (e.g. "Clear filters") without echoing them back.
  useEffect(() => {
    if (value !== lastEmitted.current) {
      lastEmitted.current = value;
      setText(value);
    }
  }, [value]);

  useEffect(() => {
    if (debounced !== lastEmitted.current) {
      lastEmitted.current = debounced;
      onChangeRef.current(debounced);
    }
  }, [debounced]);

  useEffect(() => {
    if (!shortcut) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target)) return;
      e.preventDefault();
      inputRef.current?.focus();
      inputRef.current?.select();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [shortcut]);

  const clear = () => {
    setText("");
    if (lastEmitted.current !== "") {
      lastEmitted.current = "";
      onChangeRef.current("");
    }
    inputRef.current?.focus();
  };

  return (
    <div className={cn("relative w-full max-w-xs", className)}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-faint" aria-hidden />
      <input
        ref={inputRef}
        type="search"
        aria-label={label}
        value={text}
        placeholder={placeholder}
        autoFocus={autoFocus}
        onChange={(e) => setText(e.target.value)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            if (text) {
              e.preventDefault();
              clear();
            } else {
              inputRef.current?.blur();
            }
          } else if (e.key === "Enter" && text !== lastEmitted.current) {
            lastEmitted.current = text;
            onChangeRef.current(text);
          }
        }}
        className="h-7 w-full rounded border border-border-strong bg-surface-2 pl-8 pr-8 text-xs text-fg placeholder:text-fg-faint focus:border-accent/60 focus:outline-none [&::-webkit-search-cancel-button]:hidden"
      />
      <div className="absolute right-1.5 top-1/2 flex -translate-y-1/2 items-center">
        {text ? (
          <button type="button" onClick={clear} aria-label="Clear search" className="inline-flex h-5 w-5 items-center justify-center rounded text-fg-faint hover:bg-surface-3 hover:text-fg">
            <X className="h-3 w-3" aria-hidden />
          </button>
        ) : (
          shortcut && !focused && <span aria-hidden><Kbd>/</Kbd></span>
        )}
      </div>
    </div>
  );
}
