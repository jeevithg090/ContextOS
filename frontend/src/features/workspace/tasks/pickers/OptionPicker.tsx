/**
 * Searchable popover picker (single or multiple choice) with keyboard navigation and an optional
 * "create" row. Used for assignees, labels, parent tasks and dependencies.
 */
import { useId, useMemo, useState, type ReactNode } from "react";
import * as Popover from "@radix-ui/react-popover";
import { Check, Plus, Search } from "lucide-react";
import { Spinner } from "@/components/ui";
import { cn } from "@/lib/format";

export interface PickerOption {
  value: string;
  label: string;
  hint?: string;
  icon?: ReactNode;
  disabled?: boolean;
}

export interface OptionPickerProps {
  /** A button element; becomes the popover trigger. */
  trigger: ReactNode;
  options: PickerOption[];
  selected: string[];
  multiple?: boolean;
  onSelect: (value: string) => void;
  ariaLabel: string;
  searchPlaceholder?: string;
  /** Controlled query for server-side search; without it options are filtered locally. */
  query?: string;
  onQueryChange?: (query: string) => void;
  loading?: boolean;
  emptyLabel?: string;
  /** Offer "Create …" for a query that matches no option exactly. */
  onCreate?: (query: string) => Promise<unknown>;
  createNoun?: string;
  disabled?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export function OptionPicker({
  trigger,
  options,
  selected,
  multiple = false,
  onSelect,
  ariaLabel,
  searchPlaceholder = "Search…",
  query: controlledQuery,
  onQueryChange,
  loading,
  emptyLabel = "No matches.",
  onCreate,
  createNoun = "item",
  disabled,
  onOpenChange,
}: OptionPickerProps) {
  const listId = useId();
  const [open, setOpen] = useState(false);
  const [localQuery, setLocalQuery] = useState("");
  const [active, setActive] = useState(0);
  const [creating, setCreating] = useState(false);
  const query = controlledQuery ?? localQuery;
  const setQuery = (q: string) => {
    setActive(0);
    if (onQueryChange) onQueryChange(q);
    else setLocalQuery(q);
  };

  const shown = useMemo(() => {
    if (onQueryChange) return options;
    const q = query.trim().toLowerCase();
    return q ? options.filter((o) => o.label.toLowerCase().includes(q) || o.hint?.toLowerCase().includes(q)) : options;
  }, [options, query, onQueryChange]);

  const canCreate = !!onCreate && query.trim().length > 0 && !options.some((o) => o.label.toLowerCase() === query.trim().toLowerCase());
  const rows = shown.length + (canCreate ? 1 : 0);

  const choose = async (index: number) => {
    if (index < shown.length) {
      const option = shown[index];
      if (option.disabled) return;
      onSelect(option.value);
      if (!multiple) {
        setOpen(false);
        onOpenChange?.(false);
        setQuery("");
      }
      return;
    }
    if (canCreate && onCreate && !creating) {
      setCreating(true);
      try {
        await onCreate(query.trim());
        setQuery("");
      } finally {
        setCreating(false);
      }
    }
  };

  return (
    <Popover.Root
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        onOpenChange?.(next);
        if (!next) setQuery("");
      }}
    >
      <Popover.Trigger asChild disabled={disabled}>
        {trigger}
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content align="start" sideOffset={4} className="z-50 w-[min(320px,calc(100vw-32px))] rounded-md border border-border-strong bg-surface shadow-pop animate-fade-in">
          <div className="flex items-center gap-2 border-b border-border px-2.5">
            <Search className="h-3.5 w-3.5 text-fg-faint" aria-hidden />
            <input
              autoFocus
              value={query}
              role="combobox"
              aria-label={ariaLabel}
              aria-expanded
              aria-controls={listId}
              aria-activedescendant={rows > 0 ? `${listId}-${Math.min(active, rows - 1)}` : undefined}
              placeholder={searchPlaceholder}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setActive((i) => (rows ? (i + 1) % rows : 0));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setActive((i) => (rows ? (i - 1 + rows) % rows : 0));
                } else if (e.key === "Enter") {
                  e.preventDefault();
                  if (rows > 0) void choose(Math.min(active, rows - 1));
                }
              }}
              className="h-9 w-full bg-transparent text-xs text-fg placeholder:text-fg-faint focus:outline-none"
            />
            {loading && <Spinner className="h-3.5 w-3.5" />}
          </div>
          <ul id={listId} role="listbox" aria-multiselectable={multiple || undefined} className="max-h-64 overflow-y-auto p-1">
            {shown.map((option, i) => {
              const isSelected = selected.includes(option.value);
              return (
                <li
                  key={option.value}
                  id={`${listId}-${i}`}
                  role="option"
                  aria-selected={isSelected}
                  aria-disabled={option.disabled || undefined}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => void choose(i)}
                  className={cn(
                    "flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs",
                    i === active ? "bg-surface-3 text-fg" : "text-fg-muted",
                    option.disabled && "cursor-not-allowed opacity-50",
                  )}
                >
                  <span className="flex h-3.5 w-3.5 shrink-0 items-center justify-center">{isSelected && <Check className="h-3.5 w-3.5 text-accent" aria-hidden />}</span>
                  {option.icon}
                  <span className="min-w-0 flex-1 truncate text-fg">{option.label}</span>
                  {option.hint && <span className="shrink-0 truncate text-2xs text-fg-faint">{option.hint}</span>}
                </li>
              );
            })}
            {canCreate && (
              <li
                id={`${listId}-${shown.length}`}
                role="option"
                aria-selected={false}
                onMouseEnter={() => setActive(shown.length)}
                onClick={() => void choose(shown.length)}
                className={cn("flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs text-accent", active === shown.length && "bg-surface-3")}
              >
                {creating ? <Spinner className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" aria-hidden />}
                Create {createNoun} “{query.trim()}”
              </li>
            )}
            {rows === 0 && <li className="px-2 py-3 text-center text-xs text-fg-faint">{loading ? "Searching…" : emptyLabel}</li>}
          </ul>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
