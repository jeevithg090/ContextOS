/** Pick another task by title or key (server-side search across boards). */
import { useState, type ReactNode } from "react";
import { statusKeyLabel } from "../../analytics/taskMeta";
import { useTaskSearch } from "../hooks";
import { OptionPicker } from "./OptionPicker";

export interface TaskSearchPickerProps {
  trigger: ReactNode;
  ariaLabel: string;
  /** Task ids that may not be chosen (the task itself, existing relations). */
  exclude: string[];
  onSelect: (taskId: string) => void;
  disabled?: boolean;
}

export function TaskSearchPicker({ trigger, ariaLabel, exclude, onSelect, disabled }: TaskSearchPickerProps) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const tasks = useTaskSearch(query, open);
  const options = (tasks.data?.items ?? [])
    .filter((t) => !exclude.includes(t.id))
    .map((t) => ({ value: t.id, label: `${t.key} · ${t.title}`, hint: t.is_done ? "Done" : statusKeyLabel(t.status_key) }));

  return (
    <OptionPicker
        trigger={trigger}
        ariaLabel={ariaLabel}
        searchPlaceholder="Search by title or key (CTX-12)…"
        options={options}
        selected={[]}
        onSelect={onSelect}
        query={query}
        onQueryChange={setQuery}
        loading={tasks.isFetching}
        emptyLabel={tasks.error ? "Search failed. Try again." : "No matching tasks."}
        disabled={disabled}
        onOpenChange={setOpen}
      />
  );
}
