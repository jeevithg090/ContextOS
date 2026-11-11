/** Board filter bar (search, assignee incl. "me", label, priority, type). State lives in the URL. */
import type { ReactNode } from "react";
import { FilterBar, FilterSelect, SearchInput } from "@/components/data";
import { PRIORITY_META, TASK_TYPE_LABELS } from "../analytics/taskMeta";
import { TASK_PRIORITIES, TASK_TYPES, type LabelWithUsage, type TaskPriority, type TaskType } from "../types";
import { hasActiveFilters, type BoardFilterState } from "./boardMeta";

export interface BoardFiltersProps {
  value: BoardFilterState;
  onChange: (patch: Partial<BoardFilterState>) => void;
  onClear: () => void;
  members: Array<{ user_id: string; name: string }>;
  labels: LabelWithUsage[];
  actions?: ReactNode;
}

export function BoardFilters({ value, onChange, onClear, members, labels, actions }: BoardFiltersProps) {
  return (
    <FilterBar aria-label="Board filters" onClear={onClear} canClear={hasActiveFilters(value)} actions={actions}>
      <SearchInput value={value.q} onChange={(q) => onChange({ q })} placeholder="Search title or key…" label="Search tasks on this board" className="max-w-[240px]" />
      <FilterSelect
        label="Assignee"
        value={value.assignee}
        onChange={(assignee) => onChange({ assignee })}
        allLabel="Anyone"
        options={[
          { value: "me", label: "Me" },
          { value: "none", label: "Unassigned" },
          ...members.map((m) => ({ value: m.user_id, label: m.name })),
        ]}
      />
      <FilterSelect label="Label" value={value.label} onChange={(label) => onChange({ label })} options={labels.map((l) => ({ value: l.id, label: l.name }))} />
      <FilterSelect
        label="Priority"
        value={value.priority}
        onChange={(priority) => onChange({ priority: priority as TaskPriority | "" })}
        options={TASK_PRIORITIES.map((p) => ({ value: p, label: PRIORITY_META[p].label }))}
      />
      <FilterSelect
        label="Type"
        value={value.type}
        onChange={(type) => onChange({ type: type as TaskType | "" })}
        options={TASK_TYPES.map((t) => ({ value: t, label: TASK_TYPE_LABELS[t] }))}
      />
    </FilterBar>
  );
}
