import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Ban, ClipboardList, Plus } from "lucide-react";
import { DataTable, FilterBar, FilterSelect, Pagination, SearchInput, type DataTableColumn } from "@/components/data";
import { Button, Checkbox, PageHeader, SeverityBadge } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { useMembers } from "@/features/settings/api";
import { usePagination } from "@/hooks";
import { timeAgo } from "@/lib/format";
import { useBoards, useLabels, useTasks } from "./api";
import { CreateTaskDialog } from "./analytics/CreateTaskDialog";
import {
  AssigneeStack,
  DueDate,
  LabelChip,
  PRIORITY_META,
  PriorityBadge,
  STATUS_KEY_LABELS,
  TASK_TYPE_LABELS,
  VerificationBadge,
  statusKeyLabel,
  taskTypeLabel,
} from "./analytics/taskMeta";
import { oneOf, useUrlState } from "./analytics/useUrlState";
import { STATUS_KEYS, TASK_PRIORITIES, TASK_TYPES, type TaskCard, type TaskSort } from "./types";

const SORTS: Array<{ value: TaskSort; label: string }> = [
  { value: "updated", label: "Recently updated" },
  { value: "created", label: "Recently created" },
  { value: "priority", label: "Priority (highest first)" },
  { value: "due_date", label: "Due date (soonest first)" },
  { value: "key", label: "Key (newest first)" },
];
const SORT_VALUES = SORTS.map((s) => s.value);
const FILTER_KEYS = ["board_id", "type", "priority", "assignee", "label", "status", "q", "done"] as const;

/** "Find any task." — every task across boards with server-side filters, sort and paging. */
export function AllTasksPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const { get, set } = useUrlState();
  const [creating, setCreating] = useState(false);
  const boards = useBoards();
  const labels = useLabels();
  const members = useMembers();
  const pagination = usePagination(50);
  const { reset } = pagination;

  const filters = {
    board_id: get("board_id") || undefined,
    task_type: oneOf(get("type"), TASK_TYPES),
    priority: oneOf(get("priority"), TASK_PRIORITIES),
    assignee: get("assignee") || undefined,
    label: get("label") || undefined,
    status_key: oneOf(get("status"), STATUS_KEYS),
    q: get("q") || undefined,
    // Choosing the Done stage implies showing done tasks.
    include_done: get("done") === "1" || get("status") === "done",
    sort: oneOf(get("sort"), SORT_VALUES, "updated"),
  };
  const filterSignature = FILTER_KEYS.map((k) => get(k)).join("|") + get("sort");
  useEffect(() => reset(), [filterSignature, reset]);

  const query = useTasks({ ...filters, ...pagination.params });
  const boardNames = useMemo(() => new Map((boards.data?.items ?? []).map((b) => [b.id, b.name])), [boards.data]);
  const canClear = FILTER_KEYS.some((k) => get(k));

  const columns: Array<DataTableColumn<TaskCard>> = [
    { key: "key", header: "Key", width: 88, render: (t) => <span className="whitespace-nowrap font-mono text-xs text-fg-muted">{t.key}</span> },
    {
      key: "title",
      header: "Title",
      render: (t) => (
        <div className="min-w-0 max-w-[420px]">
          <div className="flex min-w-0 items-center gap-2">
            <span className="truncate text-fg">{t.title}</span>
            {t.severity && <SeverityBadge severity={t.severity} />}
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
            <span className="text-2xs text-fg-muted">{taskTypeLabel(t.task_type)}</span>
            {t.labels.map((l) => (
              <LabelChip key={l.id} label={l} />
            ))}
            {t.subtasks_total > 0 && (
              <span className="text-2xs text-fg-muted">
                {t.subtasks_done}/{t.subtasks_total} subtasks
              </span>
            )}
            {t.verification_status !== "unverified" && <VerificationBadge status={t.verification_status} />}
            {t.blocked_by_open > 0 && (
              <span className="inline-flex items-center gap-1 text-2xs text-warn">
                <Ban className="h-3 w-3" aria-hidden />
                Blocked by {t.blocked_by_open}
              </span>
            )}
          </div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status · board",
      render: (t) => (
        <div className="flex flex-col">
          <span className="whitespace-nowrap text-xs text-fg" title={statusKeyLabel(t.status_key)}>
            {t.column_name}
            {t.archived_at && <span className="text-fg-faint"> · archived</span>}
          </span>
          <span className="whitespace-nowrap text-2xs text-fg-faint">{boardNames.get(t.board_id) ?? ""}</span>
        </div>
      ),
    },
    { key: "priority", header: "Priority", render: (t) => <PriorityBadge priority={t.priority} /> },
    { key: "assignees", header: "Assignees", hideBelow: "md", render: (t) => <AssigneeStack assignees={t.assignees} /> },
    { key: "due", header: "Due", hideBelow: "sm", render: (t) => <DueDate due={t.due_date} done={t.is_done} overdue={t.is_overdue} /> },
    { key: "updated", header: "Updated", hideBelow: "lg", render: (t) => <span className="whitespace-nowrap text-xs text-fg-muted">{timeAgo(t.updated_at)}</span> },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Engineering Workspace"
        title="All Tasks"
        description="Find any task across every board. Filters are kept in the address bar, so a filtered view can be shared."
        actions={
          can("write") ? (
            <Button variant="primary" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setCreating(true)}>
              Create task
            </Button>
          ) : undefined
        }
      />
      <div className="panel">
        <FilterBar
          className="border-b border-border px-4 pt-3"
          canClear={canClear}
          onClear={() => set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])))}
          actions={<FilterSelect label="Sort" value={filters.sort} onChange={(v) => set({ sort: v === "updated" ? null : v })} allLabel={null} options={SORTS} />}
        >
          <SearchInput value={get("q")} onChange={(v) => set({ q: v })} placeholder="Title, description or CTX-12…" label="Search tasks" className="w-60" />
          <FilterSelect
            label="Board"
            value={get("board_id")}
            onChange={(v) => set({ board_id: v })}
            options={(boards.data?.items ?? []).map((b) => ({ value: b.id, label: b.name }))}
          />
          <FilterSelect label="Status" value={get("status")} onChange={(v) => set({ status: v })} options={STATUS_KEYS.map((s) => ({ value: s, label: STATUS_KEY_LABELS[s] }))} />
          <FilterSelect label="Type" value={get("type")} onChange={(v) => set({ type: v })} options={TASK_TYPES.map((t) => ({ value: t, label: TASK_TYPE_LABELS[t] }))} />
          <FilterSelect label="Priority" value={get("priority")} onChange={(v) => set({ priority: v })} options={TASK_PRIORITIES.map((p) => ({ value: p, label: PRIORITY_META[p].label }))} />
          <FilterSelect
            label="Assignee"
            value={get("assignee")}
            onChange={(v) => set({ assignee: v })}
            allLabel="Anyone"
            options={[{ value: "me", label: "Me" }, ...(members.data?.items ?? []).filter((m) => m.is_active).map((m) => ({ value: m.user_id, label: m.name }))]}
          />
          <FilterSelect
            label="Label"
            value={get("label")}
            onChange={(v) => set({ label: v })}
            options={(labels.data ?? []).map((l) => ({ value: l.id, label: l.name, count: l.task_count }))}
          />
          <Checkbox
            label="Include done"
            checked={filters.include_done}
            disabled={filters.status_key === "done"}
            onChange={(v) => set({ done: v ? "1" : null })}
          />
        </FilterBar>
        <DataTable
          aria-label="Tasks"
          columns={columns}
          rows={query.data?.items}
          rowKey={(t) => t.id}
          onRowClick={(t) => navigate(`/work/tasks/${encodeURIComponent(t.id)}`)}
          loading={query.isLoading}
          error={query.error}
          onRetry={() => void query.refetch()}
          manualSort
          dense
          rowClassName={(t) => (query.isPlaceholderData ? "opacity-60" : t.is_done ? "text-fg-muted" : undefined)}
          empty={
            canClear
              ? { title: "No tasks match these filters", description: filters.include_done ? "Try clearing a filter." : "Done tasks are hidden — tick “Include done” or clear a filter." }
              : {
                  icon: <ClipboardList className="h-4 w-4" />,
                  title: "No open tasks yet",
                  description: "Create a task here, or turn a security finding into a remediation task from the Remediation view.",
                  action: can("write") ? <Button size="sm" variant="primary" onClick={() => setCreating(true)}>Create task</Button> : undefined,
                }
          }
        />
        {query.data && (
          <div className="border-t border-border px-3">
            <Pagination
              total={query.data.total}
              limit={pagination.limit}
              offset={pagination.offset}
              onChange={pagination.setOffset}
              onLimitChange={pagination.setLimit}
              pageSizeOptions={[25, 50, 100, 200]}
              itemLabel="tasks"
            />
          </div>
        )}
      </div>
      <CreateTaskDialog open={creating} onOpenChange={setCreating} boardId={filters.board_id} />
    </>
  );
}
