import { useEffect } from "react";
import { Link } from "react-router-dom";
import { FileText, X } from "lucide-react";
import { DataTable, Pagination, type DataTableColumn } from "@/components/data";
import { Badge } from "@/components/ui";
import { usePagination } from "@/hooks";
import { timeAgo } from "@/lib/format";
import { useTask } from "../api";
import { useUrlState } from "../analytics/useUrlState";
import { usePrompts } from "./api";
import { formatTokens } from "./meta";
import { PromptDrawer } from "./PromptDrawer";
import type { PromptSummary } from "./types";

/** Saved prompts, newest change first; filter to one task; open one to read, copy or export it. */
export function SavedPromptsTab() {
  const { get, set } = useUrlState();
  const taskFilter = get("task");
  const open = get("prompt");
  const pagination = usePagination(25);
  const { reset } = pagination;
  useEffect(() => reset(), [taskFilter, reset]);
  const prompts = usePrompts({ taskId: taskFilter || undefined, ...pagination.params });
  const filterTask = useTask(taskFilter || null);

  const columns: Array<DataTableColumn<PromptSummary>> = [
    {
      key: "task",
      header: "Task",
      render: (p) =>
        p.task_id ? (
          <div className="min-w-0 max-w-[360px]">
            <button
              type="button"
              className="font-mono text-xs text-fg-muted hover:text-accent hover:underline"
              title="Show only this task's prompts"
              onClick={(e) => {
                e.stopPropagation();
                set({ task: p.task_id, prompt: null });
              }}
            >
              {p.task_key}
            </button>
            <div className="truncate text-[13px] text-fg">{p.task_title}</div>
          </div>
        ) : (
          <span className="text-xs text-fg-faint">Task deleted</span>
        ),
    },
    { key: "mode", header: "Mode", render: (p) => <span className="whitespace-nowrap text-xs text-fg">{p.mode_label}</span> },
    { key: "preset", header: "Agent", hideBelow: "md", render: (p) => <span className="whitespace-nowrap text-xs text-fg-muted">{p.preset_label}</span> },
    {
      key: "version",
      header: "Version",
      render: (p) => (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <span className="num text-xs text-fg">v{p.version}</span>
          {p.edited_sections.length > 0 && (
            <Badge tone="accent" title={`Edited by hand: ${p.edited_sections.join(", ")}`}>
              {p.edited_sections.length} edited
            </Badge>
          )}
        </span>
      ),
    },
    { key: "size", header: "Size", align: "right", hideBelow: "lg", render: (p) => <span className="num whitespace-nowrap text-xs text-fg-muted">{formatTokens(p.token_estimate, false)} · {p.section_count} sections</span> },
    { key: "updated", header: "Last changed", hideBelow: "sm", render: (p) => <span className="whitespace-nowrap text-xs text-fg-muted" title={p.updated_at}>{timeAgo(p.updated_at)}</span> },
  ];

  return (
    <div className="space-y-3">
      {taskFilter && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-fg-faint">Showing prompts for</span>
          <span className="inline-flex items-center gap-1.5 rounded border border-border-strong bg-surface-2 py-0.5 pl-2 pr-0.5">
            <span className="font-mono text-fg">{filterTask.data?.key ?? taskFilter}</span>
            {filterTask.data && <span className="max-w-[280px] truncate text-fg-muted">{filterTask.data.title}</span>}
            <button type="button" aria-label="Show prompts for every task" onClick={() => set({ task: null })} className="rounded p-0.5 text-fg-faint hover:bg-surface-3 hover:text-fg">
              <X className="h-3 w-3" aria-hidden />
            </button>
          </span>
          {filterTask.data && (
            <Link to={`/work/fix-context/${encodeURIComponent(filterTask.data.id)}`} className="text-accent hover:underline">
              New prompt for this task
            </Link>
          )}
        </div>
      )}
      <div className="panel">
        <DataTable
          aria-label="Saved prompts"
          columns={columns}
          rows={prompts.data?.items}
          rowKey={(p) => p.id}
          onRowClick={(p) => set({ prompt: p.id })}
          selectedKey={open || null}
          loading={prompts.isLoading}
          error={prompts.error}
          onRetry={() => void prompts.refetch()}
          manualSort
          dense
          rowClassName={() => (prompts.isPlaceholderData ? "opacity-60" : undefined)}
          empty={{
            icon: <FileText className="h-4 w-4" />,
            title: taskFilter ? "No saved prompts for this task" : "No saved prompts yet",
            description: "Generate a prompt in AI Fix Context and choose “Save to task”. Saved prompts keep your section edits, a version number and the context pack they used.",
            action: (
              <Link to={taskFilter ? `/work/fix-context/${encodeURIComponent(taskFilter)}` : "/work/fix-context"} className="inline-flex h-7 items-center rounded bg-accent px-2.5 text-xs font-medium text-accent-fg hover:bg-accent-strong">
                Open AI Fix Context
              </Link>
            ),
          }}
        />
        {prompts.data && (
          <div className="border-t border-border px-3">
            <Pagination total={prompts.data.total} limit={pagination.limit} offset={pagination.offset} onChange={pagination.setOffset} onLimitChange={pagination.setLimit} itemLabel="prompts" />
          </div>
        )}
      </div>
      <PromptDrawer promptId={open || null} onOpenChange={(o) => !o && set({ prompt: null })} />
    </div>
  );
}
