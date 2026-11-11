import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Hammer, Package, X } from "lucide-react";
import { DataTable, Pagination, type DataTableColumn } from "@/components/data";
import { Button, PageHeader, useToast } from "@/components/ui";
import { usePagination } from "@/hooks";
import { timeAgo } from "@/lib/format";
import { useTask } from "../api";
import { useUrlState } from "../analytics/useUrlState";
import { useAiCatalogue, useContextPacks } from "./api";
import { BuildPackDialog } from "./BuildPackDialog";
import { PrivacyNote, TokenBudgetMeter } from "./controls";
import { useCanWrite } from "./hooks";
import { PackDrawer } from "./PackDrawer";
import type { ContextPackSummary } from "./types";

/** "What project context goes to a coding agent?" — every stored context pack, inspectable. */
export function ContextPacksPage() {
  const toast = useToast();
  const canWrite = useCanWrite();
  const catalogue = useAiCatalogue();
  const { get, set } = useUrlState();
  const taskFilter = get("task");
  const open = get("pack");
  const [building, setBuilding] = useState(false);
  const pagination = usePagination(25);
  const { reset } = pagination;
  useEffect(() => reset(), [taskFilter, reset]);
  const packs = useContextPacks({ taskId: taskFilter || undefined, ...pagination.params });
  const filterTask = useTask(taskFilter || null);

  const columns: Array<DataTableColumn<ContextPackSummary>> = [
    {
      key: "task",
      header: "Task",
      render: (p) =>
        p.task_id ? (
          <button
            type="button"
            className="font-mono text-xs text-fg-muted hover:text-accent hover:underline"
            title="Show only this task's packs"
            onClick={(e) => {
              e.stopPropagation();
              set({ task: p.task_id, pack: null });
            }}
          >
            {p.task_key}
          </button>
        ) : (
          <span className="text-xs text-fg-faint">Task deleted</span>
        ),
    },
    { key: "profile", header: "Profile", render: (p) => <span className="whitespace-nowrap text-[13px] text-fg">{p.profile_label}</span> },
    {
      key: "items",
      header: "Items",
      render: (p) => (
        <span className="num whitespace-nowrap text-xs text-fg" title={`${p.counts.included} included of ${p.counts.total} considered`}>
          {p.counts.included}
          <span className="text-fg-faint">/{p.counts.total} included</span>
        </span>
      ),
    },
    {
      key: "verification",
      header: "Verification",
      hideBelow: "md",
      render: (p) => (
        <div className="flex flex-col gap-0.5 whitespace-nowrap text-2xs">
          <span className="text-trust-trusted">{p.counts.verified} verified</span>
          {p.counts.unverified > 0 && <span className="text-trust-unknown">{p.counts.unverified} unverified</span>}
          {p.counts.excluded_sensitive > 0 && <span className="text-danger">{p.counts.excluded_sensitive} sensitive excluded</span>}
          {!p.repository_verified && (
            <span className="inline-flex items-center gap-1 text-warn" title="No repository root configured (or not readable) when this pack was built: file references are unverified">
              <AlertTriangle className="h-3 w-3" aria-hidden />
              No repository root
            </span>
          )}
        </div>
      ),
    },
    {
      key: "tokens",
      header: "Tokens",
      hideBelow: "sm",
      width: 220,
      render: (p) => (
        <div className="w-[200px]">
          <TokenBudgetMeter estimate={p.token_estimate} budget={p.token_budget} label="Budget" compact />
        </div>
      ),
    },
    { key: "built", header: "Built", hideBelow: "lg", render: (p) => <span className="whitespace-nowrap text-xs text-fg-muted" title={p.created_at}>{timeAgo(p.created_at)}</span> },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Engineering Workspace"
        title="Context Packs"
        description="The project files and ContextOS records a fix prompt carries to a coding agent — why each was chosen, whether it was verified, and what was left out."
        actions={
          canWrite ? (
            <Button variant="primary" icon={<Hammer className="h-3.5 w-3.5" aria-hidden />} onClick={() => setBuilding(true)}>
              Build pack
            </Button>
          ) : undefined
        }
      />
      <PrivacyNote detail={`${catalogue.data?.privacy_note ?? ""} Sensitive files are never read: they are listed as excluded and their contents never enter a pack.`.trim()} className="mb-4" />
      {taskFilter && (
        <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-fg-faint">Showing packs for</span>
          <span className="inline-flex items-center gap-1.5 rounded border border-border-strong bg-surface-2 py-0.5 pl-2 pr-0.5">
            <span className="font-mono text-fg">{filterTask.data?.key ?? taskFilter}</span>
            {filterTask.data && <span className="max-w-[280px] truncate text-fg-muted">{filterTask.data.title}</span>}
            <button type="button" aria-label="Show packs for every task" onClick={() => set({ task: null })} className="rounded p-0.5 text-fg-faint hover:bg-surface-3 hover:text-fg">
              <X className="h-3 w-3" aria-hidden />
            </button>
          </span>
          {filterTask.data && (
            <Link to={`/work/fix-context/${encodeURIComponent(filterTask.data.id)}`} className="text-accent hover:underline">
              Open in Fix Context
            </Link>
          )}
        </div>
      )}
      <div className="panel">
        <DataTable
          aria-label="Context packs"
          columns={columns}
          rows={packs.data?.items}
          rowKey={(p) => p.id}
          onRowClick={(p) => set({ pack: p.id })}
          selectedKey={open || null}
          loading={packs.isLoading}
          error={packs.error}
          onRetry={() => void packs.refetch()}
          manualSort
          dense
          rowClassName={() => (packs.isPlaceholderData ? "opacity-60" : undefined)}
          empty={{
            icon: <Package className="h-4 w-4" />,
            title: taskFilter ? "No context packs for this task" : "No context packs yet",
            description: "Packs are stored when you build one here or in AI Fix Context, or when you save a generated prompt.",
            action: canWrite ? (
              <Button size="sm" variant="primary" onClick={() => setBuilding(true)}>
                Build pack
              </Button>
            ) : undefined,
          }}
        />
        {packs.data && (
          <div className="border-t border-border px-3">
            <Pagination total={packs.data.total} limit={pagination.limit} offset={pagination.offset} onChange={pagination.setOffset} onLimitChange={pagination.setLimit} itemLabel="packs" />
          </div>
        )}
      </div>

      <PackDrawer packId={open || null} onOpenChange={(o) => !o && set({ pack: null })} />
      <BuildPackDialog
        open={building}
        onOpenChange={setBuilding}
        onBuilt={(pack) => {
          toast.success(`${pack.profile_label} pack built for ${pack.task_key ?? "the task"}`, `${pack.counts.included} of ${pack.counts.total} items included.`);
          set({ pack: pack.id });
        }}
      />
    </>
  );
}
