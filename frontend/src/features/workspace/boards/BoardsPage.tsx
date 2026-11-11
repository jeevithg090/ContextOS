/**
 * Kanban boards (/work/boards) — "where is every piece of work?". Every board with its template,
 * open and total task counts, and actions to create (from a template), duplicate, archive or restore.
 */
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { KanbanSquare, LayoutGrid, List, Plus } from "lucide-react";
import { SegmentedControl } from "@/components/data";
import { Badge, Button, Checkbox, EmptyState, ErrorState, PageHeader, Skeleton, Table, TD, TH, THead, TR } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { cn, timeAgo } from "@/lib/format";
import { useBoards } from "../api";
import { useUrlState } from "../analytics/useUrlState";
import type { BoardSummary } from "../types";
import { BoardActions } from "./BoardActions";
import { NewBoardDialog } from "./NewBoardDialog";
import { templateLabel } from "./boardMeta";

type View = "grid" | "list";

function Progress({ board }: { board: BoardSummary }) {
  const done = board.task_count - board.open_task_count;
  const pct = board.task_count > 0 ? Math.round((done / board.task_count) * 100) : 0;
  return (
    <div className="flex items-center gap-2" title={`${done} of ${board.task_count} tasks in a done column`}>
      <div className="h-1 w-24 overflow-hidden rounded-full bg-surface-3" aria-hidden>
        <div className="h-full rounded-full bg-ok/80" style={{ width: `${pct}%` }} />
      </div>
      <span className="num text-2xs text-fg-muted">
        {done}/{board.task_count} done
      </span>
    </div>
  );
}

function BoardTile({ board, canWrite }: { board: BoardSummary; canWrite: boolean }) {
  const archived = board.archived_at !== null;
  return (
    <li className={cn("panel group relative flex flex-col p-4 transition-colors hover:border-border-strong", archived && "opacity-70")}>
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <Link
            to={`/work/boards/${encodeURIComponent(board.id)}`}
            className="block truncate text-[14px] font-semibold text-fg after:absolute after:inset-0 after:rounded-lg after:content-[''] hover:text-accent focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-accent"
          >
            {board.name}
          </Link>
          <div className="mt-0.5 text-2xs text-fg-faint">{templateLabel(board.template)}</div>
        </div>
        <div className="relative z-10 flex items-center gap-1">
          {board.is_default && <Badge tone="accent">Default</Badge>}
          {archived && <Badge tone="warn">Archived</Badge>}
          <BoardActions board={board} canWrite={canWrite} />
        </div>
      </div>
      <p className="mt-2 line-clamp-2 min-h-[2.5em] text-xs text-fg-muted">{board.description || "No description."}</p>
      <div className="mt-3 flex items-end justify-between gap-3 border-t border-border pt-3">
        <div>
          <div className="num text-lg font-semibold leading-none text-fg">{board.open_task_count}</div>
          <div className="mt-1 text-2xs text-fg-faint">open of {board.task_count}</div>
        </div>
        <div className="flex flex-col items-end gap-1">
          <Progress board={board} />
          <span className="text-2xs text-fg-faint">
            {board.column_count} columns · updated {timeAgo(board.updated_at)}
          </span>
        </div>
      </div>
    </li>
  );
}

function BoardsTable({ boards, canWrite }: { boards: BoardSummary[]; canWrite: boolean }) {
  const navigate = useNavigate();
  return (
    <div className="panel">
      <Table>
        <THead>
          <tr>
            <TH>Board</TH>
            <TH>Template</TH>
            <TH className="text-right">Open</TH>
            <TH className="text-right">Total</TH>
            <TH>Progress</TH>
            <TH className="text-right">Columns</TH>
            <TH>Updated</TH>
            <TH>
              <span className="sr-only">Actions</span>
            </TH>
          </tr>
        </THead>
        <tbody>
          {boards.map((b) => (
            <TR key={b.id} onClick={() => navigate(`/work/boards/${encodeURIComponent(b.id)}`)}>
              <TD>
                <span className="inline-flex items-center gap-2">
                  <Link to={`/work/boards/${encodeURIComponent(b.id)}`} onClick={(e) => e.stopPropagation()} className="font-medium text-fg hover:text-accent">
                    {b.name}
                  </Link>
                  {b.is_default && <Badge tone="accent">Default</Badge>}
                  {b.archived_at && <Badge tone="warn">Archived</Badge>}
                </span>
              </TD>
              <TD className="text-fg-muted">{templateLabel(b.template)}</TD>
              <TD className="num text-right">{b.open_task_count}</TD>
              <TD className="num text-right text-fg-muted">{b.task_count}</TD>
              <TD>
                <Progress board={b} />
              </TD>
              <TD className="num text-right text-fg-muted">{b.column_count}</TD>
              <TD className="text-xs text-fg-muted">{timeAgo(b.updated_at)}</TD>
              <TD className="w-10">
                <BoardActions board={b} canWrite={canWrite} />
              </TD>
            </TR>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

export function BoardsPage() {
  const { can } = useAuth();
  const canWrite = can("write");
  const { get, set } = useUrlState();
  const view: View = get("view") === "list" ? "list" : "grid";
  const showArchived = get("archived") === "1";
  const [creating, setCreating] = useState(false);
  const boards = useBoards(showArchived);

  const sorted = useMemo(
    () =>
      [...(boards.data?.items ?? [])].sort(
        (a, b) => Number(a.archived_at !== null) - Number(b.archived_at !== null) || Number(b.is_default) - Number(a.is_default) || a.name.localeCompare(b.name),
      ),
    [boards.data],
  );

  return (
    <>
      <PageHeader
        title="Kanban boards"
        description="Each board is a workflow. Columns carry WIP limits and verification gates that the server enforces on every move."
        actions={
          canWrite && (
            <Button variant="primary" size="sm" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setCreating(true)}>
              New board
            </Button>
          )
        }
      />
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <SegmentedControl<View>
          aria-label="Board layout"
          value={view}
          onChange={(v) => set({ view: v === "grid" ? null : v })}
          options={[
            { value: "grid", label: "Grid", icon: <LayoutGrid /> },
            { value: "list", label: "List", icon: <List /> },
          ]}
        />
        <Checkbox label="Show archived" checked={showArchived} onChange={(on) => set({ archived: on ? "1" : null })} />
        {boards.data && <span className="ml-auto text-2xs text-fg-faint">{boards.data.total} boards</span>}
      </div>

      {boards.isLoading ? (
        <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-busy="true" aria-label="Loading boards">
          {Array.from({ length: 6 }).map((_, i) => (
            <li key={i} className="panel space-y-3 p-4">
              <Skeleton className="h-4 w-40" />
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-8 w-24" />
            </li>
          ))}
        </ul>
      ) : boards.error ? (
        <div className="panel">
          <ErrorState error={boards.error} onRetry={() => void boards.refetch()} />
        </div>
      ) : sorted.length === 0 ? (
        <div className="panel">
          <EmptyState
            icon={<KanbanSquare className="h-5 w-5" aria-hidden />}
            title={showArchived ? "No boards" : "No active boards"}
            description="Create a board from a template to start tracking engineering and remediation work."
            action={canWrite ? <Button size="sm" variant="primary" onClick={() => setCreating(true)}>New board</Button> : undefined}
          />
        </div>
      ) : view === "grid" ? (
        <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-label="Boards">
          {sorted.map((b) => (
            <BoardTile key={b.id} board={b} canWrite={canWrite} />
          ))}
        </ul>
      ) : (
        <BoardsTable boards={sorted} canWrite={canWrite} />
      )}

      <NewBoardDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}
