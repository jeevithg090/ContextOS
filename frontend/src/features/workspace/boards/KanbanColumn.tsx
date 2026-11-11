/**
 * One board column: header (colour accent, name, count against the WIP limit, gate markers, menu),
 * the droppable sortable card list, an empty-column hint and the quick-add box.
 */
import { useEffect, useRef, useState } from "react";
import { useDroppable } from "@dnd-kit/core";
import { SortableContext, verticalListSortingStrategy } from "@dnd-kit/sortable";
import { CheckCircle2, Lock, Zap } from "lucide-react";
import { Tooltip } from "@/components/ui";
import { cn } from "@/lib/format";
import type { CardField, ColumnWithTasks, TaskCard, TaskType } from "../types";
import { automationTriggerLabel } from "./columnOptions";
import { SortableBoardCard } from "./BoardCard";
import { ColumnMenu } from "./ColumnMenu";
import { QuickAddCard } from "./QuickAddCard";
import { columnAccent } from "./boardMeta";
import type { ConflictContext } from "../tasks/useWorkflowConflicts";

export interface KanbanColumnProps {
  boardId: string;
  column: ColumnWithTasks;
  /** Every task id in the column, in order (drives the WIP count during a drag). */
  allIds: string[];
  /** Cards visible under the current filters, in order. */
  cards: TaskCard[];
  fields: Set<CardField>;
  columnNames: Record<string, string>;
  index: number;
  columnCount: number;
  filtered: boolean;
  /** A card is being dragged over this column. */
  isDropTarget: boolean;
  /** Name of the column whose verification gate applies when entering this one (itself or an earlier one). */
  gateName: string | null;
  /** The card being dragged cannot pass this column's verification gate. */
  gateWarning: boolean;
  canWrite: boolean;
  defaultType: TaskType;
  onOpenTask: (taskId: string) => void;
  onRename: (name: string) => Promise<unknown>;
  onEdit: () => void;
  onMove: (direction: -1 | 1) => void;
  onDelete: () => void;
  onTaskCreated: (key: string) => void;
  onError: (error: unknown, ctx: ConflictContext) => void;
}

function WipCount({ count, limit, shown }: { count: number; limit: number | null; shown: number | null }) {
  const tone = limit === null ? "text-fg-faint" : count > limit ? "text-danger" : count === limit ? "text-warn" : "text-fg-faint";
  const label =
    limit === null
      ? `${count} task${count === 1 ? "" : "s"}`
      : `${count} of ${limit} (WIP limit)${count > limit ? " — over the limit" : count === limit ? " — at the limit" : ""}`;
  return (
    <span className={cn("num text-2xs", tone)} title={label} aria-label={label}>
      {limit === null ? count : `${count}/${limit}`}
      {shown !== null && <span className="text-fg-faint"> · {shown} shown</span>}
    </span>
  );
}

export function KanbanColumn(props: KanbanColumnProps) {
  const { boardId, column, allIds, cards, fields, columnNames, index, columnCount, filtered, isDropTarget, gateName, gateWarning, canWrite } = props;
  const { setNodeRef } = useDroppable({ id: column.id, data: { type: "column" }, disabled: !canWrite });
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(column.name);
  const renameRef = useRef<HTMLInputElement>(null);
  const accent = columnAccent(column.color);
  const verificationMatters = column.is_done_column || column.requires_verification;

  useEffect(() => {
    if (!renaming) setName(column.name);
  }, [column.name, renaming]);

  const commitRename = () => {
    const next = name.trim();
    setRenaming(false);
    if (next && next !== column.name) void props.onRename(next).catch(() => setName(column.name));
    else setName(column.name);
  };

  return (
    <section
      aria-label={`Column ${column.name}`}
      className={cn(
        "flex max-h-full w-[288px] shrink-0 flex-col rounded-lg border bg-surface/70 transition-colors duration-150",
        isDropTarget ? (gateWarning ? "border-danger/50 bg-danger/[0.04]" : "border-accent/50 bg-accent/[0.03]") : "border-border",
      )}
    >
      <header className="flex items-center gap-2 px-3 pb-2 pt-2.5">
        <span className={cn("h-2 w-2 shrink-0 rounded-full", accent.dot)} style={accent.style} aria-hidden />
        {renaming ? (
          <input
            ref={renameRef}
            autoFocus
            value={name}
            maxLength={100}
            aria-label="Column name"
            onChange={(e) => setName(e.target.value)}
            onBlur={commitRename}
            onKeyDown={(e) => {
              if (e.key === "Enter") commitRename();
              else if (e.key === "Escape") {
                setName(column.name);
                setRenaming(false);
              }
            }}
            className="h-6 min-w-0 flex-1 rounded border border-accent/50 bg-surface-2 px-1.5 text-[13px] font-medium text-fg focus:outline-none"
          />
        ) : (
          <h2 className="min-w-0 truncate text-[13px] font-medium text-fg" title={column.description ?? column.name}>
            {column.name}
          </h2>
        )}
        <WipCount count={allIds.length} limit={column.wip_limit} shown={filtered ? cards.length : null} />
        <span className="ml-auto flex items-center gap-1 text-fg-faint">
          {gateName !== null && (
            <Tooltip
              content={
                column.requires_verification
                  ? "Verification gate: tasks can enter only with a passed verification run. A fix attempt marked complete is a claim, not verification."
                  : `This done column comes after the verification gate “${gateName}”, so tasks need a passed verification run to enter.`
              }
            >
              <span tabIndex={0} className="inline-flex rounded focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent" aria-label="Requires passed verification">
                <Lock className="h-3.5 w-3.5" aria-hidden />
              </span>
            </Tooltip>
          )}
          {column.is_done_column && (
            <Tooltip content="Done column: tasks here count as completed. Moving a task out reopens it.">
              <span tabIndex={0} className="inline-flex rounded focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent" aria-label="Done column">
                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
              </span>
            </Tooltip>
          )}
          {column.automation.length > 0 && (
            <Tooltip
              content={
                <ul className="space-y-0.5">
                  {column.automation.map((rule) => (
                    <li key={rule.trigger}>
                      When {automationTriggerLabel(rule.trigger).toLowerCase()}, move to “{columnNames[rule.move_to_column_id] ?? "a removed column"}”.
                    </li>
                  ))}
                </ul>
              }
            >
              <span tabIndex={0} className="inline-flex rounded focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent" aria-label={`${column.automation.length} automation rule(s)`}>
                <Zap className="h-3.5 w-3.5" aria-hidden />
              </span>
            </Tooltip>
          )}
          {canWrite && (
            <ColumnMenu
              columnName={column.name}
              canMoveLeft={index > 0}
              canMoveRight={index < columnCount - 1}
              onRename={() => setRenaming(true)}
              onEdit={props.onEdit}
              onMove={props.onMove}
              onDelete={props.onDelete}
            />
          )}
        </span>
      </header>
      {column.description && <p className="-mt-1 line-clamp-2 px-3 pb-2 text-2xs text-fg-faint">{column.description}</p>}

      <div ref={setNodeRef} className="relative flex min-h-[72px] flex-1 flex-col gap-1.5 overflow-y-auto px-2 pb-2">
        <SortableContext id={column.id} items={cards.map((c) => c.id)} strategy={verticalListSortingStrategy}>
          {cards.map((card) => (
            <SortableBoardCard
              key={card.id}
              card={card}
              fields={fields}
              verificationMatters={verificationMatters}
              onOpen={props.onOpenTask}
              disabled={!canWrite}
            />
          ))}
        </SortableContext>
        {cards.length === 0 && (
          <div className={cn("flex flex-1 items-center justify-center rounded-md border border-dashed px-3 py-5 text-center text-2xs", isDropTarget ? "border-accent/50 text-fg-muted" : "border-border text-fg-faint")}>
            {filtered && allIds.length > 0
              ? "No tasks here match the filters."
              : gateName !== null
                ? "Tasks arrive here once a verification run has passed."
                : canWrite
                  ? "Drop a task here or add one below."
                  : "No tasks in this column."}
          </div>
        )}
        {isDropTarget && gateWarning && (
          <p className="rounded border border-danger/30 bg-danger/10 px-2 py-1.5 text-2xs text-danger" role="note">
            This task has no passed verification run, so the server will refuse the move.
          </p>
        )}
      </div>

      {canWrite && (
        <div className="border-t border-border/70 p-1.5">
          <QuickAddCard
            boardId={boardId}
            columnId={column.id}
            columnName={column.name}
            defaultType={props.defaultType}
            onCreated={props.onTaskCreated}
            onError={props.onError}
          />
        </div>
      )}
    </section>
  );
}
