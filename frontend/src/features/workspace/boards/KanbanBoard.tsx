/**
 * The Kanban surface: multi-column sortable drag and drop (pointer and keyboard), drag overlay,
 * optimistic moves with rollback, and the server's workflow gates reported in plain language.
 *
 * While a drag (or the move request it caused) is in flight the board renders a local copy of the
 * column order; otherwise it renders the cached board. `useMoveTask` updates that cache
 * optimistically and restores it when the server refuses the move.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  closestCenter,
  defaultDropAnimationSideEffects,
  DndContext,
  DragOverlay,
  getFirstCollision,
  KeyboardSensor,
  MeasuringStrategy,
  PointerSensor,
  pointerWithin,
  rectIntersection,
  useSensor,
  useSensors,
  type Announcements,
  type CollisionDetection,
  type DragEndEvent,
  type DragOverEvent,
  type DragStartEvent,
  type UniqueIdentifier,
} from "@dnd-kit/core";
import { sortableKeyboardCoordinates } from "@dnd-kit/sortable";
import { Plus } from "lucide-react";
import { useToast } from "@/components/ui";
import { useMoveTask, useReorderColumns, useUpdateColumn } from "../api";
import type { BoardDetail, Column, TaskCard, TaskType } from "../types";
import type { ConflictContext } from "../tasks/useWorkflowConflicts";
import { errorMessage } from "../tasks/useWorkflowConflicts";
import { BoardCardContent } from "./BoardCard";
import { KanbanColumn } from "./KanbanColumn";
import { cardFields, hasActiveFilters, matchesFilters, verificationGates, type BoardFilterState } from "./boardMeta";
import { boardToItems, findContainer, moveToContainer, placementChanged, placementOf, reorderWithin, type ColumnItems } from "./dnd";

export interface KanbanBoardProps {
  board: BoardDetail;
  filters: BoardFilterState;
  meId: string | null;
  canWrite: boolean;
  onOpenTask: (taskId: string) => void;
  onAddColumn: () => void;
  onEditColumn: (column: Column) => void;
  onDeleteColumn: (column: Column) => void;
  report: (error: unknown, ctx: ConflictContext) => void;
}

const SCREEN_READER_INSTRUCTIONS = {
  draggable:
    "To move a task card, press Space to pick it up. Use the arrow keys to move it within a column or to another column, press Space again to drop it, or Escape to cancel. Press Enter to open the task.",
};

export function KanbanBoard({ board, filters, meId, canWrite, onOpenTask, onAddColumn, onEditColumn, onDeleteColumn, report }: KanbanBoardProps) {
  const toast = useToast();
  const move = useMoveTask();
  const reorder = useReorderColumns();
  const updateColumn = useUpdateColumn();

  const columns = useMemo(() => [...board.columns].sort((a, b) => a.position - b.position), [board.columns]);
  const cardsById = useMemo(() => new Map<string, TaskCard>(columns.flatMap((c) => c.tasks.map((t) => [t.id, t] as const))), [columns]);
  const columnById = useMemo(() => new Map(columns.map((c) => [c.id, c])), [columns]);
  const columnNames = useMemo(() => Object.fromEntries(columns.map((c) => [c.id, c.name])), [columns]);
  const serverItems = useMemo(() => boardToItems({ columns }), [columns]);
  const fields = useMemo(() => cardFields(board.config), [board.config]);
  const gates = useMemo(() => verificationGates(columns), [columns]);
  const filtered = hasActiveFilters(filters);
  const defaultType: TaskType = board.config.default_task_type ?? "task";

  const [dragItems, setDragItems] = useState<ColumnItems | null>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [overColumn, setOverColumn] = useState<string | null>(null);
  const items = dragItems ?? serverItems;
  const startItems = useRef<ColumnItems | null>(null);
  const lastOverId = useRef<UniqueIdentifier | null>(null);
  const dragging = useRef(false);
  const settleToken = useRef(0);
  /** Set right after a card changes column so collision detection does not bounce it straight back. */
  const movedToNewColumn = useRef(false);
  /** When the last drag ended: a click that immediately follows a drop must not open the task. */
  const lastDragEnd = useRef(0);

  const visible = useMemo(() => {
    const out: Record<string, TaskCard[]> = {};
    for (const column of columns) {
      out[column.id] = (items[column.id] ?? []).flatMap((id) => {
        const card = cardsById.get(id);
        return card && (!filtered || matchesFilters(card, filters, meId)) ? [card] : [];
      });
    }
    return out;
  }, [columns, items, cardsById, filtered, filters, meId]);

  const visibleRef = useRef(visible);
  visibleRef.current = visible;
  const itemsRef = useRef(items);
  itemsRef.current = items;

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      movedToNewColumn.current = false;
    });
    return () => cancelAnimationFrame(frame);
  }, [items]);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
      keyboardCodes: { start: ["Space"], cancel: ["Escape"], end: ["Space", "Enter"] },
      // Instant scrolling keeps the highlighted drop column in step with each arrow key press.
      scrollBehavior: "auto",
    }),
  );

  /** Pointer first, then rectangle overlap; inside a column snap to its closest visible card. */
  const collisionDetection: CollisionDetection = useCallback((args) => {
    const pointerHits = pointerWithin(args);
    const hits = pointerHits.length > 0 ? pointerHits : rectIntersection(args);
    let overId = getFirstCollision(hits, "id");
    if (overId != null) {
      const key = String(overId);
      if (key in itemsRef.current) {
        const ids = (visibleRef.current[key] ?? []).map((c) => c.id);
        if (ids.length > 0) {
          const closest = closestCenter({ ...args, droppableContainers: args.droppableContainers.filter((c) => ids.includes(String(c.id))) });
          if (closest.length > 0) overId = closest[0].id;
        }
      }
      lastOverId.current = overId;
      return [{ id: overId }];
    }
    if (movedToNewColumn.current) lastOverId.current = args.active.id;
    return lastOverId.current != null ? [{ id: lastOverId.current }] : [];
  }, []);

  const cardLabel = (id: UniqueIdentifier) => {
    const card = cardsById.get(String(id));
    return card ? `${card.key} “${card.title}”` : "the task";
  };
  const describeOver = (id: UniqueIdentifier) => {
    const column = findContainer(itemsRef.current, String(id));
    if (!column) return "no column";
    const ids = itemsRef.current[column] ?? [];
    const at = ids.indexOf(String(id));
    return at >= 0 ? `column ${columnNames[column]}, position ${at + 1} of ${ids.length}` : `column ${columnNames[column]}`;
  };
  const announcements: Announcements = {
    onDragStart: ({ active }) => `Picked up ${cardLabel(active.id)}.`,
    onDragOver: ({ active, over }) => (over ? `${cardLabel(active.id)} is over ${describeOver(over.id)}.` : `${cardLabel(active.id)} is not over a column.`),
    onDragEnd: ({ active, over }) => (over ? `Dropped ${cardLabel(active.id)} in ${describeOver(active.id)}.` : `Dropped ${cardLabel(active.id)}; it was not moved.`),
    onDragCancel: ({ active }) => `Cancelled. ${cardLabel(active.id)} was not moved.`,
  };

  const resetDrag = () => {
    dragging.current = false;
    lastDragEnd.current = Date.now();
    setActiveId(null);
    setOverColumn(null);
    startItems.current = null;
  };

  const runMove = (taskId: string, columnId: string, position: number, token: number) => {
    const card = cardsById.get(taskId);
    const target = columnById.get(columnId);
    const vars = { taskId, boardId: board.id, column_id: columnId, position };
    // Promise handlers (not per-call mutate callbacks) so every move reports its own outcome, even
    // when a second drag starts before the first request has finished.
    move
      .mutateAsync(vars)
      .catch((error: unknown) =>
        report(error, {
          title: `${card?.key ?? "Task"} was not moved to “${target?.name ?? "that column"}”`,
          override: () => move.mutateAsync({ ...vars, override_wip: true }),
        }),
      )
      .finally(() => {
        if (settleToken.current === token && !dragging.current) setDragItems(null);
      });
  };

  const onDragStart = ({ active }: DragStartEvent) => {
    dragging.current = true;
    lastOverId.current = null;
    startItems.current = serverItems;
    setDragItems(serverItems);
    setActiveId(String(active.id));
    setOverColumn(findContainer(serverItems, String(active.id)));
  };

  const onDragOver = ({ active, over }: DragOverEvent) => {
    if (!over) return;
    const activeKey = String(active.id);
    const overKey = String(over.id);
    const current = itemsRef.current;
    const from = findContainer(current, activeKey);
    const to = findContainer(current, overKey);
    if (to !== overColumn) setOverColumn(to);
    if (!from || !to || from === to) return;
    const translated = active.rect.current.translated;
    const placeBelow = overKey !== to && !!translated && translated.top + translated.height / 2 > over.rect.top + over.rect.height / 2;
    movedToNewColumn.current = true;
    setDragItems((prev) => moveToContainer(prev ?? current, activeKey, overKey, placeBelow));
  };

  const onDragEnd = ({ active, over }: DragEndEvent) => {
    const activeKey = String(active.id);
    const start = startItems.current;
    let next = itemsRef.current;
    if (over) {
      const overKey = String(over.id);
      if (findContainer(next, activeKey) === findContainer(next, overKey)) next = reorderWithin(next, activeKey, overKey);
    }
    resetDrag();
    const placement = placementOf(next, activeKey);
    if (!over || !start || !placement || !placementChanged(start, next, activeKey)) {
      setDragItems(null);
      return;
    }
    setDragItems(next);
    runMove(activeKey, placement.columnId, placement.index, ++settleToken.current);
  };

  const onDragCancel = () => {
    resetDrag();
    setDragItems(null);
  };

  const renameColumn = (column: Column, name: string) =>
    updateColumn.mutateAsync({ boardId: board.id, columnId: column.id, patch: { name } }).catch((error: unknown) => {
      toast.error("Column not renamed", errorMessage(error));
      throw error;
    });

  const moveColumn = (index: number, direction: -1 | 1) => {
    const ids = columns.map((c) => c.id);
    const target = index + direction;
    if (target < 0 || target >= ids.length) return;
    [ids[index], ids[target]] = [ids[target], ids[index]];
    reorder.mutate({ boardId: board.id, columnIds: ids }, { onError: (error) => toast.error("Columns not reordered", errorMessage(error)) });
  };

  const openTask = useCallback(
    (taskId: string) => {
      if (Date.now() - lastDragEnd.current > 250) onOpenTask(taskId);
    },
    [onOpenTask],
  );

  const activeCard = activeId ? cardsById.get(activeId) : undefined;
  const startColumn = activeId && startItems.current ? findContainer(startItems.current, activeId) : null;

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={collisionDetection}
      measuring={{ droppable: { strategy: MeasuringStrategy.Always } }}
      accessibility={{ announcements, screenReaderInstructions: SCREEN_READER_INSTRUCTIONS }}
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDragEnd={onDragEnd}
      onDragCancel={onDragCancel}
    >
      {/* `relative` makes this scroll container the containing block for absolutely positioned
          descendants (e.g. screen-reader-only text), so they cannot widen the page. */}
      <div className="relative flex h-full min-h-[420px] items-stretch gap-3 overflow-x-auto pb-3" role="list" aria-label={`Columns of ${board.name}`}>
        {columns.map((column, index) => {
          const isTarget = activeId !== null && overColumn === column.id && startColumn !== column.id;
          return (
            <div role="listitem" key={column.id} className="flex">
              <KanbanColumn
                boardId={board.id}
                column={column}
                allIds={items[column.id] ?? []}
                cards={visible[column.id] ?? []}
                fields={fields}
                columnNames={columnNames}
                index={index}
                columnCount={columns.length}
                filtered={filtered}
                isDropTarget={isTarget}
                gateName={gates[column.id] ?? null}
                gateWarning={isTarget && gates[column.id] != null && activeCard?.verification_status !== "passed"}
                canWrite={canWrite}
                defaultType={defaultType}
                onOpenTask={openTask}
                onRename={(name) => renameColumn(column, name)}
                onEdit={() => onEditColumn(column)}
                onMove={(direction) => moveColumn(index, direction)}
                onDelete={() => onDeleteColumn(column)}
                onTaskCreated={(key) => toast.success(`${key} created`, `Added to “${column.name}”.`)}
                onError={report}
              />
            </div>
          );
        })}
        {canWrite && (
          <div role="listitem" className="flex">
            <button
              type="button"
              onClick={onAddColumn}
              className="flex h-10 w-[200px] shrink-0 items-center justify-center gap-1.5 rounded-lg border border-dashed border-border text-xs text-fg-muted transition-colors hover:border-border-strong hover:bg-surface-2 hover:text-fg"
            >
              <Plus className="h-3.5 w-3.5" aria-hidden />
              Add column
            </button>
          </div>
        )}
      </div>
      <DragOverlay dropAnimation={{ duration: 180, easing: "cubic-bezier(.2,.8,.2,1)", sideEffects: defaultDropAnimationSideEffects({ styles: { active: { opacity: "0.4" } } }) }}>
        {activeCard ? (
          <div className="w-[272px]">
            <BoardCardContent card={activeCard} fields={fields} verificationMatters={false} overlay />
          </div>
        ) : null}
      </DragOverlay>
    </DndContext>
  );
}
