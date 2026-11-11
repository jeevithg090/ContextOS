/**
 * Kanban card. `BoardCardContent` is the presentational body (also used by the drag overlay);
 * `SortableBoardCard` wires it to dnd-kit. Click or Enter opens the task; Space picks it up for a
 * keyboard move (arrow keys move it, Space drops, Escape cancels).
 */
import { memo, type KeyboardEvent } from "react";
import { Link } from "react-router-dom";
import { useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { Radar } from "lucide-react";
import { SeverityBadge } from "@/components/ui";
import { cn } from "@/lib/format";
import { AssigneeStack, DueDate, LabelChip, taskTypeLabel } from "../analytics/taskMeta";
import type { CardField, TaskCard } from "../types";
import { BlockedMarker, PriorityIcon, SubtaskProgress, VerificationIcon } from "../tasks/taskBits";
import { SECURITY_TASK_TYPES } from "./boardMeta";

export interface BoardCardContentProps {
  card: TaskCard;
  fields: Set<CardField>;
  /** The card sits in a done or verification-gated column, so "unverified" deserves attention. */
  verificationMatters: boolean;
  overlay?: boolean;
}

export const BoardCardContent = memo(function BoardCardContent({ card, fields, verificationMatters, overlay }: BoardCardContentProps) {
  const show = (f: CardField) => fields.has(f);
  const securityWork = SECURITY_TASK_TYPES.has(card.task_type) || card.related_finding_id !== null;
  const showVerification = show("verification") && (card.verification_status !== "unverified" || verificationMatters);
  const people = card.assignees.filter((a) => a.role === "assignee");

  return (
    <div
      className={cn(
        "group/card rounded-md border border-border bg-surface-2 px-2.5 py-2 text-left transition-[border-color,box-shadow] duration-150",
        overlay ? "rotate-[1.5deg] cursor-grabbing border-accent/50 shadow-pop" : "hover:border-border-strong",
      )}
    >
      <div className="flex items-center gap-1.5">
        {show("priority") && <PriorityIcon priority={card.priority} />}
        {show("key") && <span className="font-mono text-2xs text-fg-faint">{card.key}</span>}
        <span className="ml-auto flex items-center gap-1.5">
          {show("finding") && card.related_finding_id && (
            <Link
              to={`/intelligence/${encodeURIComponent(card.related_finding_id)}`}
              onClick={(e) => e.stopPropagation()}
              onPointerDown={(e) => e.stopPropagation()}
              onKeyDown={(e) => e.stopPropagation()}
              className="inline-flex text-fg-faint hover:text-accent"
              title="Open the linked finding"
              aria-label={`Open the finding linked to ${card.key}`}
            >
              <Radar className="h-3.5 w-3.5" aria-hidden />
            </Link>
          )}
          {showVerification && <VerificationIcon status={card.verification_status} emphasise={verificationMatters} />}
        </span>
      </div>

      <p className="mt-1 line-clamp-3 break-words text-[13px] leading-snug text-fg">{card.title}</p>

      {(show("severity") || show("type") || show("labels")) && (
        <div className="mt-1.5 flex flex-wrap items-center gap-1">
          {show("severity") && securityWork && card.severity && <SeverityBadge severity={card.severity} />}
          {show("type") && <span className="text-2xs text-fg-muted">{taskTypeLabel(card.task_type)}</span>}
          {show("labels") && card.labels.slice(0, 3).map((label) => <LabelChip key={label.id} label={label} />)}
          {show("labels") && card.labels.length > 3 && <span className="text-2xs text-fg-faint">+{card.labels.length - 3}</span>}
        </div>
      )}

      {(card.due_date || card.subtasks_total > 0 || card.blocked_by_open > 0 || people.length > 0) && (
        <div className="mt-2 flex items-center gap-2">
          {show("due_date") && card.due_date && <DueDate due={card.due_date} done={card.is_done} overdue={card.is_overdue} />}
          {show("subtasks") && <SubtaskProgress done={card.subtasks_done} total={card.subtasks_total} />}
          <BlockedMarker count={card.blocked_by_open} />
          {show("assignees") && people.length > 0 && (
            <span className="ml-auto">
              <AssigneeStack assignees={card.assignees} max={3} />
            </span>
          )}
        </div>
      )}
    </div>
  );
});

export interface SortableBoardCardProps extends Omit<BoardCardContentProps, "overlay"> {
  onOpen: (taskId: string) => void;
  disabled?: boolean;
}

export function SortableBoardCard({ card, fields, verificationMatters, onOpen, disabled }: SortableBoardCardProps) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: card.id,
    data: { type: "card", columnId: card.column_id },
    disabled,
  });

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Enter" && !isDragging) {
      e.preventDefault();
      onOpen(card.id);
      return;
    }
    listeners?.onKeyDown?.(e);
  };

  return (
    <div
      ref={setNodeRef}
      style={{ transform: CSS.Translate.toString(transform), transition }}
      {...attributes}
      {...listeners}
      onKeyDown={onKeyDown}
      onClick={() => onOpen(card.id)}
      aria-roledescription="Draggable task card"
      aria-label={`${card.key}: ${card.title}`}
      className={cn(
        "cursor-pointer touch-manipulation rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent",
        isDragging && "opacity-40",
      )}
    >
      <BoardCardContent card={card} fields={fields} verificationMatters={verificationMatters} />
    </div>
  );
}
