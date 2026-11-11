/** Per-column actions menu (Radix dropdown: keyboard navigable, focus returns to the trigger). */
import * as Menu from "@radix-ui/react-dropdown-menu";
import { ArrowLeft, ArrowRight, MoreHorizontal, Pencil, Settings2, Trash2 } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/format";

export interface ColumnMenuProps {
  columnName: string;
  canMoveLeft: boolean;
  canMoveRight: boolean;
  onRename: () => void;
  onEdit: () => void;
  onMove: (direction: -1 | 1) => void;
  onDelete: () => void;
}

function Item({ icon, children, onSelect, disabled, danger }: { icon: ReactNode; children: ReactNode; onSelect: () => void; disabled?: boolean; danger?: boolean }) {
  return (
    <Menu.Item
      disabled={disabled}
      onSelect={onSelect}
      className={cn(
        "flex h-7 cursor-pointer select-none items-center gap-2 rounded px-2 text-xs outline-none data-[disabled]:cursor-not-allowed data-[disabled]:opacity-40 data-[highlighted]:bg-surface-3",
        danger ? "text-danger" : "text-fg",
      )}
    >
      <span className="text-fg-muted [&>svg]:h-3.5 [&>svg]:w-3.5" aria-hidden>
        {icon}
      </span>
      {children}
    </Menu.Item>
  );
}

export function ColumnMenu({ columnName, canMoveLeft, canMoveRight, onRename, onEdit, onMove, onDelete }: ColumnMenuProps) {
  return (
    <Menu.Root>
      <Menu.Trigger asChild>
        <button
          type="button"
          aria-label={`Actions for column ${columnName}`}
          title="Column actions"
          className="inline-flex h-6 w-6 items-center justify-center rounded text-fg-faint transition-colors hover:bg-surface-3 hover:text-fg data-[state=open]:bg-surface-3 data-[state=open]:text-fg"
        >
          <MoreHorizontal className="h-4 w-4" aria-hidden />
        </button>
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Content align="end" sideOffset={4} className="z-50 min-w-[180px] rounded-md border border-border-strong bg-surface p-1 shadow-pop animate-fade-in">
          <Item icon={<Pencil />} onSelect={onRename}>
            Rename
          </Item>
          <Item icon={<Settings2 />} onSelect={onEdit}>
            Edit column…
          </Item>
          <Menu.Separator className="my-1 h-px bg-border" />
          <Item icon={<ArrowLeft />} onSelect={() => onMove(-1)} disabled={!canMoveLeft}>
            Move left
          </Item>
          <Item icon={<ArrowRight />} onSelect={() => onMove(1)} disabled={!canMoveRight}>
            Move right
          </Item>
          <Menu.Separator className="my-1 h-px bg-border" />
          <Item icon={<Trash2 />} onSelect={onDelete} danger>
            Delete column…
          </Item>
        </Menu.Content>
      </Menu.Portal>
    </Menu.Root>
  );
}
