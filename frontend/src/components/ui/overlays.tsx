import * as RadixDialog from "@radix-ui/react-dialog";
import * as RadixTabs from "@radix-ui/react-tabs";
import * as RadixTooltip from "@radix-ui/react-tooltip";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/format";

/* ----------------------------------------------------------------------------- Dialog */

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  className,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  className?: string;
}) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="fixed inset-0 z-40 bg-scrim/60 backdrop-blur-[2px] animate-fade-in" />
        <RadixDialog.Content
          className={cn(
            // -translate-x-1/2 centres the panel; animate-dialog-in keeps that translate in every
            // keyframe (a plain slide-up would replace it and shift the dialog while it animates).
            "fixed left-1/2 top-[12vh] z-50 w-[min(560px,calc(100vw-32px))] -translate-x-1/2 rounded-lg border border-border-strong bg-surface shadow-pop animate-dialog-in focus:outline-none",
            className,
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div>
              <RadixDialog.Title className="text-[14px] font-semibold text-fg">{title}</RadixDialog.Title>
              {description ? (
                <RadixDialog.Description className="mt-1 text-xs text-fg-muted">{description}</RadixDialog.Description>
              ) : (
                <RadixDialog.Description className="sr-only">Dialog</RadixDialog.Description>
              )}
            </div>
            <RadixDialog.Close className="rounded p-1 text-fg-faint hover:bg-surface-2 hover:text-fg" aria-label="Close">
              <X className="h-4 w-4" />
            </RadixDialog.Close>
          </div>
          <div className="max-h-[65vh] overflow-y-auto px-5 py-4">{children}</div>
          {footer && <div className="flex justify-end gap-2 border-t border-border px-5 py-3">{footer}</div>}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}

/* ----------------------------------------------------------------------------- Drawer (side panel) */

export function Drawer({
  open,
  onOpenChange,
  title,
  subtitle,
  actions,
  children,
  width = "w-[min(720px,100vw)]",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  width?: string;
}) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="fixed inset-0 z-40 bg-scrim/50 animate-fade-in" />
        <RadixDialog.Content className={cn("fixed inset-y-0 right-0 z-50 flex flex-col border-l border-border-strong bg-surface shadow-pop animate-slide-in-right focus:outline-none", width)}>
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div className="min-w-0">
              <RadixDialog.Title className="truncate text-[15px] font-semibold text-fg">{title}</RadixDialog.Title>
              {subtitle ? (
                <RadixDialog.Description className="mt-1 text-xs text-fg-muted">{subtitle}</RadixDialog.Description>
              ) : (
                <RadixDialog.Description className="sr-only">Details panel</RadixDialog.Description>
              )}
            </div>
            <div className="flex items-center gap-2">
              {actions}
              <RadixDialog.Close className="rounded p-1 text-fg-faint hover:bg-surface-2 hover:text-fg" aria-label="Close panel">
                <X className="h-4 w-4" />
              </RadixDialog.Close>
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}

/* ----------------------------------------------------------------------------- Tabs */

export function Tabs({
  value,
  onValueChange,
  tabs,
  children,
  className,
}: {
  value: string;
  onValueChange: (v: string) => void;
  tabs: Array<{ value: string; label: ReactNode; count?: number }>;
  children: ReactNode;
  className?: string;
}) {
  return (
    <RadixTabs.Root value={value} onValueChange={onValueChange} className={className}>
      <RadixTabs.List className="flex gap-1 border-b border-border" aria-label="Sections">
        {tabs.map((t) => (
          <RadixTabs.Trigger
            key={t.value}
            value={t.value}
            className="relative -mb-px inline-flex h-9 items-center gap-1.5 border-b-2 border-transparent px-2.5 text-[13px] text-fg-muted transition-colors hover:text-fg data-[state=active]:border-accent data-[state=active]:text-fg"
          >
            {t.label}
            {t.count !== undefined && <span className="num rounded bg-surface-3 px-1 text-2xs text-fg-muted">{t.count}</span>}
          </RadixTabs.Trigger>
        ))}
      </RadixTabs.List>
      {children}
    </RadixTabs.Root>
  );
}

export const TabPanel = ({ value, children, className }: { value: string; children: ReactNode; className?: string }) => (
  <RadixTabs.Content value={value} className={cn("focus:outline-none", className)}>
    {children}
  </RadixTabs.Content>
);

/* ----------------------------------------------------------------------------- Tooltip */

export function Tooltip({ content, children, side = "top" }: { content: ReactNode; children: ReactNode; side?: "top" | "bottom" | "left" | "right" }) {
  return (
    <RadixTooltip.Root delayDuration={250}>
      <RadixTooltip.Trigger asChild>{children}</RadixTooltip.Trigger>
      <RadixTooltip.Portal>
        <RadixTooltip.Content side={side} sideOffset={6} className="z-50 max-w-xs rounded border border-border-strong bg-surface-3 px-2 py-1 text-xs text-fg shadow-pop animate-fade-in">
          {content}
        </RadixTooltip.Content>
      </RadixTooltip.Portal>
    </RadixTooltip.Root>
  );
}

export const TooltipProvider = RadixTooltip.Provider;
