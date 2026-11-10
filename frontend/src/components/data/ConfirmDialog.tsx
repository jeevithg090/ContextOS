import { useEffect, useId, useState, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button, Dialog, Input } from "@/components/ui";

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  /** Extra explanation of consequences (what changes, who is affected, whether it can be undone). */
  children?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Red confirm button and warning icon for irreversible or security-relevant actions. */
  destructive?: boolean;
  /** Ask the user to type this exact text before confirming (for very destructive actions). */
  requireText?: string;
  /** May return a promise; the dialog shows a spinner, stays open on error and shows the message. */
  onConfirm: () => unknown | Promise<unknown>;
}

/** Confirmation step for consequential actions. Never closes while the action is in flight. */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  destructive = false,
  requireText,
  onConfirm,
}: ConfirmDialogProps) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [typed, setTyped] = useState("");
  const inputId = useId();

  useEffect(() => {
    if (open) {
      setError(null);
      setTyped("");
    }
  }, [open]);

  const blocked = requireText !== undefined && typed.trim() !== requireText;

  const confirm = async () => {
    if (pending || blocked) return;
    setPending(true);
    setError(null);
    try {
      await onConfirm();
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The action failed. Please try again.");
    } finally {
      setPending(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!pending) onOpenChange(next);
      }}
      title={
        <span className="inline-flex items-center gap-2">
          {destructive && <AlertTriangle className="h-4 w-4 text-danger" aria-hidden />}
          {title}
        </span>
      }
      description={description}
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={() => onOpenChange(false)} disabled={pending}>
            {cancelLabel}
          </Button>
          <Button variant={destructive ? "danger" : "primary"} size="sm" onClick={confirm} loading={pending} disabled={blocked}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void confirm();
        }}
        className="space-y-3 text-[13px] text-fg-muted"
      >
        {children}
        {requireText !== undefined && (
          <div className="space-y-1.5">
            <label htmlFor={inputId} className="block text-xs text-fg-muted">
              Type <span className="font-mono text-fg">{requireText}</span> to confirm
            </label>
            <Input id={inputId} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} disabled={pending} />
          </div>
        )}
        {error && (
          <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-2.5 py-2 text-xs text-danger">
            {error}
          </p>
        )}
      </form>
    </Dialog>
  );
}
