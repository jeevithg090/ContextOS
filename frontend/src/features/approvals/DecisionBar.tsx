/**
 * Approve / Reject with an optional note. Approving asks for confirmation when the destination is
 * SUSPICIOUS/BLOCKED or credentials are involved (the server lists the reasons). Keyboard: A / R,
 * ignored while typing or when a dialog is open.
 */
import { useCallback, useEffect, useId, useState } from "react";
import { Check, X } from "lucide-react";
import { ConfirmDialog } from "@/components/data";
import { Button, Textarea, useToast } from "@/components/ui";
import { useDecideApproval } from "./api";
import type { ApprovalDetail } from "./types";

const MAX_NOTE = 2000;

/** Visible shortcut hint inside a button (inherits the button's colour). */
function ShortcutHint({ children }: { children: string }) {
  return (
    <kbd className="ml-0.5 rounded border border-current px-1 font-mono text-2xs leading-4 opacity-60" aria-hidden>
      {children}
    </kbd>
  );
}

function isTypingTarget(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  return !!el?.closest?.("input, textarea, select, [contenteditable='true'], [role='dialog']");
}

export interface DecisionBarProps {
  approval: ApprovalDetail;
  canApprove: boolean;
  /** The client-side countdown reached zero; the server will refuse a decision. */
  deadlinePassed: boolean;
  onDecided: (detail: ApprovalDetail) => void;
}

export function DecisionBar({ approval, canApprove, deadlinePassed, onDecided }: DecisionBarProps) {
  const noteId = useId();
  const [note, setNote] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const decide = useDecideApproval();
  const toast = useToast();

  useEffect(() => {
    setNote("");
    setError(null);
    setConfirmOpen(false);
  }, [approval.id]);

  const submit = useCallback(
    async (approve: boolean) => {
      setError(null);
      try {
        const detail = await decide.mutateAsync({ id: approval.id, body: { approve, note: note.trim() || null } });
        toast.success(
          approve ? "Approved" : "Rejected",
          approve ? "The integration receives the approval on its next poll and lets the call run." : "The integration receives the rejection on its next poll and denies the call.",
        );
        onDecided(detail);
      } catch (err) {
        const message = err instanceof Error ? err.message : "The decision could not be recorded.";
        setError(message);
        throw err;
      }
    },
    [approval.id, decide, note, onDecided, toast],
  );

  const disabled = !canApprove || deadlinePassed || decide.isPending;

  const requestApprove = useCallback(() => {
    if (disabled) return;
    if (approval.requires_confirmation) setConfirmOpen(true);
    else void submit(true).catch(() => undefined);
  }, [approval.requires_confirmation, disabled, submit]);

  const requestReject = useCallback(() => {
    if (disabled) return;
    void submit(false).catch(() => undefined);
  }, [disabled, submit]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.repeat || e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target)) return;
      if (document.querySelector("[role='dialog']")) return;
      const key = e.key.toLowerCase();
      if (key === "a") {
        e.preventDefault();
        requestApprove();
      } else if (key === "r") {
        e.preventDefault();
        requestReject();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [requestApprove, requestReject]);

  if (!canApprove) {
    return (
      <div className="rounded-md border border-border bg-surface-2/60 px-3 py-2.5 text-xs text-fg-muted">
        You can review this request, but deciding needs the <span className="font-mono text-fg">approve</span> permission (Owner, Admin or
        Security analyst role).
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <label htmlFor={noteId} className="block text-xs font-medium text-fg-muted">
        Note <span className="font-normal text-fg-faint">(optional; recorded in the audit log, secrets are redacted)</span>
      </label>
      <Textarea
        id={noteId}
        value={note}
        maxLength={MAX_NOTE}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Why are you approving or rejecting this?"
        className="min-h-[56px]"
        disabled={decide.isPending}
      />
      {error && (
        <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-2.5 py-2 text-xs text-danger">
          {error}
        </p>
      )}
      {deadlinePassed && <p className="text-xs text-fg-muted">The deadline has passed; this request can no longer be decided.</p>}
      <div className="flex flex-wrap items-center justify-end gap-2">
        {note.length > MAX_NOTE - 200 && (
          <span className="num mr-auto text-2xs text-fg-faint">
            {note.length}/{MAX_NOTE}
          </span>
        )}
        <Button variant="danger" onClick={requestReject} disabled={disabled} loading={decide.isPending && decide.variables?.body.approve === false} icon={<X className="h-3.5 w-3.5" aria-hidden />} aria-keyshortcuts="r">
          Reject <ShortcutHint>R</ShortcutHint>
        </Button>
        <Button variant="primary" onClick={requestApprove} disabled={disabled} loading={decide.isPending && decide.variables?.body.approve === true} icon={<Check className="h-3.5 w-3.5" aria-hidden />} aria-keyshortcuts="a">
          Approve <ShortcutHint>A</ShortcutHint>
        </Button>
      </div>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        destructive
        title="Approve this request?"
        description={`${approval.agent.name ?? "The agent"} wants to ${approval.action}.`}
        confirmLabel="Approve anyway"
        onConfirm={() => submit(true)}
      >
        <p>ContextOS flagged this request because:</p>
        <ul className="list-disc space-y-1 pl-5 text-fg">
          {approval.confirmation_reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
        <p>Approving lets the integration run the call as requested. This cannot be undone once the call has run.</p>
      </ConfirmDialog>
    </div>
  );
}
