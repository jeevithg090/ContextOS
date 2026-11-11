import { useEffect, useRef, useState, type MouseEvent, type ReactNode } from "react";
import { Check, Copy, X } from "lucide-react";
import { cn } from "@/lib/format";

/**
 * Copy text to the clipboard. Uses the async Clipboard API when available (secure contexts) and
 * falls back to a hidden textarea + execCommand for plain-http self-hosted deployments.
 * Resolves `true` on success, `false` when the browser refused.
 */
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText && window.isSecureContext !== false) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Permission denied or document not focused: try the legacy path below.
    }
  }
  if (typeof document === "undefined") return false;
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.top = "-1000px";
  area.style.opacity = "0";
  document.body.appendChild(area);
  const selection = document.getSelection();
  const previous = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;
  area.select();
  let ok = false;
  try {
    ok = typeof document.execCommand === "function" && document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(area);
  if (previous && selection) {
    selection.removeAllRanges();
    selection.addRange(previous);
  }
  return ok;
}

type CopyState = "idle" | "copied" | "failed";

export interface CopyButtonProps {
  /** Text to copy, or a function producing it at click time (for large payloads). */
  value: string | (() => string);
  /** Accessible name, e.g. "Copy API key prefix". */
  label?: string;
  /** Optional visible text next to the icon ("Copy prompt"). Icon-only when omitted. */
  children?: ReactNode;
  className?: string;
  size?: "xs" | "sm";
  onCopied?: () => void;
}

export function CopyButton({ value, label = "Copy to clipboard", children, className, size = "sm", onCopied }: CopyButtonProps) {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<number>();

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const handleClick = async (e: MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation();
    const text = typeof value === "function" ? value() : value;
    const ok = await copyText(text);
    setState(ok ? "copied" : "failed");
    if (ok) onCopied?.();
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState("idle"), 1600);
  };

  const Icon = state === "copied" ? Check : state === "failed" ? X : Copy;
  const statusText = state === "copied" ? "Copied" : state === "failed" ? "Copy failed — select the text and copy manually" : "";
  const iconSize = size === "xs" ? "h-3 w-3" : "h-3.5 w-3.5";

  return (
    <button
      type="button"
      onClick={handleClick}
      aria-label={children ? undefined : label}
      title={statusText || label}
      className={cn(
        // `relative` keeps the sr-only status span inside the button (an unpositioned button would let it escape
        // a scrolling table cell and widen the page).
        "relative inline-flex shrink-0 items-center justify-center gap-1.5 rounded transition-colors",
        children ? (size === "xs" ? "h-6 px-2 text-2xs" : "h-7 px-2.5 text-xs") : size === "xs" ? "h-6 w-6" : "h-7 w-7",
        state === "copied" ? "text-ok" : state === "failed" ? "text-danger" : "text-fg-muted hover:bg-surface-2 hover:text-fg",
        children ? "border border-border-strong" : null,
        className,
      )}
    >
      <Icon className={iconSize} aria-hidden />
      {children}
      <span className="sr-only" role="status" aria-live="polite">
        {statusText}
      </span>
    </button>
  );
}
