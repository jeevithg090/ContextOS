import { Fragment } from "react";
import { Tooltip, TooltipProvider } from "@/components/ui";
import { cn } from "@/lib/format";

/** Marker format written by backend/app/engines/redaction, e.g. "[REDACTED:aws_access_key]". */
export const REDACTION_PREFIX = "[REDACTED:";
const REDACTION_PATTERN = /\[REDACTED:[^\]\s]{0,64}\]/g;
export const REDACTION_EXPLANATION = "Redacted by ContextOS before storage";

export function isRedactedValue(value: unknown): value is string {
  return typeof value === "string" && value.startsWith(REDACTION_PREFIX);
}

/** One redaction marker, styled distinctly so nobody mistakes it for the original value. */
export function RedactionMarker({ text, className }: { text: string; className?: string }) {
  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip content={REDACTION_EXPLANATION}>
        <span
          tabIndex={0}
          data-redacted="true"
          className={cn(
            "rounded-sm border border-dashed border-border-strong bg-surface-3/70 px-1 font-mono italic text-fg-faint",
            className,
          )}
        >
          {text}
        </span>
      </Tooltip>
    </TooltipProvider>
  );
}

/** Plain text with every embedded redaction marker highlighted. Never interprets HTML. */
export function RedactedText({ text }: { text: string }) {
  const parts: Array<{ marker: boolean; value: string }> = [];
  let last = 0;
  for (const match of text.matchAll(REDACTION_PATTERN)) {
    const start = match.index ?? 0;
    if (start > last) parts.push({ marker: false, value: text.slice(last, start) });
    parts.push({ marker: true, value: match[0] });
    last = start + match[0].length;
  }
  if (last < text.length) parts.push({ marker: false, value: text.slice(last) });
  if (parts.length === 0) return null;
  return (
    <>
      {parts.map((part, i) => (part.marker ? <RedactionMarker key={i} text={part.value} /> : <Fragment key={i}>{part.value}</Fragment>))}
    </>
  );
}
