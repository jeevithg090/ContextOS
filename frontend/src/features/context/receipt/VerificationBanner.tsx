/** Signature verification status of a Context Receipt, re-checked by the server on every read. */
import { ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { TONE_CLASSES, type Tone } from "@/lib/domain";
import { cn, formatDateTime } from "@/lib/format";
import type { ContextReceipt, VerificationStatus } from "../types";

const STATUS: Record<VerificationStatus, { title: string; tone: Tone; Icon: typeof ShieldCheck }> = {
  valid: { title: "Signature valid", tone: "ok", Icon: ShieldCheck },
  invalid: { title: "Signature INVALID — this record was altered after it was signed", tone: "danger", Icon: ShieldAlert },
  missing: { title: "No signature recorded", tone: "warn", Icon: ShieldQuestion },
};

export function VerificationBanner({ receipt }: { receipt: ContextReceipt }) {
  const { status, algorithm, purpose, explanation } = receipt.verification;
  const meta = STATUS[status];
  const tone = TONE_CLASSES[meta.tone];
  return (
    <div role={status === "valid" ? "status" : "alert"} className={cn("flex items-start gap-3 rounded-lg border px-4 py-3", tone.bg, tone.border)}>
      <meta.Icon className={cn("mt-0.5 h-5 w-5 shrink-0", tone.text)} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className={cn("text-[14px] font-semibold", tone.text)}>{meta.title}</div>
        <p className="mt-0.5 text-xs text-fg-muted">{explanation}</p>
        <p className="mt-1.5 text-2xs text-fg-faint">
          {algorithm} keyed with this server’s secret · purpose <span className="font-mono">{purpose}</span> · checked {formatDateTime(receipt.generated_at)}
        </p>
      </div>
    </div>
  );
}
