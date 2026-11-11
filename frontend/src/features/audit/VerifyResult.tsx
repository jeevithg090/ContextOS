import { ShieldAlert, ShieldCheck, X } from "lucide-react";
import { CopyButton } from "@/components/data";
import { IconButton, Mono } from "@/components/ui";
import { cn, formatDateTime, formatNumber } from "@/lib/format";
import type { AuditVerifyResult } from "./types";

function ThreatModel({ result }: { result: AuditVerifyResult }) {
  const tm = result.threat_model;
  return (
    <details className="group mt-3 rounded border border-border bg-surface/60">
      <summary className="cursor-pointer select-none px-3 py-2 text-xs font-medium text-fg-muted hover:text-fg">
        What this verification proves — and what it cannot
      </summary>
      <div className="grid gap-4 border-t border-border px-3 py-3 text-xs leading-5 md:grid-cols-2">
        <div>
          <div className="label-caps mb-1.5">Detects</div>
          <ul className="list-disc space-y-1 pl-4 text-fg-muted marker:text-fg-faint">
            {tm.detects.map((d) => (
              <li key={d}>{d}</li>
            ))}
          </ul>
        </div>
        <div>
          <div className="label-caps mb-1.5">Does not protect against</div>
          <ul className="list-disc space-y-1 pl-4 text-fg-muted marker:text-fg-faint">
            {tm.does_not_protect_against.map((d) => (
              <li key={d}>{d}</li>
            ))}
          </ul>
        </div>
        <div className="md:col-span-2">
          <div className="label-caps mb-1.5">Anchoring the head hash</div>
          <p className="text-fg-muted">{tm.anchoring}</p>
        </div>
      </div>
    </details>
  );
}

/** Result of GET /audit/verify: intact (with head hash to anchor) or the first broken entry and why. */
export function VerifyResult({ result, onDismiss }: { result: AuditVerifyResult; onDismiss: () => void }) {
  const ok = result.valid;
  const Icon = ok ? ShieldCheck : ShieldAlert;
  return (
    <section
      role={ok ? "status" : "alert"}
      aria-label="Audit chain verification result"
      className={cn("mb-4 rounded-md border px-4 py-3", ok ? "border-ok/30 bg-ok/5" : "border-danger/40 bg-danger/5")}
    >
      <div className="flex items-start gap-3">
        <Icon className={cn("mt-0.5 h-5 w-5 shrink-0", ok ? "text-ok" : "text-danger")} aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
            <h2 className={cn("text-[13px] font-semibold", ok ? "text-ok" : "text-danger")}>
              {ok
                ? result.checked
                  ? `Chain intact — ${formatNumber(result.checked)} ${result.checked === 1 ? "entry" : "entries"} verified`
                  : "No entries to verify yet"
                : `Tampering detected at entry #${result.first_invalid_seq}`}
            </h2>
            <span className="text-2xs text-fg-faint">Verified {formatDateTime(result.verified_at)}</span>
          </div>
          <p className="mt-1 text-xs leading-5 text-fg">{result.summary}</p>
          {!ok && (
            <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
              <dt className="text-fg-faint">Check that failed</dt>
              <dd className="font-mono text-fg-muted">{result.reason}</dd>
              {result.first_invalid_entry_id && (
                <>
                  <dt className="text-fg-faint">Entry</dt>
                  <dd className="flex items-center gap-1">
                    <Mono>{result.first_invalid_entry_id}</Mono>
                    <CopyButton size="xs" value={result.first_invalid_entry_id} label="Copy entry id" />
                  </dd>
                </>
              )}
              <dt className="text-fg-faint">Entries checked</dt>
              <dd className="num text-fg-muted">{formatNumber(result.checked)}</dd>
            </dl>
          )}
          {result.head_hash && (
            <div className="mt-2 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-xs">
              <span className="text-fg-faint">Head #{result.head_seq}</span>
              <Mono className="min-w-0 truncate" title={result.head_hash}>
                {result.head_hash}
              </Mono>
              <CopyButton size="xs" value={`seq=${result.head_seq} hash=${result.head_hash}`} label="Copy head sequence and hash" />
            </div>
          )}
          <ThreatModel result={result} />
        </div>
        <IconButton label="Dismiss verification result" onClick={onDismiss} className="-mr-1 -mt-1">
          <X className="h-4 w-4" aria-hidden />
        </IconButton>
      </div>
    </section>
  );
}
