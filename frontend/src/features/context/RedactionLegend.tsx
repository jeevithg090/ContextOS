/** Explains the redaction markers in a preview and which secret types were removed. */
import { EyeOff } from "lucide-react";
import { RedactionMarker } from "@/components/data";
import { humanize } from "@/lib/domain";
import { pluralize } from "@/lib/format";

export function RedactionLegend({ secretTypes, fingerprintCount, previewStored }: { secretTypes: Array<{ type: string; count: number }>; fingerprintCount: number; previewStored: boolean }) {
  return (
    <div className="rounded-md border border-border bg-surface-2/40 px-3 py-2.5 text-xs text-fg-muted">
      <div className="flex items-start gap-2">
        <EyeOff className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
        <div className="min-w-0 space-y-1.5">
          <p>
            {previewStored ? "This preview was redacted before it was stored. " : ""}
            Every detected secret is replaced by a marker such as <RedactionMarker text="[REDACTED:github_token:1a2b3c4d]" /> — the secret type and the first
            characters of a keyed fingerprint. The original value is never stored, so it cannot be shown here.
          </p>
          {fingerprintCount > 0 ? (
            <p>
              <span className="text-fg">{pluralize(fingerprintCount, "secret")}</span> fingerprinted:{" "}
              {secretTypes.map((s, i) => (
                <span key={s.type}>
                  {i > 0 && ", "}
                  <span className="text-fg">{humanize(s.type)}</span>
                  {s.count > 1 && <span className="num"> ×{s.count}</span>}
                </span>
              ))}
              . Fingerprints let ContextOS recognise the same secret if it later appears in an outbound tool call.
            </p>
          ) : (
            <p>No secrets were detected in this content.</p>
          )}
        </div>
      </div>
    </div>
  );
}
