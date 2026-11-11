import { useMemo, type FormEvent, type ReactNode } from "react";
import { Check, Fingerprint, Hash, KeyRound, Radio, ScrollText, ShieldOff, TextQuote } from "lucide-react";
import { Section } from "@/components/data";
import { Checkbox, Input, useToast } from "@/components/ui";
import { useUpdateOrgSettings, type Org } from "./api";
import { RetentionScope } from "./RetentionScope";
import { AdminOnlyNotice, SaveBar, SettingRow } from "./SettingsControls";
import { useSettingsDraft } from "./useSettingsDraft";

const RETENTION_MIN = 1;
const RETENTION_MAX = 3650;

interface Draft extends Record<string, unknown> {
  retention_days: number;
  store_previews: boolean;
}

const STORED: Array<{ icon: ReactNode; title: string; body: ReactNode }> = [
  {
    icon: <TextQuote className="h-4 w-4" />,
    title: "Redacted previews",
    body: (
      <>
        A short, truncated preview of each piece of context and each tool call&apos;s result, after secret redaction. Tool-call arguments are
        always kept in redacted form, because policy decisions, approvals and replay evaluate them. Recognised secrets are replaced with
        markers of the form <code className="font-mono text-fg">[REDACTED:type:fingerprint]</code>. Redaction is pattern-based, so unusual
        secret formats can slip through — treat previews and arguments as sensitive.
      </>
    ),
  },
  {
    icon: <Hash className="h-4 w-4" />,
    title: "Content hashes",
    body: "A SHA-256 hash of the full original content. It proves what an agent saw (context receipts) and spots repeated content without keeping the content itself.",
  },
  {
    icon: <Fingerprint className="h-4 w-4" />,
    title: "Secret fingerprints",
    body: "A keyed HMAC of each detected secret (16 hex characters, keyed with this server's secret). It lets ContextOS recognise the same credential leaving in a later tool call. It cannot be reversed into the secret.",
  },
  {
    icon: <ScrollText className="h-4 w-4" />,
    title: "Metadata and security results",
    body: "Sources, trust classifications, sessions, tool names, policy decisions with their redacted inputs, findings, incidents and approvals.",
  },
  {
    icon: <KeyRound className="h-4 w-4" />,
    title: "Credentials as hashes only",
    body: "Passwords are stored as scrypt hashes; API keys and session tokens as SHA-256 hashes. A new API key is displayed once and cannot be retrieved later.",
  },
  {
    icon: <Radio className="h-4 w-4" />,
    title: "Audit trail and live updates",
    body: "Administrative and security actions are written to a keyed, hash-chained audit log with redacted details. Live browser updates carry record ids only, never content.",
  },
];

const NEVER: string[] = [
  "Raw secrets detected in context or tool calls",
  "Full raw context content — only the redacted, truncated preview",
  "Plaintext passwords, API keys or session tokens",
];

export function PrivacyTab({ org, canAdmin }: { org: Org; canAdmin: boolean }) {
  const toast = useToast();
  const update = useUpdateOrgSettings();
  const source = useMemo<Draft>(() => ({ retention_days: org.settings.retention_days, store_previews: org.settings.store_previews }), [org]);
  const { draft, dirty, changes, set, reset } = useSettingsDraft(source);
  const values = draft ?? source;

  const retentionError =
    Number.isInteger(values.retention_days) && values.retention_days >= RETENTION_MIN && values.retention_days <= RETENTION_MAX
      ? null
      : `Enter a whole number of days between ${RETENTION_MIN} and ${RETENTION_MAX}.`;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!dirty || retentionError) return;
    update.mutate(changes, { onSuccess: () => toast.success("Data settings saved") });
  };

  return (
    <div className="space-y-5">
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Section title="What ContextOS stores" description="Content passes through secret redaction before anything is written to the database, logs, audit details, live updates or exports.">
          <ul className="grid gap-x-6 gap-y-4 md:grid-cols-2">
            {STORED.map((item) => (
              <li key={item.title} className="flex min-w-0 gap-3">
                <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded border border-border bg-surface-2 text-fg-muted" aria-hidden>
                  {item.icon}
                </span>
                <div className="min-w-0">
                  <div className="text-[13px] font-medium text-fg">{item.title}</div>
                  <p className="mt-0.5 text-xs leading-relaxed text-fg-muted">{item.body}</p>
                </div>
              </li>
            ))}
          </ul>
        </Section>

        <Section title="Never stored" description="By design, not by configuration.">
          <ul className="space-y-2.5">
            {NEVER.map((line) => (
              <li key={line} className="flex gap-2 text-[13px] text-fg">
                <ShieldOff className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ok" aria-hidden />
                {line}
              </li>
            ))}
          </ul>
          <p className="mt-4 flex gap-2 border-t border-border pt-3 text-xs text-fg-muted">
            <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
            Rotating the server secret (CONTEXTOS_SECRET_KEY) invalidates existing fingerprints, receipts and the audit chain anchor.
          </p>
        </Section>
      </div>

      <form onSubmit={submit} className="space-y-5" aria-label="Data settings">
        {!canAdmin && <AdminOnlyNotice />}
        <Section title="Retention and previews" description="Organisation-wide data settings.">
          <fieldset disabled={!canAdmin} className="min-w-0 divide-y divide-border">
            <legend className="sr-only">Retention and previews</legend>
            <SettingRow
              title="Retention period"
              htmlFor="retention-days"
              description="How long recorded events, context, tool calls and decisions are kept. Older data is deleted the next time the purge command runs — see below for exactly what it removes."
            >
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative w-36">
                  <Input
                    id="retention-days"
                    type="number"
                    inputMode="numeric"
                    min={RETENTION_MIN}
                    max={RETENTION_MAX}
                    step={1}
                    value={Number.isNaN(values.retention_days) ? "" : values.retention_days}
                    onChange={(e) => set("retention_days", e.target.value === "" ? Number.NaN : Number(e.target.value))}
                    aria-invalid={!!retentionError}
                    aria-describedby="retention-hint"
                    className="pr-12"
                  />
                  <span className="pointer-events-none absolute inset-y-0 right-2.5 flex items-center text-xs text-fg-faint">days</span>
                </div>
                <span id="retention-hint" className={retentionError ? "text-2xs text-danger" : "text-xs text-fg-muted"}>
                  {retentionError ?? `≈ ${(values.retention_days / 30.44).toFixed(values.retention_days < 61 ? 1 : 0)} months`}
                </span>
              </div>
            </SettingRow>
            <div className="py-4">
              <RetentionScope days={retentionError ? null : values.retention_days} />
            </div>
            <SettingRow
              title="Store redacted previews"
              description="When off, new context and tool results are recorded without preview text — as hashes, fingerprints and metadata only. Redacted tool-call arguments are still kept, because policy decisions, approvals and replay need them. Existing previews are not removed."
            >
              <Checkbox
                label={values.store_previews ? "Previews are stored" : "Previews are not stored"}
                checked={values.store_previews}
                onChange={(on) => set("store_previews", on)}
                disabled={!canAdmin}
              />
            </SettingRow>
          </fieldset>
        </Section>
        {canAdmin && (
          <SaveBar dirty={dirty} saving={update.isPending} error={update.error?.message ?? null} onReset={reset} invalid={!!retentionError} />
        )}
      </form>
    </div>
  );
}
