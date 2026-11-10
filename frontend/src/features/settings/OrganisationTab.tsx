import { useMemo, type FormEvent } from "react";
import { CopyButton, Section } from "@/components/data";
import { DecisionBadge, Input, KeyValue, Mono, useToast } from "@/components/ui";
import { formatDateTime, pluralize } from "@/lib/format";
import { useUpdateOrgSettings, type DefaultDecision, type FailMode, type Org } from "./api";
import { DEFAULT_DECISION_META, FAIL_MODE_META, FAIL_MODE_ORDER, formatDuration } from "./meta";
import { AdminOnlyNotice, ChoiceCards, SaveBar, SettingRow } from "./SettingsControls";
import { useSettingsDraft } from "./useSettingsDraft";

const TIMEOUT_MIN = 30;
const TIMEOUT_MAX = 86_400;

interface Draft extends Record<string, unknown> {
  name: string;
  fail_mode: FailMode;
  default_decision: DefaultDecision;
  approval_timeout_s: number;
}

export function OrganisationTab({ org, canAdmin, onShowTab }: { org: Org; canAdmin: boolean; onShowTab: (tab: string) => void }) {
  const toast = useToast();
  const update = useUpdateOrgSettings();
  const source = useMemo<Draft>(
    () => ({
      name: org.name,
      fail_mode: org.settings.fail_mode,
      default_decision: org.settings.default_decision,
      approval_timeout_s: org.settings.approval_timeout_s,
    }),
    [org],
  );
  const { draft, dirty, changes, set, reset } = useSettingsDraft(source);
  const values = draft ?? source;

  const nameError = values.name.trim() ? null : "The organisation needs a name.";
  const timeoutError =
    Number.isInteger(values.approval_timeout_s) && values.approval_timeout_s >= TIMEOUT_MIN && values.approval_timeout_s <= TIMEOUT_MAX
      ? null
      : `Enter a whole number of seconds between ${TIMEOUT_MIN} and ${TIMEOUT_MAX}.`;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!dirty || nameError || timeoutError) return;
    const patch = { ...changes, ...(changes.name !== undefined ? { name: values.name.trim() } : {}) };
    update.mutate(patch, {
      onSuccess: () => toast.success("Organisation settings saved"),
    });
  };

  const error = update.error instanceof Error ? update.error.message : null;

  return (
    <form onSubmit={submit} className="space-y-5" aria-label="Organisation settings">
      {!canAdmin && <AdminOnlyNotice />}

      <Section title="Organisation" description="Identity of this tenant. Every record ContextOS stores belongs to exactly one organisation.">
        <fieldset disabled={!canAdmin} className="min-w-0">
          <legend className="sr-only">Organisation details</legend>
          <SettingRow title="Name" htmlFor="org-name" description="Shown in the header and in exported evidence.">
            <Input
              id="org-name"
              value={values.name}
              maxLength={200}
              onChange={(e) => set("name", e.target.value)}
              aria-invalid={!!nameError}
              aria-describedby={nameError ? "org-name-error" : undefined}
              className="max-w-md"
            />
            {nameError && (
              <p id="org-name-error" className="mt-1.5 text-2xs text-danger">
                {nameError}
              </p>
            )}
          </SettingRow>
        </fieldset>
        <div className="mt-4 border-t border-border pt-4">
          <KeyValue
            items={[
              {
                label: "Slug",
                value: (
                  <span className="inline-flex items-center gap-1">
                    <Mono>{org.slug}</Mono>
                    <CopyButton value={org.slug} label="Copy organisation slug" size="xs" />
                  </span>
                ),
              },
              {
                label: "Organisation ID",
                value: (
                  <span className="inline-flex items-center gap-1">
                    <Mono>{org.id}</Mono>
                    <CopyButton value={org.id} label="Copy organisation ID" size="xs" />
                  </span>
                ),
              },
              { label: "Created", value: formatDateTime(org.created_at) },
              {
                label: "Members",
                value: (
                  <button type="button" className="text-accent hover:underline" onClick={() => onShowTab("members")}>
                    {pluralize(org.member_count, "member")}
                  </button>
                ),
              },
              {
                label: "Active API keys",
                value: canAdmin ? (
                  <button type="button" className="text-accent hover:underline" onClick={() => onShowTab("api-keys")}>
                    {pluralize(org.active_api_key_count, "key")}
                  </button>
                ) : (
                  pluralize(org.active_api_key_count, "key")
                ),
              },
            ]}
          />
        </div>
      </Section>

      <Section
        title="Enforcement defaults"
        description="How decisions behave when no policy matches, when a human must approve, and when ContextOS cannot be reached."
        flush
      >
        <fieldset disabled={!canAdmin} className="min-w-0 divide-y divide-border px-4 py-4">
          <legend className="sr-only">Enforcement defaults</legend>
          <SettingRow
            title="Fail mode"
            description={
              <>
                What an integration does when it cannot reach ContextOS for a decision. Each integration applies this
                locally — ContextOS cannot answer while it is unreachable — and generated integration setup uses this
                value as its default.
              </>
            }
          >
            <ChoiceCards
              name="fail_mode"
              legend="Fail mode"
              value={values.fail_mode}
              onChange={(v) => set("fail_mode", v)}
              options={FAIL_MODE_ORDER.map((mode) => ({ value: mode, label: FAIL_MODE_META[mode].label, description: FAIL_MODE_META[mode].description }))}
            />
          </SettingRow>
          <SettingRow
            title="When no policy matches"
            description="The decision returned for a tool call that no enabled policy matches. Monitor-mode policies never change it."
          >
            <ChoiceCards
              name="default_decision"
              legend="Default decision"
              columns={2}
              value={values.default_decision}
              onChange={(v) => set("default_decision", v)}
              options={(["ALLOW", "AUDIT"] as const).map((d) => ({
                value: d,
                label: d === "ALLOW" ? "Allow" : "Allow and audit",
                badge: <DecisionBadge decision={d} />,
                description: DEFAULT_DECISION_META[d].description,
              }))}
            />
          </SettingRow>
          <SettingRow
            title="Approval timeout"
            htmlFor="approval-timeout"
            description="How long a tool call that needs approval waits for a human decision before the request expires."
          >
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative w-40">
                <Input
                  id="approval-timeout"
                  type="number"
                  inputMode="numeric"
                  min={TIMEOUT_MIN}
                  max={TIMEOUT_MAX}
                  step={1}
                  value={Number.isNaN(values.approval_timeout_s) ? "" : values.approval_timeout_s}
                  onChange={(e) => set("approval_timeout_s", e.target.value === "" ? Number.NaN : Number(e.target.value))}
                  aria-invalid={!!timeoutError}
                  aria-describedby="approval-timeout-hint"
                  className="pr-16"
                />
                <span className="pointer-events-none absolute inset-y-0 right-2.5 flex items-center text-xs text-fg-faint">seconds</span>
              </div>
              <span id="approval-timeout-hint" className={timeoutError ? "text-2xs text-danger" : "text-xs text-fg-muted"}>
                {timeoutError ?? `= ${formatDuration(values.approval_timeout_s)}`}
              </span>
            </div>
          </SettingRow>
        </fieldset>
      </Section>

      {canAdmin && <SaveBar dirty={dirty} saving={update.isPending} error={error} onReset={reset} invalid={!!nameError || !!timeoutError} />}
    </form>
  );
}
