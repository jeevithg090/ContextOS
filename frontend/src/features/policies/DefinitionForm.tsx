/** Policy definition: identity, outcome, mode, ordering, conditions and (for RESTRICT) restrictions. */
import { useId, type ReactNode } from "react";
import { Field, Input, Select, Skeleton, Textarea } from "@/components/ui";
import { SegmentedControl } from "@/components/data";
import { DECISIONS, DECISION_META, SEVERITIES, SEVERITY_META, type Decision, type Severity } from "@/lib/domain";
import { ConditionBuilder } from "./ConditionBuilder";
import { ChipListInput, Switch } from "./controls";
import type { PolicyDraft } from "./draft";
import { RestrictionsEditor } from "./RestrictionsEditor";
import type { FieldSpec, OperatorSpec, PolicyMode, ValidationResult } from "./types";

export const OUTCOME_HELP: Record<Decision, string> = {
  DENY: "Block the call where the integration enforces decisions.",
  REQUIRE_APPROVAL: "Pause the call until a person approves it.",
  RESTRICT: "Let the call run only with constraints applied.",
  AUDIT: "Let the call run and flag it for review.",
  ALLOW: "Explicitly allow. Lowest precedence: any other matching outcome wins.",
};

export const MODE_HELP: Record<PolicyMode, string> = {
  enforce: "Decisions are returned to the integration and enforced where it supports enforcement.",
  monitor: "Matches are recorded only (dry run). The decision returned to the agent never changes.",
};

export interface ValidationState {
  data: ValidationResult | undefined;
  loading: boolean;
  error: unknown;
  syntaxError: string | null;
}

export function PlainEnglishPreview({ validation, outcome, mode }: { validation: ValidationState; outcome: Decision; mode: PolicyMode }) {
  let body: ReactNode;
  if (validation.syntaxError) {
    body = <p className="text-xs text-danger">Fix the JSON syntax error to see what this policy matches.</p>;
  } else if (validation.error) {
    body = <p className="text-xs text-danger">Couldn’t validate the conditions: {validation.error instanceof Error ? validation.error.message : "request failed"}</p>;
  } else if (!validation.data) {
    body = <Skeleton className="h-4 w-2/3" />;
  } else if (validation.data.valid) {
    body = (
      <p className="text-[13px] leading-relaxed text-fg">
        <span className="text-fg-muted">When </span>
        <span className="font-mono text-xs">{validation.data.explanation}</span>
        <span className="text-fg-muted"> → </span>
        <span className="font-medium">{DECISION_META[outcome].label}</span>
        <span className="text-fg-muted">{mode === "monitor" ? " (recorded only — monitor mode)" : ""}</span>
      </p>
    );
  } else {
    body = (
      <ul className="space-y-1" aria-label="Validation errors">
        {validation.data.errors.map((e) => (
          <li key={e} className="font-mono text-2xs leading-relaxed text-danger">
            {e}
          </li>
        ))}
      </ul>
    );
  }
  return (
    <div aria-live="polite" className="rounded-md border border-border bg-surface-2/60 px-3 py-2.5">
      <div className="label-caps mb-1.5 flex items-center gap-2">
        Plain-English preview
        {validation.loading && validation.data && <span className="normal-case tracking-normal text-fg-faint">checking…</span>}
      </div>
      {body}
    </div>
  );
}

export function DefinitionForm({
  draft,
  onChange,
  catalog,
  operators,
  validation,
  readOnly,
  onOpenJson,
}: {
  draft: PolicyDraft;
  onChange: (patch: Partial<PolicyDraft>) => void;
  catalog: FieldSpec[];
  operators: OperatorSpec[];
  validation: ValidationState;
  readOnly?: boolean;
  onOpenJson: () => void;
}) {
  const ids = { name: useId(), description: useId(), outcome: useId(), priority: useId(), severity: useId(), tags: useId() };
  return (
    <div className="space-y-5 p-5">
      <div className="grid gap-4 sm:grid-cols-[1fr_auto]">
        <Field label="Name" htmlFor={ids.name}>
          <Input id={ids.name} value={draft.name} maxLength={200} readOnly={readOnly} onChange={(e) => onChange({ name: e.target.value })} placeholder="e.g. Require approval for production deploys" />
        </Field>
        <div className="space-y-1.5">
          <span className="block text-xs font-medium text-fg-muted">Enabled</span>
          <div className="flex h-8 items-center gap-2">
            <Switch checked={draft.enabled} disabled={readOnly} label="Policy enabled" onCheckedChange={(enabled) => onChange({ enabled })} />
            <span className="text-xs text-fg-muted">{draft.enabled ? "Evaluated on every tool call" : "Not evaluated"}</span>
          </div>
        </div>
      </div>
      <Field label="Description" htmlFor={ids.description} hint="What threat this addresses and why the outcome is right. Shown to investigators.">
        <Textarea id={ids.description} value={draft.description} readOnly={readOnly} maxLength={4000} onChange={(e) => onChange({ description: e.target.value })} />
      </Field>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Outcome" htmlFor={ids.outcome} hint={OUTCOME_HELP[draft.outcome]}>
          <Select id={ids.outcome} value={draft.outcome} disabled={readOnly} onChange={(e) => onChange({ outcome: e.target.value as Decision })}>
            {DECISIONS.map((d) => (
              <option key={d} value={d}>
                {DECISION_META[d].label}
              </option>
            ))}
          </Select>
        </Field>
        <div className="space-y-1.5">
          <span className="block text-xs font-medium text-fg-muted">Mode</span>
          <SegmentedControl<PolicyMode>
            aria-label="Policy mode"
            size="md"
            value={draft.mode}
            onChange={(mode) => !readOnly && onChange({ mode })}
            options={[
              { value: "enforce", label: "Enforce", disabled: readOnly && draft.mode !== "enforce" },
              { value: "monitor", label: "Monitor (dry run)", disabled: readOnly && draft.mode !== "monitor" },
            ]}
          />
          <p className="text-2xs text-fg-faint">{MODE_HELP[draft.mode]}</p>
        </div>
        <Field label="Priority" htmlFor={ids.priority} hint="Breaks ties between matching policies with the same outcome. Higher wins.">
          <Input id={ids.priority} type="number" min={0} max={100000} readOnly={readOnly} value={draft.priority} onChange={(e) => onChange({ priority: Math.trunc(Number(e.target.value) || 0) })} />
        </Field>
        <Field label="Severity" htmlFor={ids.severity} hint="How serious a match is; used for findings and triage ordering.">
          <Select id={ids.severity} value={draft.severity} disabled={readOnly} onChange={(e) => onChange({ severity: e.target.value as Severity })}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_META[s].label}
              </option>
            ))}
          </Select>
        </Field>
      </div>

      <section aria-labelledby={`${ids.name}-conditions`} className="space-y-3">
        <div>
          <h3 id={`${ids.name}-conditions`} className="text-[13px] font-semibold text-fg">
            Conditions
          </h3>
          <p className="mt-0.5 text-xs text-fg-muted">Evaluated against the redacted tool request and the session’s recorded risk and context. A missing field never matches.</p>
        </div>
        <ConditionBuilder conditions={draft.conditions} onChange={(conditions) => onChange({ conditions })} catalog={catalog} operators={operators} readOnly={readOnly} onUnsupported={onOpenJson} />
        <PlainEnglishPreview validation={validation} outcome={draft.outcome} mode={draft.mode} />
      </section>

      {draft.outcome === "RESTRICT" && (
        <section aria-label="Restrictions" className="space-y-2">
          <h3 className="text-[13px] font-semibold text-fg">Restrictions</h3>
          <RestrictionsEditor restrictions={draft.restrictions} onChange={(restrictions) => onChange({ restrictions })} readOnly={readOnly} />
        </section>
      )}

      <Field label="Tags" htmlFor={ids.tags} hint="Lower-case labels for filtering, e.g. exfiltration, shell.">
        <ChipListInput id={ids.tags} label="Tags" values={draft.tags} disabled={readOnly} onChange={(tags) => onChange({ tags: tags.map((t) => t.toLowerCase()) })} placeholder="Add a tag, Enter to confirm" />
      </Field>
    </div>
  );
}
