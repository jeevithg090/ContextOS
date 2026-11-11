/** Create / edit a trust rule, with pattern help and a live dry run against an example identifier.
 * Mount it per rule (key by rule id) so each opening starts from that rule's saved values. */
import { useId, useState } from "react";
import { Button, Checkbox, Dialog, Field, Input, Select, Textarea, TrustBadge, useToast } from "@/components/ui";
import { SegmentedControl } from "@/components/data";
import { TRUST_LEVELS, TRUST_META, type TrustLevel } from "@/lib/domain";
import { errorMessage, useCreateRule, useUpdateRule, validationErrors } from "./api";
import { CapabilityPicker, ContextualTrustNote } from "./components";
import { LEVEL_HELP, SOURCE_TYPE_LABELS, reassessMessage } from "./meta";
import { PATTERN_HELP, draftFromRule, draftProblems, draftToInput, emptyDraft, withLevel, withScope, type RuleDraft } from "./ruleDraft";
import { RuleLiveTest } from "./RuleLiveTest";
import { SOURCE_TYPES, type AppliesTo, type MatchField, type SourceType, type TrustRule } from "./types";

export function RuleDialog({
  rule,
  open,
  canManage,
  onClose,
}: {
  /** null = create a new rule. */
  rule: TrustRule | null;
  open: boolean;
  canManage: boolean;
  onClose: () => void;
}) {
  const toast = useToast();
  const create = useCreateRule();
  const update = useUpdateRule();
  const [draft, setDraft] = useState<RuleDraft>(() => (rule ? draftFromRule(rule) : emptyDraft()));
  const [showProblems, setShowProblems] = useState(false);
  const ids = { name: useId(), description: useId(), pattern: useId(), level: useId(), priority: useId(), type: useId() };
  const mutation = rule ? update : create;

  const change = (next: RuleDraft) => {
    if (mutation.error) mutation.reset();
    setDraft(next);
  };
  const problems = draftProblems(draft);
  const serverErrors = validationErrors(mutation.error);
  const readOnly = !canManage;

  const save = async () => {
    if (problems.length) {
      setShowProblems(true);
      return;
    }
    try {
      const saved = rule ? await update.mutateAsync({ id: rule.id, patch: draftToInput(draft) }) : await create.mutateAsync(draftToInput(draft));
      toast.success(rule ? `Rule “${saved.name}” saved` : `Rule “${saved.name}” created`, reassessMessage(saved.reassessment));
      onClose();
    } catch {
      /* shown inline */
    }
  };

  const help = PATTERN_HELP[draft.match_field];
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && !mutation.isPending && onClose()}
      title={rule ? (readOnly ? `Trust rule “${rule.name}”` : `Edit “${rule.name}”`) : "New trust rule"}
      description="Rules classify sources and destinations whose identifier or domain matches the pattern. Higher priority wins; on a tie the more restrictive level wins."
      className="w-[min(780px,calc(100vw-32px))]"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose} disabled={mutation.isPending}>
            {readOnly ? "Close" : "Cancel"}
          </Button>
          {!readOnly && (
            <Button variant="primary" size="sm" onClick={() => void save()} loading={mutation.isPending}>
              {rule ? "Save rule" : "Create rule"}
            </Button>
          )}
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <fieldset disabled={readOnly || mutation.isPending} className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-[1fr_120px]">
            <Field label="Name" htmlFor={ids.name}>
              <Input id={ids.name} value={draft.name} maxLength={200} onChange={(e) => change({ ...draft, name: e.target.value })} placeholder="e.g. Acme engineering wiki" />
            </Field>
            <Field label="Priority" htmlFor={ids.priority} hint="Higher wins">
              <Input id={ids.priority} inputMode="numeric" value={draft.priority} onChange={(e) => change({ ...draft, priority: e.target.value })} className="num" />
            </Field>
          </div>

          <div className="flex flex-wrap items-end gap-4">
            <div className="space-y-1.5">
              <div className="text-xs font-medium text-fg-muted">Applies to</div>
              <SegmentedControl<AppliesTo>
                aria-label="Applies to"
                value={draft.applies_to}
                onChange={(v) => change(withScope(draft, v))}
                options={[
                  { value: "source", label: "Sources" },
                  { value: "destination", label: "Destinations" },
                  { value: "both", label: "Both" },
                ]}
              />
            </div>
            {draft.applies_to !== "destination" && (
              <Field label="Source type" htmlFor={ids.type}>
                <Select id={ids.type} value={draft.source_type} onChange={(e) => change({ ...draft, source_type: e.target.value as SourceType | "" })} className="!w-48">
                  <option value="">Any type</option>
                  {SOURCE_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {SOURCE_TYPE_LABELS[t]}
                    </option>
                  ))}
                </Select>
              </Field>
            )}
            <div className="space-y-1.5">
              <div className="text-xs font-medium text-fg-muted">Match on</div>
              <SegmentedControl<MatchField>
                aria-label="Match on"
                value={draft.match_field}
                onChange={(v) => change({ ...draft, match_field: v })}
                options={[
                  { value: "domain", label: "Domain" },
                  { value: "identifier", label: "Identifier" },
                ]}
              />
            </div>
          </div>

          <Field label="Pattern" htmlFor={ids.pattern}>
            <Input
              id={ids.pattern}
              value={draft.pattern}
              maxLength={1024}
              onChange={(e) => change({ ...draft, pattern: e.target.value })}
              placeholder={draft.match_field === "domain" ? "*.acme.com" : "github.com/acme/*"}
              className="font-mono text-xs"
              spellCheck={false}
              autoComplete="off"
            />
          </Field>
          <div className="rounded-md border border-border px-3 py-2 text-xs text-fg-muted">
            <p>{help.summary}</p>
            <ul className="mt-1.5 grid gap-1 sm:grid-cols-3">
              {help.examples.map(([pattern, meaning]) => (
                <li key={pattern}>
                  <button
                    type="button"
                    className="font-mono text-2xs text-accent hover:underline disabled:no-underline"
                    onClick={() => change({ ...draft, pattern })}
                    title="Use this pattern"
                  >
                    {pattern}
                  </button>
                  <span className="block text-2xs text-fg-faint">{meaning}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="grid gap-3 sm:grid-cols-[200px_1fr]">
            <Field label="Trust level" htmlFor={ids.level}>
              <Select id={ids.level} value={draft.trust_level} onChange={(e) => change(withLevel(draft, e.target.value as TrustLevel))}>
                {TRUST_LEVELS.map((l) => (
                  <option key={l} value={l}>
                    {TRUST_META[l].label}
                  </option>
                ))}
              </Select>
            </Field>
            <div className="flex items-end gap-2 pb-1.5 text-xs text-fg-muted">
              <TrustBadge level={draft.trust_level} />
              <span>{LEVEL_HELP[draft.trust_level]}</span>
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="text-xs font-medium text-fg-muted">Capabilities granted</div>
            <CapabilityPicker level={draft.trust_level} appliesTo={draft.applies_to} value={draft.capabilities} onChange={(caps) => change({ ...draft, capabilities: caps })} />
            {draft.applies_to !== "destination" && <ContextualTrustNote />}
          </div>

          <Field label="Description" htmlFor={ids.description} hint="Shown to everyone who reviews this rule. Explain why it is safe.">
            <Textarea id={ids.description} value={draft.description} maxLength={2000} onChange={(e) => change({ ...draft, description: e.target.value })} className="min-h-[56px]" />
          </Field>
          <Checkbox label="Enabled" checked={draft.enabled} onChange={(v) => change({ ...draft, enabled: v })} disabled={readOnly} />
        </fieldset>

        <RuleLiveTest draft={draft} ruleId={rule?.id ?? null} />

        {(showProblems && problems.length > 0) || serverErrors.length > 0 || (mutation.error && !serverErrors.length) ? (
          <div role="alert" className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            <ul className="list-disc space-y-0.5 pl-4">
              {(serverErrors.length ? serverErrors : showProblems && problems.length ? problems : [errorMessage(mutation.error)]).map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </div>
        ) : null}
      </form>
    </Dialog>
  );
}
