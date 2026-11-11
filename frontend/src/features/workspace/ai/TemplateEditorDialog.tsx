import { useEffect, useId, useState, type FormEvent } from "react";
import { Button, Dialog, Field, Input, Select, Textarea, useToast } from "@/components/ui";
import { useAiCatalogue, useCreateTemplate, useUpdateTemplate } from "./api";
import { mutationMessage } from "./hooks";
import { ModeAccess } from "./ModeCards";
import { defaultOptions, effectiveOptions, MAX_OVERRIDE_CHARS, presetLine } from "./meta";
import { OptionsFields } from "./OptionsFields";
import type { AgentPreset, GenerationOptions, PromptMode, PromptTemplate } from "./types";

export interface TemplateDraft {
  name: string;
  description: string;
  mode: PromptMode;
  preset: AgentPreset;
  options: GenerationOptions;
  section_overrides: Record<string, string>;
}

export function templateDraftFrom(template: PromptTemplate, overrides: Partial<TemplateDraft> = {}): TemplateDraft {
  return {
    name: template.name,
    description: template.description ?? "",
    mode: template.mode,
    preset: template.preset,
    options: { ...template.options, constraints: [...template.options.constraints] },
    section_overrides: { ...template.section_overrides },
    ...overrides,
  };
}

/**
 * Create or edit an organisation prompt template: name, description, mode, agent preset, generation
 * options and extra instructions per section. Built-in templates are never edited here (read-only).
 */
export function TemplateEditorDialog({
  open,
  onOpenChange,
  initial,
  templateId,
  title,
  description,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Starting values; `null` starts from the catalogue defaults. */
  initial: TemplateDraft | null;
  /** Set to edit an existing organisation template. */
  templateId?: string;
  title: string;
  description?: string;
  onSaved?: (template: PromptTemplate) => void;
}) {
  const id = useId();
  const toast = useToast();
  const catalogue = useAiCatalogue();
  const create = useCreateTemplate();
  const update = useUpdateTemplate();
  const [draft, setDraft] = useState<TemplateDraft | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);
    setDraft(
      initial ?? {
        name: "",
        description: "",
        mode: "implement_fix",
        preset: "generic",
        options: defaultOptions(catalogue.data),
        section_overrides: {},
      },
    );
    // Reset only when the dialog opens; the catalogue fills defaults if it arrives later.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const modes = catalogue.data?.modes ?? [];
  const presets = catalogue.data?.presets ?? [];
  const sections = catalogue.data?.sections ?? [];
  const mode = modes.find((m) => m.key === draft?.mode);
  const preset = presets.find((p) => p.key === draft?.preset);
  const pending = create.isPending || update.isPending;
  const overrideCount = Object.values(draft?.section_overrides ?? {}).filter((v) => v.trim()).length;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!draft) return;
    const name = draft.name.trim();
    if (!name) return setError("Give the template a name.");
    const body = {
      name,
      description: draft.description.trim() || null,
      mode: draft.mode,
      preset: draft.preset,
      // Stored as chosen; read-only modes ignore the change toggles when the template is used.
      options: effectiveOptions(draft.options, undefined),
      section_overrides: Object.fromEntries(Object.entries(draft.section_overrides).map(([k, v]) => [k, v.trim()]).filter(([, v]) => v)),
    };
    const done = (template: PromptTemplate) => {
      toast.success(templateId ? "Template updated" : "Template created", template.name);
      onSaved?.(template);
      onOpenChange(false);
    };
    const fail = (err: unknown) => setError(mutationMessage(err));
    if (templateId) update.mutate({ templateId, patch: body }, { onSuccess: done, onError: fail });
    else create.mutate(body, { onSuccess: done, onError: fail });
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !pending && onOpenChange(next)}
      title={title}
      description={description ?? "Organisation templates are shared with everyone in your organisation."}
      className="w-[min(760px,calc(100vw-32px))]"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={pending}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form={`${id}-form`} loading={pending} disabled={!draft}>
            {templateId ? "Save changes" : "Create template"}
          </Button>
        </>
      }
    >
      {draft && (
        <form id={`${id}-form`} onSubmit={submit} className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" htmlFor={`${id}-name`}>
              <Input id={`${id}-name`} value={draft.name} maxLength={200} autoFocus onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="e.g. Security fix with strict tests" />
            </Field>
            <Field label="Mode" htmlFor={`${id}-mode`} hint={mode ? <ModeAccess mayModify={mode.may_modify_files} /> : undefined}>
              <Select id={`${id}-mode`} value={draft.mode} onChange={(e) => setDraft({ ...draft, mode: e.target.value as PromptMode })}>
                {modes.map((m) => (
                  <option key={m.key} value={m.key}>
                    {m.label}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <Field label="Description" htmlFor={`${id}-desc`} hint="Optional. When should someone use this template?">
            <Textarea id={`${id}-desc`} value={draft.description} maxLength={2000} className="min-h-[56px] text-xs" onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
          </Field>
          <Field label="Coding agent" htmlFor={`${id}-preset`} hint={preset ? presetLine(preset) : undefined}>
            <Select id={`${id}-preset`} value={draft.preset} onChange={(e) => setDraft({ ...draft, preset: e.target.value as AgentPreset })}>
              {presets.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.label}
                </option>
              ))}
            </Select>
          </Field>

          <fieldset className="space-y-3">
            <legend className="label-caps pb-1">Generation options</legend>
            <OptionsFields catalogue={catalogue.data} mode={mode} options={draft.options} onChange={(patch) => setDraft({ ...draft, options: { ...draft.options, ...patch } })} />
          </fieldset>

          <details className="group rounded-md border border-border" open={overrideCount > 0}>
            <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-xs font-medium text-fg">
              Extra instructions per section
              <span className="text-2xs font-normal text-fg-faint">{overrideCount ? `${overrideCount} set` : "None set"}</span>
            </summary>
            <div className="space-y-3 border-t border-border px-3 py-3">
              <p className="text-2xs text-fg-muted">Appended to that section whenever this template generates a prompt (up to {MAX_OVERRIDE_CHARS} characters each).</p>
              {sections.map((s) => (
                <Field key={s.key} label={s.title} htmlFor={`${id}-ov-${s.key}`}>
                  <Textarea
                    id={`${id}-ov-${s.key}`}
                    value={draft.section_overrides[s.key] ?? ""}
                    maxLength={MAX_OVERRIDE_CHARS}
                    className="min-h-[44px] text-xs"
                    placeholder="No extra instructions"
                    onChange={(e) => setDraft({ ...draft, section_overrides: { ...draft.section_overrides, [s.key]: e.target.value } })}
                  />
                </Field>
              ))}
            </div>
          </details>

          {error && (
            <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
              {error}
            </p>
          )}
        </form>
      )}
    </Dialog>
  );
}
