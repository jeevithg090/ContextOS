import { useId, useState, type ReactNode } from "react";
import { BookmarkPlus, LayoutTemplate, X } from "lucide-react";
import { Button, Select } from "@/components/ui";
import { cn } from "@/lib/format";
import { useTemplateGroups } from "./hooks";
import { defaultOptions, effectiveOptions, presetLine } from "./meta";
import { ModeCards } from "./ModeCards";
import { OptionsFields } from "./OptionsFields";
import { TemplateEditorDialog, type TemplateDraft } from "./TemplateEditorDialog";
import type { AgentPreset, AiCatalogue } from "./types";
import type { FixContextState } from "./useFixContextState";

function Step({ n, title, hint, children, actions }: { n: number; title: string; hint?: string; children: ReactNode; actions?: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="space-y-2.5 border-b border-border px-4 py-4 last:border-b-0">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h2 id={id} className="flex items-center gap-2 text-[13px] font-semibold text-fg">
            <span className="num inline-flex h-4 w-4 items-center justify-center rounded-full bg-surface-3 text-2xs text-fg-muted" aria-hidden>
              {n}
            </span>
            {title}
          </h2>
          {hint && <p className="mt-0.5 pl-6 text-2xs text-fg-faint">{hint}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

/** Preset choice as compact radio cards with the server's honest one-line note. */
function PresetPicker({ catalogue, value, onChange }: { catalogue: AiCatalogue; value: AgentPreset; onChange: (p: AgentPreset) => void }) {
  return (
    <div role="radiogroup" aria-label="Coding agent" className="grid gap-1.5 sm:grid-cols-2">
      {catalogue.presets.map((preset) => {
        const selected = preset.key === value;
        return (
          <label
            key={preset.key}
            className={cn(
              "flex cursor-pointer flex-col gap-0.5 rounded-md border px-2.5 py-2 transition-colors focus-within:border-accent/60",
              selected ? "border-accent/60 bg-accent/[0.07]" : "border-border hover:border-border-strong hover:bg-surface-2",
            )}
          >
            <span className="flex items-center gap-2">
              <input type="radio" name="fix-context-preset" value={preset.key} checked={selected} onChange={() => onChange(preset.key)} className="h-3 w-3 accent-[rgb(var(--accent))]" />
              <span className="text-[13px] font-medium text-fg">{preset.label}</span>
              {preset.instruction_file && <span className="truncate font-mono text-2xs text-fg-faint">{preset.instruction_file}</span>}
            </span>
            <span className="line-clamp-2 pl-5 text-2xs leading-snug text-fg-muted" title={preset.notes.join(" ")}>
              {presetLine(preset)}
            </span>
          </label>
        );
      })}
    </div>
  );
}

/**
 * Left-hand configuration: template, mode, coding agent and generation options. Every change marks
 * the current preview as out of date until it is generated again.
 */
export function ConfigPanel({ state, catalogue, canWrite }: { state: FixContextState; catalogue: AiCatalogue; canWrite: boolean }) {
  const templateSelectId = useId();
  const { templates, builtin, org, byId } = useTemplateGroups();
  const [saving, setSaving] = useState(false);
  const { config, modeInfo } = state;
  const applied = config.templateId ? byId.get(config.templateId) : undefined;
  const overrideCount = applied ? Object.keys(applied.section_overrides).length : 0;

  const saveDraft: TemplateDraft = {
    name: "",
    description: "",
    mode: config.mode,
    preset: config.preset,
    options: effectiveOptions(config.options, undefined),
    section_overrides: applied && !applied.is_builtin ? { ...applied.section_overrides } : {},
  };

  return (
    <div>
      <Step
        n={1}
        title="Template"
        hint="Optional. Applying a template replaces the mode, agent and options below."
        actions={
          canWrite ? (
            <Button size="xs" variant="ghost" icon={<BookmarkPlus className="h-3 w-3" aria-hidden />} onClick={() => setSaving(true)}>
              Save as template
            </Button>
          ) : undefined
        }
      >
        <div className="flex gap-2">
          <label htmlFor={templateSelectId} className="sr-only">
            Apply a template
          </label>
          <Select
            id={templateSelectId}
            value=""
            disabled={templates.isLoading || !!templates.error}
            onChange={(e) => {
              const t = byId.get(e.target.value);
              if (t) state.applyTemplate(t, defaultOptions(catalogue));
            }}
          >
            <option value="">{templates.isLoading ? "Loading templates…" : templates.error ? "Templates unavailable" : "Apply a template…"}</option>
            <optgroup label="Built-in">
              {builtin.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </optgroup>
            {org.length > 0 && (
              <optgroup label="Your organisation">
                {org.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </optgroup>
            )}
          </Select>
        </div>
        {applied ? (
          <div className="flex items-start gap-2 rounded-md border border-border bg-surface-2/60 px-2.5 py-2">
            <LayoutTemplate className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />
            <div className="min-w-0 flex-1 text-xs">
              <div className="truncate font-medium text-fg">{applied.name}</div>
              <div className="text-2xs text-fg-muted">
                {applied.is_builtin ? "Built-in template" : "Organisation template"}
                {overrideCount > 0 && ` · adds extra instructions to ${overrideCount} section${overrideCount === 1 ? "" : "s"}`}
              </div>
            </div>
            <button type="button" onClick={state.clearTemplate} aria-label={`Stop using template ${applied.name}`} className="rounded p-0.5 text-fg-faint hover:bg-surface-3 hover:text-fg">
              <X className="h-3.5 w-3.5" aria-hidden />
            </button>
          </div>
        ) : null}
      </Step>

      <Step n={2} title="Mode" hint="What the coding agent is allowed to do.">
        <ModeCards modes={catalogue.modes} value={config.mode} onChange={state.setMode} />
        {modeInfo && <p className="text-2xs text-fg-muted"><span className="text-fg-faint">Deliverable: </span>{modeInfo.deliverable}</p>}
      </Step>

      <Step n={3} title="Coding agent" hint="Adds notes about how that product reads project instructions.">
        <PresetPicker catalogue={catalogue} value={config.preset} onChange={state.setPreset} />
      </Step>

      <Step n={4} title="Options">
        <OptionsFields catalogue={catalogue} mode={modeInfo} options={config.options} onChange={state.setOptions} />
      </Step>

      <TemplateEditorDialog
        open={saving}
        onOpenChange={setSaving}
        initial={saveDraft}
        title="Save as template"
        description="Saves the current mode, agent and options as an organisation template everyone can reuse."
      />
    </div>
  );
}
