import { useId, type ReactNode } from "react";
import { SegmentedControl } from "@/components/data";
import { Select, Textarea } from "@/components/ui";
import { ChipsInput, LabelledSwitch } from "./controls";
import { MAX_CONSTRAINT_CHARS, MAX_CONSTRAINTS, MAX_EXTRA_CHARS, optionValueLabel } from "./meta";
import type { AiCatalogue, Autonomy, GenerationOptions, ModeInfo, OptionSpec, OutputFormat, RequiredTesting, SecurityLevel, TechnicalDepth } from "./types";

type OptionPatch = Partial<GenerationOptions>;

const FALLBACK_VALUES: Record<string, string[]> = {
  technical_depth: ["brief", "standard", "deep"],
  autonomy: ["ask_before_changes", "autonomous_with_checkpoints", "fully_autonomous"],
  testing_requirements: ["none", "unit", "unit_integration", "full_regression"],
  security_requirements: ["standard", "strict"],
  output_format: ["markdown", "xml_tagged"],
};

function optionSpecs(catalogue: AiCatalogue | undefined) {
  const byKey = new Map<string, OptionSpec>((catalogue?.options ?? []).map((o) => [o.key, o]));
  return (key: keyof GenerationOptions, fallbackLabel: string) => {
    const spec = byKey.get(key);
    return {
      label: spec?.label ?? fallbackLabel,
      description: spec?.description ?? "",
      values: spec?.values?.length ? spec.values : (FALLBACK_VALUES[key] ?? []),
    };
  };
}

function OptionRow({ label, description, htmlFor, children }: { label: string; description?: string; htmlFor?: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between gap-2">
        {htmlFor ? (
          <label htmlFor={htmlFor} className="text-xs font-medium text-fg-muted">
            {label}
          </label>
        ) : (
          <span className="text-xs font-medium text-fg-muted">{label}</span>
        )}
      </div>
      {children}
      {description && <p className="text-2xs text-fg-faint">{description}</p>}
    </div>
  );
}

/**
 * Generation options form (technical depth, autonomy, testing, security, output format, constraints,
 * change permissions, extra instructions). Read-only modes force both change toggles off.
 */
export function OptionsFields({
  catalogue,
  mode,
  options,
  onChange,
  disabled,
}: {
  catalogue: AiCatalogue | undefined;
  mode: ModeInfo | undefined;
  options: GenerationOptions;
  onChange: (patch: OptionPatch) => void;
  disabled?: boolean;
}) {
  const id = useId();
  const spec = optionSpecs(catalogue);
  const readOnlyMode = !!mode && !mode.may_modify_files;
  const codeChanges = !readOnlyMode && options.allow_code_changes;
  const depth = spec("technical_depth", "Technical depth");
  const autonomy = spec("autonomy", "Autonomy");
  const testing = spec("testing_requirements", "Required testing");
  const security = spec("security_requirements", "Security requirements");
  const format = spec("output_format", "Output format");
  const constraints = spec("constraints", "Constraints");
  const codeSpec = spec("allow_code_changes", "Allow code changes");
  const archSpec = spec("allow_architecture_changes", "Allow architecture changes");
  const extra = spec("extra_instructions", "Extra instructions");

  return (
    <div className="space-y-4">
      <OptionRow label={depth.label} description={depth.description}>
        <SegmentedControl<TechnicalDepth>
          aria-label={depth.label}
          value={options.technical_depth}
          onChange={(v) => onChange({ technical_depth: v })}
          options={depth.values.map((v) => ({ value: v as TechnicalDepth, label: optionValueLabel(v), disabled }))}
        />
      </OptionRow>

      <div className="grid gap-4 sm:grid-cols-2">
        <OptionRow label={autonomy.label} htmlFor={`${id}-autonomy`} description={codeChanges ? autonomy.description : "Not used: the agent will not modify files with these settings."}>
          <Select id={`${id}-autonomy`} value={options.autonomy} disabled={disabled || !codeChanges} onChange={(e) => onChange({ autonomy: e.target.value as Autonomy })}>
            {autonomy.values.map((v) => (
              <option key={v} value={v}>
                {optionValueLabel(v)}
              </option>
            ))}
          </Select>
        </OptionRow>
        <OptionRow label={testing.label} htmlFor={`${id}-testing`} description={testing.description}>
          <Select id={`${id}-testing`} value={options.testing_requirements} disabled={disabled} onChange={(e) => onChange({ testing_requirements: e.target.value as RequiredTesting })}>
            {testing.values.map((v) => (
              <option key={v} value={v}>
                {optionValueLabel(v)}
              </option>
            ))}
          </Select>
        </OptionRow>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <OptionRow label={security.label} description={security.description}>
          <SegmentedControl<SecurityLevel>
            aria-label={security.label}
            value={options.security_requirements}
            onChange={(v) => onChange({ security_requirements: v })}
            options={security.values.map((v) => ({ value: v as SecurityLevel, label: optionValueLabel(v), disabled }))}
          />
        </OptionRow>
        <OptionRow label={format.label} description={format.description}>
          <SegmentedControl<OutputFormat>
            aria-label={format.label}
            value={options.output_format}
            onChange={(v) => onChange({ output_format: v })}
            options={format.values.map((v) => ({ value: v as OutputFormat, label: v === "xml_tagged" ? "XML-tagged" : optionValueLabel(v), disabled }))}
          />
        </OptionRow>
      </div>

      <div className="space-y-3 rounded-md border border-border bg-surface-2/40 p-3">
        <LabelledSwitch
          label={codeSpec.label}
          description={codeSpec.description}
          checked={codeChanges}
          disabled={disabled || readOnlyMode}
          disabledReason={readOnlyMode ? `${mode?.label ?? "This mode"} is read-only, so code changes are always off.` : undefined}
          onCheckedChange={(v) => onChange({ allow_code_changes: v, ...(v ? {} : { allow_architecture_changes: false }) })}
        />
        <LabelledSwitch
          label={archSpec.label}
          description={archSpec.description}
          checked={codeChanges && options.allow_architecture_changes}
          disabled={disabled || !codeChanges}
          disabledReason={!codeChanges && !disabled ? "Needs code changes to be allowed." : undefined}
          onCheckedChange={(v) => onChange({ allow_architecture_changes: v })}
        />
      </div>

      <ChipsInput
        label={constraints.label}
        values={options.constraints}
        onChange={(values) => onChange({ constraints: values })}
        placeholder="e.g. Do not change the public API — press Enter to add"
        maxItems={MAX_CONSTRAINTS}
        maxLength={MAX_CONSTRAINT_CHARS}
        disabled={disabled}
        hint={`Rules the agent must follow, one per entry (up to ${MAX_CONSTRAINTS}).`}
      />

      <OptionRow label={extra.label} htmlFor={`${id}-extra`} description={`${extra.description} ${options.extra_instructions.length}/${MAX_EXTRA_CHARS} characters.`}>
        <Textarea
          id={`${id}-extra`}
          value={options.extra_instructions}
          maxLength={MAX_EXTRA_CHARS}
          disabled={disabled}
          placeholder="Anything else the agent should know or do."
          className="min-h-[64px] text-xs"
          onChange={(e) => onChange({ extra_instructions: e.target.value })}
        />
      </OptionRow>
    </div>
  );
}
