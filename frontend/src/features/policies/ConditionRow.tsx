/** One condition ("field op value") in the visual builder: field picker, operator, adaptive value input. */
import { useId } from "react";
import { Trash2 } from "lucide-react";
import { IconButton, Input, Select } from "@/components/ui";
import { cn } from "@/lib/format";
import { ChipListInput, EnumMultiSelect } from "./controls";
import {
  ARGUMENT_FIELD,
  coerceValue,
  groupFields,
  leafForField,
  opsFor,
  parseScalarInput,
  resolveField,
  scalarKind,
  valueKind,
  type ScalarKind,
  type UiLeaf,
} from "./conditions";
import type { ConditionOp, ConditionValue, FieldSpec, JsonScalar, OperatorSpec } from "./types";

const CUSTOM = "__custom__";

export function NotToggle({ negated, onToggle, disabled, label }: { negated: boolean; onToggle: () => void; disabled?: boolean; label: string }) {
  return (
    <button
      type="button"
      aria-pressed={negated}
      aria-label={label}
      title={negated ? "Negated: matches when this is NOT true. Click to remove NOT." : "Click to negate (NOT)"}
      disabled={disabled}
      onClick={onToggle}
      className={cn(
        "h-7 shrink-0 rounded border px-1.5 font-mono text-2xs font-semibold transition-colors disabled:cursor-not-allowed",
        negated ? "border-dec-restrict/50 bg-dec-restrict/10 text-dec-restrict" : "border-border text-fg-faint hover:border-border-strong hover:text-fg-muted",
      )}
    >
      NOT
    </button>
  );
}

export function ConditionRow({
  leaf,
  catalog,
  operators,
  onChange,
  onRemove,
  readOnly,
}: {
  leaf: UiLeaf;
  catalog: FieldSpec[];
  operators: OperatorSpec[];
  onChange: (leaf: UiLeaf) => void;
  onRemove: () => void;
  readOnly?: boolean;
}) {
  const fieldId = useId();
  const { spec, argumentKey } = resolveField(leaf.field, catalog);
  const isArgument = spec?.path === ARGUMENT_FIELD;
  const selectValue = !leaf.field ? "" : spec ? spec.path : CUSTOM;
  const ops = opsFor(spec, operators);
  const opKnown = ops.some((o) => o.op === leaf.op);

  const pickField = (path: string) => {
    if (path === CUSTOM) return;
    const next = catalog.find((f) => f.path === path) ?? null;
    const fieldPath = path === ARGUMENT_FIELD ? `arguments.${argumentKey || "command"}` : path;
    onChange(leafForField(leaf, fieldPath, next, operators));
  };

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-start gap-1.5">
        <NotToggle negated={leaf.negated} disabled={readOnly} label="Negate this condition" onToggle={() => onChange({ ...leaf, negated: !leaf.negated })} />
        <Select
          id={fieldId}
          aria-label="Field"
          value={selectValue}
          disabled={readOnly}
          onChange={(e) => pickField(e.target.value)}
          className={cn("!h-7 !w-[220px] font-mono !text-xs", !leaf.field && "text-fg-faint")}
        >
          <option value="" disabled>
            Choose a field…
          </option>
          {selectValue === CUSTOM && <option value={CUSTOM}>{leaf.field} (unknown field)</option>}
          {groupFields(catalog).map((group) => (
            <optgroup key={group.root} label={group.root}>
              {group.fields.map((f) => (
                <option key={f.path} value={f.path}>
                  {f.path === ARGUMENT_FIELD ? "arguments.<key>" : f.path}
                </option>
              ))}
            </optgroup>
          ))}
        </Select>
        {isArgument && (
          <Input
            aria-label="Argument key"
            value={argumentKey ?? ""}
            disabled={readOnly}
            placeholder="command"
            onChange={(e) => onChange({ ...leaf, field: `arguments.${e.target.value.trim()}` })}
            className="!h-7 !w-[140px] font-mono !text-xs"
          />
        )}
        <Select
          aria-label="Operator"
          value={leaf.op}
          disabled={readOnly || !leaf.field}
          onChange={(e) => {
            const op = e.target.value as ConditionOp;
            onChange({ ...leaf, op, value: coerceValue(leaf.value, op, spec) });
          }}
          className="!h-7 !w-[190px] !text-xs"
        >
          {!leaf.op && <option value="">Operator…</option>}
          {!opKnown && leaf.op && <option value={leaf.op}>{leaf.op} (not valid here)</option>}
          {ops.map((o) => (
            <option key={o.op} value={o.op}>
              {o.label}
            </option>
          ))}
        </Select>
        <div className="min-w-[160px] flex-1">
          <ValueInput leaf={leaf} spec={spec} readOnly={readOnly} onChange={(value) => onChange({ ...leaf, value })} />
        </div>
        {!readOnly && (
          <IconButton label="Remove condition" onClick={onRemove} className="text-fg-faint hover:text-danger">
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
        )}
      </div>
      {spec && <p className="pl-[46px] text-2xs text-fg-faint">{spec.description}</p>}
      {leaf.field && !spec && <p className="pl-[46px] text-2xs text-danger">Unknown field. Pick one from the list; the validation messages suggest the closest match.</p>}
    </div>
  );
}

function ValueInput({
  leaf,
  spec,
  onChange,
  readOnly,
}: {
  leaf: UiLeaf;
  spec: FieldSpec | null;
  onChange: (value: ConditionValue | undefined) => void;
  readOnly?: boolean;
}) {
  const kind = valueKind(leaf.op);
  const scalar = scalarKind(spec);
  if (!leaf.field || !leaf.op) return null;
  if (kind === "none") return <span className="inline-flex h-7 items-center text-2xs text-fg-faint">no value needed</span>;

  if (kind === "glob") {
    const items = (Array.isArray(leaf.value) ? leaf.value : leaf.value === undefined ? [] : [leaf.value]).map(String);
    return <ChipListInput label="Glob patterns" mono values={items} disabled={readOnly} placeholder="e.g. TOOL-DESTRUCTIVE-*  (Enter to add)" onChange={onChange} />;
  }

  if (kind === "list") {
    const items = Array.isArray(leaf.value) ? leaf.value : leaf.value === undefined ? [] : [leaf.value];
    if (scalar === "enum" && spec?.values) {
      return <EnumMultiSelect label="Values" options={spec.values} values={items.map(String)} disabled={readOnly} onChange={onChange} />;
    }
    return (
      <ChipListInput
        label="Values"
        mono
        values={items.map(String)}
        disabled={readOnly}
        placeholder="Type a value, Enter to add"
        onChange={(values) => onChange(values.map((v) => parseScalarInput(v, scalar)))}
      />
    );
  }

  return <ScalarInput value={leaf.value} kind={scalar} spec={spec} readOnly={readOnly} onChange={onChange} />;
}

function ScalarInput({
  value,
  kind,
  spec,
  onChange,
  readOnly,
}: {
  value: ConditionValue | undefined;
  kind: ScalarKind;
  spec: FieldSpec | null;
  onChange: (value: JsonScalar) => void;
  readOnly?: boolean;
}) {
  const current = Array.isArray(value) ? value[0] : value;
  if (kind === "enum" && spec?.values) {
    const text = current === undefined ? "" : String(current);
    const known = spec.values.some((v) => v.toLowerCase() === text.toLowerCase());
    return (
      <Select aria-label="Value" value={text} disabled={readOnly} onChange={(e) => onChange(e.target.value)} className="!h-7 font-mono !text-xs">
        {!known && <option value={text}>{text || "Choose…"}</option>}
        {spec.values.map((v) => (
          <option key={v} value={v}>
            {v}
          </option>
        ))}
      </Select>
    );
  }
  if (kind === "boolean") {
    return (
      <Select aria-label="Value" value={String(current === true)} disabled={readOnly} onChange={(e) => onChange(e.target.value === "true")} className="!h-7 !text-xs">
        <option value="true">true</option>
        <option value="false">false</option>
      </Select>
    );
  }
  if (kind === "any") {
    // Free-form tool arguments: let the user say which JSON type the value is.
    const type = typeof current === "number" ? "number" : typeof current === "boolean" ? "boolean" : "string";
    return (
      <div className="flex gap-1.5">
        <Select
          aria-label="Value type"
          value={type}
          disabled={readOnly}
          onChange={(e) => {
            const t = e.target.value;
            onChange(t === "number" ? Number(current) || 0 : t === "boolean" ? current === true || current === "true" : String(current ?? ""));
          }}
          className="!h-7 !w-[92px] !text-xs"
        >
          <option value="string">text</option>
          <option value="number">number</option>
          <option value="boolean">boolean</option>
        </Select>
        {type === "boolean" ? (
          <Select aria-label="Value" value={String(current === true)} disabled={readOnly} onChange={(e) => onChange(e.target.value === "true")} className="!h-7 !text-xs">
            <option value="true">true</option>
            <option value="false">false</option>
          </Select>
        ) : (
          <Input
            aria-label="Value"
            type={type === "number" ? "number" : "text"}
            value={current === undefined ? "" : String(current)}
            disabled={readOnly}
            onChange={(e) => onChange(parseScalarInput(e.target.value, type === "number" ? "number" : "string"))}
            className="!h-7 font-mono !text-xs"
          />
        )}
      </div>
    );
  }
  return (
    <Input
      aria-label="Value"
      type={kind === "number" ? "number" : "text"}
      value={current === undefined ? "" : String(current)}
      disabled={readOnly}
      placeholder={spec?.example !== undefined && typeof spec.example !== "object" ? `e.g. ${String(spec.example)}` : undefined}
      onChange={(e) => onChange(parseScalarInput(e.target.value, kind))}
      className="!h-7 font-mono !text-xs"
    />
  );
}
