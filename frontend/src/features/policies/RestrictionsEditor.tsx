/** Constraints for RESTRICT policies (schema: backend/app/engines/policy/restrictions.py). */
import { useId } from "react";
import { Checkbox, Field, Input } from "@/components/ui";
import { ChipListInput } from "./controls";
import type { Restrictions } from "./types";

const MAX_ARGUMENT_BYTES = 10 * 1024 * 1024;

export function RestrictionsEditor({
  restrictions,
  onChange,
  readOnly,
}: {
  restrictions: Restrictions;
  onChange: (next: Restrictions) => void;
  readOnly?: boolean;
}) {
  const allowId = useId();
  const denyId = useId();
  const sizeId = useId();
  const set = <K extends keyof Restrictions>(key: K, value: Restrictions[K] | undefined) => {
    const next = { ...restrictions };
    if (value === undefined) delete next[key];
    else next[key] = value;
    onChange(next);
  };

  return (
    <div className="space-y-3 rounded-md border border-dec-restrict/25 bg-dec-restrict/[0.04] p-3">
      <p className="text-xs text-fg-muted">
        The call may run only with these constraints applied. Integrations that cannot apply every constraint must treat
        RESTRICT as <span className="font-medium text-dec-deny">DENY</span> (fail closed). When several RESTRICT policies match,
        the strictest combination applies.
      </p>
      <Checkbox
        label="Redact detected secrets in the arguments before the call runs"
        checked={!!restrictions.redact_secrets}
        disabled={readOnly}
        onChange={(v) => set("redact_secrets", v ? true : undefined)}
      />
      <Field label="Only allow file paths matching" htmlFor={allowId} hint="Every file the call touches must match one of these globs. Leave empty for no allowlist.">
        <ChipListInput
          id={allowId}
          label="Allowed path globs"
          mono
          disabled={readOnly}
          values={restrictions.allowed_path_globs ?? []}
          placeholder="e.g. /srv/app/*  (Enter to add)"
          onChange={(v) => set("allowed_path_globs", v.length ? v : undefined)}
        />
      </Field>
      <Field label="Never allow file paths matching" htmlFor={denyId} hint="No file the call touches may match any of these globs (* also matches /).">
        <ChipListInput
          id={denyId}
          label="Denied path globs"
          mono
          disabled={readOnly}
          values={restrictions.deny_path_globs ?? []}
          placeholder="e.g. */.env  (Enter to add)"
          onChange={(v) => set("deny_path_globs", v.length ? v : undefined)}
        />
      </Field>
      <Field label="Maximum argument size (bytes)" htmlFor={sizeId} hint={`Serialised arguments larger than this are refused. 1 – ${MAX_ARGUMENT_BYTES.toLocaleString("en-GB")}; empty for no limit.`}>
        <Input
          id={sizeId}
          type="number"
          min={1}
          max={MAX_ARGUMENT_BYTES}
          disabled={readOnly}
          value={restrictions.max_argument_bytes ?? ""}
          onChange={(e) => set("max_argument_bytes", e.target.value === "" ? undefined : Math.trunc(Number(e.target.value)))}
          className="!w-48"
        />
      </Field>
    </div>
  );
}
