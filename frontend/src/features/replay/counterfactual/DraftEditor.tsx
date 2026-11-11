/**
 * Add an unsaved policy to the hypothetical set as JSON. The shape is checked locally, then the
 * conditions/outcome/restrictions are validated by POST /policies/validate (the same validator the
 * Policy Studio uses); only a valid draft can be added. The server validates again on Run.
 */
import { useId, useState } from "react";
import { CircleCheck, Plus } from "lucide-react";
import { Button, Textarea } from "@/components/ui";
import { useValidateDraft, validationErrors } from "../api";
import { DRAFT_TEMPLATE, parseDraft } from "../policySet";
import type { DraftPolicy } from "../types";

export function DraftEditor({ onAdd, existingNames }: { onAdd: (draft: DraftPolicy) => void; existingNames: string[] }) {
  const id = useId();
  const [text, setText] = useState(DRAFT_TEMPLATE);
  const [errors, setErrors] = useState<string[]>([]);
  const [valid, setValid] = useState<{ draft: DraftPolicy; explanation: string | null } | null>(null);
  const validate = useValidateDraft();

  const check = () => {
    setValid(null);
    const [draft, problems] = parseDraft(text);
    if (!draft) {
      setErrors(problems);
      return;
    }
    if (existingNames.includes(draft.name.trim())) {
      setErrors([`A draft named "${draft.name}" is already in the set; give this one a different name.`]);
      return;
    }
    setErrors([]);
    validate.mutate(
      { conditions: draft.conditions, outcome: draft.outcome, restrictions: draft.restrictions ?? {} },
      {
        onSuccess: (result) => {
          if (result.valid) setValid({ draft, explanation: result.explanation });
          else setErrors(result.errors);
        },
        onError: (error) => setErrors(validationErrors(error).length ? validationErrors(error) : [error instanceof Error ? error.message : "Validation failed"]),
      },
    );
  };

  return (
    <div className="space-y-2">
      <label htmlFor={id} className="block text-xs font-medium text-fg-muted">
        Draft policy (JSON: name, outcome, conditions; optional mode, priority, severity, restrictions, id to replace a saved policy)
      </label>
      <Textarea
        id={id}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setValid(null);
        }}
        spellCheck={false}
        className="!min-h-[220px] font-mono text-xs"
        aria-invalid={errors.length > 0}
        aria-describedby={`${id}-feedback`}
      />
      <div id={`${id}-feedback`} aria-live="polite" className="space-y-1">
        {errors.length > 0 && (
          <ul className="list-disc space-y-0.5 pl-5 text-xs text-danger">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}
        {valid && (
          <p className="flex items-start gap-1.5 text-xs text-ok">
            <CircleCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
            <span>
              Valid. {valid.draft.outcome} when {valid.explanation ?? "its conditions match"}.
            </span>
          </p>
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" onClick={check} loading={validate.isPending}>
          Validate
        </Button>
        <Button
          size="sm"
          variant="secondary"
          icon={<Plus className="h-3.5 w-3.5" aria-hidden />}
          disabled={!valid}
          onClick={() => {
            if (!valid) return;
            onAdd(valid.draft);
            setValid(null);
          }}
        >
          Add to policy set
        </Button>
        <Button size="sm" variant="ghost" onClick={() => { setText(DRAFT_TEMPLATE); setErrors([]); setValid(null); }}>
          Reset template
        </Button>
      </div>
    </div>
  );
}
