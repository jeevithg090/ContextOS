/** Raw JSON editing of a policy's conditions. The text is controlled by the editor so an
 * unparseable draft survives tab switches; semantic errors come from POST /policies/validate and
 * are shown next to the plain-English preview. */
import { useId } from "react";
import { WandSparkles } from "lucide-react";
import { Button, Textarea } from "@/components/ui";
import { CopyButton } from "@/components/data";
import { cn } from "@/lib/format";

export const prettyJson = (value: unknown) => JSON.stringify(value ?? {}, null, 2);

/** Parse conditions text. Returns the value, or the syntax problem to show. */
export function parseConditionsText(text: string): { value: unknown; error: null } | { value: null; error: string } {
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return { value: null, error: 'conditions must be a JSON object, e.g. {"all": [...]}' };
    }
    return { value: parsed, error: null };
  } catch (err) {
    return { value: null, error: err instanceof Error ? err.message : "invalid JSON" };
  }
}

export function JsonConditionsEditor({
  text,
  onTextChange,
  syntaxError,
  readOnly,
}: {
  text: string;
  onTextChange: (text: string) => void;
  syntaxError: string | null;
  readOnly?: boolean;
}) {
  const id = useId();
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <label htmlFor={id} className="text-xs font-medium text-fg-muted">
          Conditions (JSON)
        </label>
        <div className="flex items-center gap-1">
          {!readOnly && (
            <Button
              size="xs"
              variant="ghost"
              icon={<WandSparkles className="h-3 w-3" aria-hidden />}
              disabled={!!syntaxError}
              onClick={() => onTextChange(prettyJson(JSON.parse(text)))}
            >
              Format
            </Button>
          )}
          <CopyButton value={text} label="Copy conditions JSON" size="xs" />
        </div>
      </div>
      <Textarea
        id={id}
        value={text}
        readOnly={readOnly}
        spellCheck={false}
        aria-invalid={!!syntaxError}
        aria-describedby={`${id}-help`}
        onChange={(e) => onTextChange(e.target.value)}
        className={cn("!min-h-[320px] font-mono text-xs leading-5", syntaxError && "border-danger/60 focus:border-danger/60")}
      />
      <p id={`${id}-help`} className={cn("text-2xs", syntaxError ? "text-danger" : "text-fg-faint")}>
        {syntaxError
          ? `JSON syntax error: ${syntaxError}. The builder and preview keep the last valid version until this parses.`
          : 'Shape: {"all": [...]} · {"any": [...]} · {"not": {...}} · {"field": "tool.category", "op": "in", "value": ["http"]}'}
      </p>
    </div>
  );
}
