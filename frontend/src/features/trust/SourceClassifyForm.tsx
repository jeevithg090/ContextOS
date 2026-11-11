/** Manual classification of one source: level + capabilities + a required note for the audit trail. */
import { useId, useState } from "react";
import { Button, Field, Select, Textarea, useToast } from "@/components/ui";
import { TRUST_LEVELS, TRUST_META, type TrustLevel } from "@/lib/domain";
import { errorMessage, useClassifySource } from "./api";
import { CapabilityPicker, ContextualTrustNote } from "./components";
import { LEVEL_HELP, capabilityAllowed, defaultCapabilities } from "./meta";
import type { Capability, TrustSourceDetail } from "./types";

export function SourceClassifyForm({ source }: { source: TrustSourceDetail }) {
  const toast = useToast();
  const classify = useClassifySource(source.id);
  const initialLevel = (source.manual_classification?.level ?? source.trust_level) as TrustLevel;
  const [level, setLevel] = useState<TrustLevel>(initialLevel);
  const [caps, setCaps] = useState<Capability[]>(
    source.manual_classification?.capabilities.length ? source.manual_classification.capabilities : defaultCapabilities(initialLevel, "source"),
  );
  const [note, setNote] = useState("");
  const levelId = useId();
  const noteId = useId();

  const clearError = () => {
    if (classify.error) classify.reset();
  };
  const changeLevel = (next: TrustLevel) => {
    clearError();
    setLevel(next);
    setCaps(defaultCapabilities(next, "source"));
  };
  const granted = caps.filter((c) => capabilityAllowed(level, c));
  const canSave = note.trim().length > 0 && !classify.isPending;

  const submit = async () => {
    if (!canSave) return;
    try {
      const saved = await classify.mutateAsync({ trust_level: level, capabilities: granted.length ? granted : null, note: note.trim() });
      setNote("");
      if (saved.trust_level !== level)
        toast.toast({
          kind: "info",
          title: `Classified as ${TRUST_META[level].label}, but kept at ${TRUST_META[saved.trust_level].label}`,
          description: "Findings recorded for this source still apply. See the evidence downgrade above.",
        });
      else toast.success(`Source classified as ${TRUST_META[saved.trust_level].label}`, "Recorded in the audit trail with your note.");
    } catch {
      /* the error is shown inline */
    }
  };

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <ContextualTrustNote />
      <Field label="Trust level" htmlFor={levelId} hint={LEVEL_HELP[level]}>
        <Select id={levelId} value={level} onChange={(e) => changeLevel(e.target.value as TrustLevel)} className="max-w-[220px]">
          {TRUST_LEVELS.map((l) => (
            <option key={l} value={l}>
              {TRUST_META[l].label}
            </option>
          ))}
        </Select>
      </Field>
      <div className="space-y-1.5">
        <div className="text-xs font-medium text-fg-muted">What content from this source may do</div>
        <CapabilityPicker
          level={level}
          appliesTo="source"
          value={caps}
          onChange={(next) => {
            clearError();
            setCaps(next);
          }}
        />
      </div>
      <Field label="Note (required)" htmlFor={noteId} hint="Why you are classifying it this way. Stored with your name in the audit trail; secrets are redacted.">
        <Textarea
          id={noteId}
          value={note}
          onChange={(e) => {
            clearError();
            setNote(e.target.value);
          }}
          maxLength={1000}
          placeholder="e.g. Our own engineering wiki, edited only by staff"
          className="min-h-[64px]"
        />
      </Field>
      {classify.error && (
        <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-2.5 py-2 text-xs text-danger">
          {errorMessage(classify.error)}
        </p>
      )}
      <div className="flex items-center justify-end gap-2">
        <Button type="submit" variant="primary" size="sm" loading={classify.isPending} disabled={!canSave}>
          Save classification
        </Button>
      </div>
    </form>
  );
}
