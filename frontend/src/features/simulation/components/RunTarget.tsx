import { useId } from "react";
import { Button, Field, Input, Select } from "@/components/ui";
import { useAgentOptions } from "../api";

export interface RunTargetValue {
  agentId: string;
  version: string;
}

/**
 * Who a run is attributed to: the dedicated simulated agent (default) or a registered agent with an
 * optional version label, for regression testing that agent against the same synthetic attacks.
 */
export function RunTarget({ value, onChange, disabled }: { value: RunTargetValue; onChange: (next: RunTargetValue) => void; disabled?: boolean }) {
  const agents = useAgentOptions(!disabled);
  const agentFieldId = useId();
  const versionFieldId = useId();
  const options = agents.data ?? [];
  const selected = options.find((a) => a.id === value.agentId);

  return (
    <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,14rem)]">
      <Field
        label="Run against"
        htmlFor={agentFieldId}
        hint={
          agents.error ? undefined : options.length === 0 && !agents.isLoading && !disabled
            ? "No registered agents yet — runs use the dedicated simulated agent."
            : "A registered agent is credited with the simulated sessions; its registered version and last-seen time are not changed."
        }
        error={agents.error ? "Could not load your agents." : null}
      >
        <div className="flex items-center gap-2">
          <Select
            id={agentFieldId}
            value={value.agentId}
            disabled={disabled || agents.isLoading}
            onChange={(e) => onChange({ ...value, agentId: e.target.value })}
          >
            <option value="">Dedicated simulated agent (default)</option>
            {agents.isLoading && <option disabled>Loading agents…</option>}
            {options.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} · {a.framework}
                {a.version ? ` · v${a.version}` : ""}
              </option>
            ))}
          </Select>
          {agents.error && (
            <Button size="sm" variant="outline" onClick={() => void agents.refetch()}>
              Retry
            </Button>
          )}
        </div>
      </Field>
      <Field
        label="Agent version (optional)"
        htmlFor={versionFieldId}
        hint={value.agentId ? `Recorded on the run. Empty: ${selected?.version ? `v${selected.version}` : "the agent's registered version"}.` : "Recorded on the run as a label."}
      >
        <Input
          id={versionFieldId}
          value={value.version}
          maxLength={64}
          disabled={disabled}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => onChange({ ...value, version: e.target.value })}
        />
      </Field>
    </div>
  );
}
