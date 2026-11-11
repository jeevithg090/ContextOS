import { useId } from "react";
import { Field, Input, Select, Textarea } from "@/components/ui";
import { ENVIRONMENT_LABELS, frameworkLabel } from "../meta";
import { ENVIRONMENTS, QUARANTINE_LABEL, type AgentCreateInput, type AgentDetail, type AgentPatchInput, type DeclaredToolInput, type Environment } from "../types";
import { ChipsInput } from "./ChipsInput";
import { DeclaredToolsEditor } from "./DeclaredToolsEditor";

const FRAMEWORKS = ["claude_code", "mcp", "python_sdk", "langgraph", "langchain", "openai_agents", "crewai", "autogen", "custom"];
const RESERVED = { [QUARANTINE_LABEL]: "“quarantined” is reserved: use the Quarantine action on the agent instead." };

export interface AgentDraft {
  name: string;
  framework: string;
  version: string;
  owner: string;
  environment: Environment;
  description: string;
  labels: string[];
  tools: DeclaredToolInput[];
  permissions: string[];
  mcp_servers: string[];
}

export function emptyDraft(): AgentDraft {
  return { name: "", framework: "claude_code", version: "", owner: "", environment: "development", description: "", labels: [], tools: [], permissions: [], mcp_servers: [] };
}

export function draftFromAgent(agent: AgentDetail): AgentDraft {
  return {
    name: agent.name,
    framework: agent.framework,
    version: agent.version ?? "",
    owner: agent.owner ?? "",
    environment: (ENVIRONMENTS as string[]).includes(agent.environment) ? (agent.environment as Environment) : "development",
    description: agent.description ?? "",
    labels: agent.labels.filter((l) => l !== QUARANTINE_LABEL),
    tools: agent.declared_capabilities.tools.map((t) => ({ name: t.name, category: (t.category_hint as DeclaredToolInput["category"]) ?? null })),
    permissions: agent.declared_capabilities.permissions,
    mcp_servers: agent.declared_capabilities.mcp_servers,
  };
}

const orNull = (v: string) => (v.trim() ? v.trim() : null);
const capabilities = (d: AgentDraft) => ({
  tools: d.tools.map((t) => (t.category ? { name: t.name, category: t.category } : { name: t.name })),
  permissions: d.permissions,
  mcp_servers: d.mcp_servers,
});

export function createInput(d: AgentDraft): AgentCreateInput {
  return {
    name: d.name.trim(),
    framework: d.framework,
    version: orNull(d.version),
    owner: orNull(d.owner),
    environment: d.environment,
    description: orNull(d.description),
    labels: d.labels,
    declared_capabilities: capabilities(d),
  };
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** Only the fields the user changed, so unchanged policy-relevant fields never need extra permission. */
export function patchFromDraft(agent: AgentDetail, d: AgentDraft): AgentPatchInput {
  const before = draftFromAgent(agent);
  const patch: AgentPatchInput = {};
  if (d.description.trim() !== before.description.trim()) patch.description = orNull(d.description);
  if (d.owner.trim() !== before.owner.trim()) patch.owner = orNull(d.owner);
  if (d.environment !== before.environment) patch.environment = d.environment;
  if (!same(d.labels, before.labels)) patch.labels = d.labels;
  if (!same(capabilities(d), capabilities(before))) patch.declared_capabilities = capabilities(d);
  return patch;
}

export interface AgentFormProps {
  draft: AgentDraft;
  onChange: (draft: AgentDraft) => void;
  mode: "create" | "edit";
  /** Environment and labels are policy inputs: editing them needs policy:manage. */
  canEditPolicyFields: boolean;
}

export function AgentForm({ draft, onChange, mode, canEditPolicyFields }: AgentFormProps) {
  const id = useId();
  const set = <K extends keyof AgentDraft>(key: K, value: AgentDraft[K]) => onChange({ ...draft, [key]: value });
  const policyLocked = mode === "edit" && !canEditPolicyFields;
  const lockHint = "Policies evaluate this field, so changing it requires the policy:manage permission.";

  return (
    <div className="space-y-4">
      {mode === "create" && (
        <div className="grid gap-3 sm:grid-cols-[1fr_180px]">
          <Field label="Name" htmlFor={`${id}-name`} hint="Must match the agent name your integration reports, so its events attach here.">
            <Input id={`${id}-name`} value={draft.name} maxLength={200} required autoFocus onChange={(e) => set("name", e.target.value)} placeholder="e.g. billing-coder" />
          </Field>
          <Field label="Framework" htmlFor={`${id}-fw`}>
            <Select id={`${id}-fw`} value={draft.framework} onChange={(e) => set("framework", e.target.value)}>
              {FRAMEWORKS.map((f) => (
                <option key={f} value={f}>
                  {frameworkLabel(f)}
                </option>
              ))}
            </Select>
          </Field>
        </div>
      )}
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Owner" htmlFor={`${id}-owner`} hint="Team or person responsible.">
          <Input id={`${id}-owner`} value={draft.owner} maxLength={200} onChange={(e) => set("owner", e.target.value)} placeholder="platform-team" />
        </Field>
        <Field label="Environment" htmlFor={`${id}-env`} hint={policyLocked ? lockHint : "Production-only policies apply when set to production."}>
          <Select id={`${id}-env`} value={draft.environment} disabled={policyLocked} onChange={(e) => set("environment", e.target.value as Environment)}>
            {ENVIRONMENTS.map((env) => (
              <option key={env} value={env}>
                {ENVIRONMENT_LABELS[env]}
              </option>
            ))}
          </Select>
        </Field>
        {mode === "create" && (
          <Field label="Version" htmlFor={`${id}-ver`} hint="Optional; integrations update it.">
            <Input id={`${id}-ver`} value={draft.version} maxLength={64} onChange={(e) => set("version", e.target.value)} placeholder="1.4.0" />
          </Field>
        )}
      </div>
      <Field label="Description" htmlFor={`${id}-desc`}>
        <Textarea id={`${id}-desc`} value={draft.description} maxLength={4000} rows={2} className="min-h-[56px]" onChange={(e) => set("description", e.target.value)} placeholder="What this agent does and what it is allowed to touch." />
      </Field>
      <Field label="Labels" htmlFor={`${id}-labels`} hint={policyLocked ? lockHint : "Policies can match agent.labels. Press Enter or comma to add."}>
        <ChipsInput id={`${id}-labels`} value={draft.labels} onChange={(v) => set("labels", v)} lowercase disabled={policyLocked} reserved={RESERVED} placeholder="payments, pci" />
      </Field>
      <div className="space-y-1.5">
        <div className="text-xs font-medium text-fg-muted">Declared tools</div>
        <DeclaredToolsEditor value={draft.tools} onChange={(v) => set("tools", v)} />
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Declared permissions" htmlFor={`${id}-perms`} hint="As configured in the agent (e.g. Bash(git:*)).">
          <ChipsInput id={`${id}-perms`} value={draft.permissions} onChange={(v) => set("permissions", v)} maxItems={100} maxLength={200} placeholder="Add permission" />
        </Field>
        <Field label="MCP servers" htmlFor={`${id}-mcp`}>
          <ChipsInput id={`${id}-mcp`} value={draft.mcp_servers} onChange={(v) => set("mcp_servers", v)} maxItems={100} maxLength={200} placeholder="github, linear" />
        </Field>
      </div>
    </div>
  );
}
