import { useEffect, useState, type FormEvent } from "react";
import { Button, Checkbox, Dialog, Field, Input, Select } from "@/components/ui";
import { useAgentOptions, useCreateApiKey, type ApiKeyCreated, type ApiKeyScope } from "./api";
import { SCOPE_META, SCOPE_ORDER } from "./meta";

const EXPIRY_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "", label: "Never expires" },
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "180", label: "180 days" },
  { value: "365", label: "1 year" },
];

const INITIAL = { name: "", scopes: ["ingest", "decide"] as ApiKeyScope[], agentId: "", expires: "90" };

export function CreateApiKeyDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (key: ApiKeyCreated) => void;
}) {
  const create = useCreateApiKey();
  const agents = useAgentOptions(open);
  const [form, setForm] = useState(INITIAL);

  useEffect(() => {
    if (open) {
      setForm(INITIAL);
      create.reset();
    }
    // Reset only when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const toggleScope = (scope: ApiKeyScope, on: boolean) =>
    setForm((f) => ({ ...f, scopes: on ? [...new Set([...f.scopes, scope])] : f.scopes.filter((s) => s !== scope) }));

  const noScopes = form.scopes.length === 0;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (noScopes) return;
    create.mutate(
      {
        name: form.name.trim(),
        scopes: SCOPE_ORDER.filter((s) => form.scopes.includes(s)),
        agent_id: form.agentId || null,
        expires_in_days: form.expires ? Number(form.expires) : null,
      },
      {
        onSuccess: (key) => {
          onCreated(key);
          onOpenChange(false);
        },
      },
    );
  };

  const agentItems = agents.data?.items ?? [];
  const agentHint = agents.isError
    ? "The agent list could not be loaded; the key can still be created unbound."
    : agents.data && agentItems.length === 0
      ? "No agents registered yet. Agents appear after they first report, or when added on the Agents page."
      : "A bound key can only report events for that agent, so a leaked key cannot forge another agent's activity.";

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !create.isPending && onOpenChange(next)}
      title="Create API key"
      description="Integrations (Claude Code hooks, the MCP gateway, the Python SDK) authenticate with an API key."
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            Cancel
          </Button>
          <Button type="submit" form="create-key-form" variant="primary" size="sm" loading={create.isPending} disabled={noScopes}>
            Create key
          </Button>
        </>
      }
    >
      <form id="create-key-form" onSubmit={submit} className="space-y-4">
        <Field label="Name" htmlFor="key-name" hint="Where the key is used, e.g. “ci-runner” or “claude-code · ada-laptop”.">
          <Input id="key-name" required maxLength={200} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} autoComplete="off" />
        </Field>

        <fieldset className="space-y-2">
          <legend className="mb-1.5 text-xs font-medium text-fg-muted">Scopes</legend>
          {SCOPE_ORDER.map((scope) => (
            <div key={scope} className="rounded border border-border bg-surface-2/40 px-3 py-2">
              <Checkbox label={<span className="font-medium">{SCOPE_META[scope].label}</span>} checked={form.scopes.includes(scope)} onChange={(on) => toggleScope(scope, on)} />
              <p className="mt-0.5 pl-[22px] text-xs text-fg-muted">{SCOPE_META[scope].description}</p>
            </div>
          ))}
          {noScopes && <p className="text-2xs text-danger">Choose at least one scope.</p>}
          <p className="text-2xs text-fg-faint">Keys never carry admin rights. Use only the scopes the integration needs.</p>
        </fieldset>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Bind to agent (optional)" htmlFor="key-agent" hint={agentHint}>
            <Select id="key-agent" value={form.agentId} onChange={(e) => setForm({ ...form, agentId: e.target.value })} disabled={agents.isLoading}>
              <option value="">{agents.isLoading ? "Loading agents…" : "Any agent (unbound)"}</option>
              {agentItems.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                  {a.environment ? ` · ${a.environment}` : ""}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Expiry" htmlFor="key-expiry" hint="Expired keys are rejected; create a new key to rotate.">
            <Select id="key-expiry" value={form.expires} onChange={(e) => setForm({ ...form, expires: e.target.value })}>
              {EXPIRY_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </Field>
        </div>

        {create.error && (
          <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {create.error.message}
          </p>
        )}
      </form>
    </Dialog>
  );
}
