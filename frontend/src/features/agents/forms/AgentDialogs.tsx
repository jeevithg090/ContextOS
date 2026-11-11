import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Button, Dialog, useToast } from "@/components/ui";
import { useRegisterAgent, useUpdateAgent, validationMessages } from "../api";
import type { AgentDetail } from "../types";
import { AgentForm, createInput, draftFromAgent, emptyDraft, patchFromDraft, type AgentDraft } from "./AgentForm";

function FormErrors({ error }: { error: unknown }) {
  if (!error) return null;
  const details = validationMessages(error);
  return (
    <div role="alert" className="mt-4 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
      <div className="font-medium">{error instanceof Error ? error.message : "The request failed."}</div>
      {details.length > 0 && (
        <ul className="mt-1 list-disc pl-4">
          {details.map((d) => (
            <li key={d}>{d}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function RegisterAgentDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [draft, setDraft] = useState<AgentDraft>(emptyDraft);
  const register = useRegisterAgent();
  const toast = useToast();
  const navigate = useNavigate();

  useEffect(() => {
    if (open) {
      setDraft(emptyDraft());
      register.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset only when the dialog opens
  }, [open]);

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!draft.name.trim() || register.isPending) return;
    try {
      const agent = await register.mutateAsync(createInput(draft));
      toast.success(`Registered “${agent.name}”`, "Events your integration reports under this name now attach to it.");
      onOpenChange(false);
      navigate(`/agents/${encodeURIComponent(agent.id)}`);
    } catch {
      /* shown inline by FormErrors */
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !register.isPending && onOpenChange(next)}
      title="Register agent"
      description="Declare an agent before it reports, so its configuration is known and undeclared tool use stands out."
      className="w-[min(720px,calc(100vw-32px))]"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={() => onOpenChange(false)} disabled={register.isPending}>
            Cancel
          </Button>
          <Button variant="primary" size="sm" onClick={() => submit()} loading={register.isPending} disabled={!draft.name.trim()}>
            Register agent
          </Button>
        </>
      }
    >
      <form onSubmit={submit} noValidate>
        <AgentForm draft={draft} onChange={setDraft} mode="create" canEditPolicyFields />
        <FormErrors error={register.error} />
        <button type="submit" className="hidden" aria-hidden tabIndex={-1} />
      </form>
    </Dialog>
  );
}

export function EditAgentDialog({ agent, open, onOpenChange, canEditPolicyFields }: { agent: AgentDetail; open: boolean; onOpenChange: (open: boolean) => void; canEditPolicyFields: boolean }) {
  const [draft, setDraft] = useState<AgentDraft>(() => draftFromAgent(agent));
  const update = useUpdateAgent(agent.id);
  const toast = useToast();

  useEffect(() => {
    if (open) {
      setDraft(draftFromAgent(agent));
      update.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset only when the dialog opens
  }, [open]);

  const patch = patchFromDraft(agent, draft);
  const changed = Object.keys(patch).length > 0;

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!changed || update.isPending) return;
    try {
      await update.mutateAsync(patch);
      toast.success(`Saved “${agent.name}”`, "The change is recorded in the audit log.");
      onOpenChange(false);
    } catch {
      /* shown inline by FormErrors */
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !update.isPending && onOpenChange(next)}
      title={`Edit ${agent.name}`}
      description="Name and framework come from the integration and cannot be changed here."
      className="w-[min(720px,calc(100vw-32px))]"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={() => onOpenChange(false)} disabled={update.isPending}>
            Cancel
          </Button>
          <Button variant="primary" size="sm" onClick={() => submit()} loading={update.isPending} disabled={!changed}>
            Save changes
          </Button>
        </>
      }
    >
      <form onSubmit={submit} noValidate>
        <AgentForm draft={draft} onChange={setDraft} mode="edit" canEditPolicyFields={canEditPolicyFields} />
        <FormErrors error={update.error} />
        <button type="submit" className="hidden" aria-hidden tabIndex={-1} />
      </form>
    </Dialog>
  );
}
