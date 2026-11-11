/**
 * Quarantine: sets status "quarantined" plus the reserved label "quarantined". It is enforced only
 * by an enforce-mode policy matching agent.labels at an enforcing integration — the UI says so and
 * offers to create that policy (Policy Studio API, policy:manage).
 */
import { useState } from "react";
import { ShieldAlert, ShieldCheck, ShieldOff } from "lucide-react";
import { Button, Checkbox, useToast } from "@/components/ui";
import { ConfirmDialog, EntityLink } from "@/components/data";
import { cn } from "@/lib/format";
import { useCreateQuarantinePolicy, useUpdateAgent } from "../api";
import type { AgentDetail } from "../types";

export function QuarantineButton({ agent, canManage }: { agent: AgentDetail; canManage: boolean }) {
  const [open, setOpen] = useState(false);
  const [withPolicy, setWithPolicy] = useState(true);
  const update = useUpdateAgent(agent.id);
  const createPolicy = useCreateQuarantinePolicy();
  const toast = useToast();
  const q = agent.quarantine;
  const quarantined = agent.status === "quarantined";
  const hasFullPolicy = q.policies.some((p) => p.scope === "all_calls");

  const confirm = async () => {
    if (quarantined) {
      await update.mutateAsync({ status: "active" });
      toast.success(`Released “${agent.name}” from quarantine`, "Its tool calls are decided by your regular policies again.");
      return;
    }
    if (withPolicy && !hasFullPolicy) await createPolicy.mutateAsync(q.suggested_policy);
    await update.mutateAsync({ status: "quarantined" });
    toast.success(`Quarantined “${agent.name}”`, withPolicy || hasFullPolicy ? "Tool calls are denied wherever the integration enforces decisions." : "Status marked only; no policy enforces it yet.");
  };

  const disabledReason = canManage ? undefined : "Quarantine changes how policies apply, so it requires the policy:manage permission.";
  return (
    <>
      <Button
        size="sm"
        variant={quarantined ? "outline" : "danger"}
        icon={quarantined ? <ShieldCheck className="h-3.5 w-3.5" aria-hidden /> : <ShieldOff className="h-3.5 w-3.5" aria-hidden />}
        onClick={() => setOpen(true)}
        disabled={!canManage}
        title={disabledReason}
      >
        {quarantined ? "Release quarantine" : "Quarantine"}
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        destructive={!quarantined}
        title={quarantined ? `Release ${agent.name} from quarantine?` : `Quarantine ${agent.name}?`}
        confirmLabel={quarantined ? "Release" : "Quarantine agent"}
        onConfirm={confirm}
      >
        {quarantined ? (
          <p>The status returns to active and the reserved label “quarantined” is removed, so quarantine policies stop matching this agent. The change is audited.</p>
        ) : (
          <>
            <p>{q.explanation}</p>
            {hasFullPolicy ? (
              <p className="text-fg">
                Enforced by{" "}
                {q.policies
                  .filter((p) => p.scope === "all_calls")
                  .map((p) => (
                    <EntityLink key={p.id} type="policy" id={p.id} label={p.name} />
                  ))}
                .
              </p>
            ) : (
              <div className="rounded border border-border bg-surface-2/60 p-3">
                <Checkbox label={<span className="text-fg">Also create the policy “{q.suggested_policy.name}”</span>} checked={withPolicy} onChange={setWithPolicy} />
                <p className="mt-1.5 pl-5 text-xs">
                  DENY, enforce mode, matching <code className="font-mono text-fg">agent.labels contains "{q.label}"</code>. It applies to every quarantined agent and can be edited in
                  Policy Studio.
                </p>
              </div>
            )}
            <p className="text-xs">Events reported after the fact (observed) are still recorded; they cannot be prevented. The change is audited.</p>
          </>
        )}
      </ConfirmDialog>
    </>
  );
}

/** Shown while the agent is quarantined: whether the quarantine is actually enforced, and how to enforce it. */
export function QuarantineBanner({ agent, canManage }: { agent: AgentDetail; canManage: boolean }) {
  const q = agent.quarantine;
  const createPolicy = useCreateQuarantinePolicy();
  const toast = useToast();
  if (!q.active) return null;

  const create = async () => {
    try {
      const policy = await createPolicy.mutateAsync(q.suggested_policy);
      toast.success(`Created “${policy.name}”`, "Quarantined agents' tool calls are now denied at enforcing integrations.");
    } catch (err) {
      toast.error("Couldn’t create the policy", err instanceof Error ? err.message : undefined);
    }
  };

  return (
    <div role="status" className={cn("mb-5 flex flex-wrap items-start gap-3 rounded-md border px-4 py-3", q.enforced ? "border-dec-deny/35 bg-dec-deny/10" : "border-warn/40 bg-warn/10")}>
      {q.enforced ? <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-dec-deny" aria-hidden /> : <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-warn" aria-hidden />}
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-medium text-fg">{q.enforced ? "Quarantined — enforced by policy" : "Quarantined — not enforced"}</div>
        <p className="mt-0.5 text-xs text-fg-muted">{q.explanation}</p>
        {q.policies.length > 0 && (
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
            {q.policies.map((p) => (
              <span key={p.id} className="inline-flex items-center gap-1">
                <EntityLink type="policy" id={p.id} label={p.name} />
                <span className="text-fg-faint">({p.scope === "all_calls" ? "every call" : "some calls"})</span>
              </span>
            ))}
          </div>
        )}
      </div>
      {!q.enforced && canManage && (
        <Button size="sm" variant="primary" onClick={create} loading={createPolicy.isPending}>
          Create blocking policy
        </Button>
      )}
    </div>
  );
}
