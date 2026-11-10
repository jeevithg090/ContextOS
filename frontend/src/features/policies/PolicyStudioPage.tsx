/**
 * Policy Studio — answers "what are agents allowed to do?". Lists every policy in evaluation
 * precedence with its mode, state and recorded match counts, and opens the editor drawer
 * (deep link: ?policy=<id>, or ?policy=new).
 */
import { useCallback, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Plus, ScrollText } from "lucide-react";
import { Button, EmptyState, ErrorState, LoadingRows, PageHeader, useToast } from "@/components/ui";
import { ConfirmDialog, FilterBar, FilterSelect, SearchInput } from "@/components/data";
import { useAuth } from "@/features/auth/AuthProvider";
import { DECISIONS, DECISION_META, type Decision } from "@/lib/domain";
import { pluralize } from "@/lib/format";
import { usePolicies, useUpdatePolicy } from "./api";
import { stopsEnforcingDeny } from "./draft";
import { ModesBanner } from "./ModesBanner";
import { PolicyEditorDrawer } from "./PolicyEditorDrawer";
import { PolicyTable } from "./PolicyTable";
import type { Policy, PolicyFilters, PolicyMode, PolicyPatch } from "./types";

const STATUS = { "": undefined, enabled: true, disabled: false } as const;
const SOURCE = { "": undefined, builtin: true, custom: false } as const;

export function PolicyStudioPage() {
  const { can } = useAuth();
  const canManage = can("policy:manage");
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const openId = params.get("policy");

  const outcome = params.get("outcome") ?? "";
  const mode = params.get("mode") ?? "";
  const status = (params.get("status") ?? "") as keyof typeof STATUS;
  const source = (params.get("source") ?? "") as keyof typeof SOURCE;
  const q = params.get("q") ?? "";
  const filters: PolicyFilters = {
    outcome: (outcome || undefined) as Decision | undefined,
    mode: (mode || undefined) as PolicyMode | undefined,
    enabled: STATUS[status] ?? undefined,
    builtin: SOURCE[source] ?? undefined,
    q: q || undefined,
  };
  const filtered = !!(outcome || mode || status || source || q);
  const policies = usePolicies(filters);

  const setParam = useCallback(
    (key: string, value: string | null) =>
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (value) next.set(key, value);
          else next.delete(key);
          return next;
        },
        { replace: key !== "policy" },
      ),
    [setParams],
  );
  const clearFilters = () =>
    setParams((prev) => {
      const next = new URLSearchParams();
      const policy = prev.get("policy");
      if (policy) next.set("policy", policy);
      return next;
    });

  // Inline toggles (mode / enabled), with confirmation before an enforced DENY stops blocking.
  const update = useUpdatePolicy();
  const [pendingIds, setPendingIds] = useState<ReadonlySet<string>>(new Set());
  const [confirmStop, setConfirmStop] = useState<{ policy: Policy; patch: PolicyPatch } | null>(null);
  const applyPatch = async (policy: Policy, patch: PolicyPatch) => {
    setPendingIds((s) => new Set(s).add(policy.id));
    try {
      const saved = await update.mutateAsync({ id: policy.id, patch });
      const what = "enabled" in patch ? (saved.enabled ? "enabled" : "disabled") : `switched to ${saved.mode} mode`;
      toast.success(`“${saved.name}” ${what}`, `Now at version ${saved.version}.`);
    } catch (err) {
      toast.error(`Couldn’t update “${policy.name}”`, err instanceof Error ? err.message : undefined);
      throw err;
    } finally {
      setPendingIds((s) => {
        const next = new Set(s);
        next.delete(policy.id);
        return next;
      });
    }
  };
  const requestPatch = (policy: Policy, patch: PolicyPatch) => {
    if (stopsEnforcingDeny(policy, patch)) setConfirmStop({ policy, patch });
    else void applyPatch(policy, patch).catch(() => undefined);
  };

  const items = policies.data?.items ?? [];
  const enabledCount = items.filter((p) => p.enabled).length;
  const enforcing = items.filter((p) => p.enabled && p.mode === "enforce").length;

  let content;
  if (policies.isLoading) content = <LoadingRows rows={8} />;
  else if (policies.error) content = <ErrorState error={policies.error} onRetry={() => void policies.refetch()} />;
  else if (!items.length)
    content = filtered ? (
      <EmptyState title="No policies match these filters" action={<Button size="sm" variant="outline" onClick={clearFilters}>Clear filters</Button>} />
    ) : (
      <EmptyState
        icon={<ScrollText className="h-5 w-5" aria-hidden />}
        title="No policies yet"
        description="Without policies every tool call gets the organisation's default decision. Create a policy to deny, pause for approval, restrict or audit specific calls."
        action={canManage ? <Button size="sm" variant="primary" onClick={() => setParam("policy", "new")}>Create policy</Button> : undefined}
      />
    );
  else
    content = (
      <PolicyTable
        policies={items}
        canManage={canManage}
        pendingIds={pendingIds}
        onOpen={(id) => setParam("policy", id)}
        onSetEnabled={(p, enabled) => requestPatch(p, { enabled })}
        onSetMode={(p, m) => requestPatch(p, { mode: m })}
      />
    );

  return (
    <>
      <PageHeader
        eyebrow="Policy Studio"
        title="What are agents allowed to do?"
        description="Policies are evaluated on every tool call an integration asks ContextOS to decide. Each one matches conditions on the redacted request and the session's recorded risk, then denies, pauses for approval, restricts, audits or allows it."
        actions={
          canManage && (
            <Button variant="primary" size="sm" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setParam("policy", "new")}>
              New policy
            </Button>
          )
        }
      />
      <div className="space-y-4">
        <ModesBanner />
        <FilterBar
          onClear={clearFilters}
          canClear={filtered}
          actions={
            policies.data && (
              <span className="num text-xs text-fg-muted">
                {pluralize(policies.data.total, "policy", "policies")} · {enabledCount} enabled · {enforcing} enforcing
              </span>
            )
          }
        >
          <SearchInput value={q} onChange={(v) => setParam("q", v.trim() || null)} placeholder="Search name or description" label="Search policies" className="w-64" />
          <FilterSelect label="Outcome" value={outcome} onChange={(v) => setParam("outcome", v || null)} options={DECISIONS.map((d) => ({ value: d, label: DECISION_META[d].label }))} />
          <FilterSelect label="Mode" value={mode} onChange={(v) => setParam("mode", v || null)} options={[{ value: "enforce", label: "Enforce" }, { value: "monitor", label: "Monitor" }]} />
          <FilterSelect label="Status" value={status} onChange={(v) => setParam("status", v || null)} options={[{ value: "enabled", label: "Enabled" }, { value: "disabled", label: "Disabled" }]} />
          <FilterSelect label="Source" value={source} onChange={(v) => setParam("source", v || null)} options={[{ value: "builtin", label: "Built-in" }, { value: "custom", label: "Custom" }]} />
        </FilterBar>
        {content}
        <p className="text-2xs text-fg-faint">
          Match counts come from recorded decisions in the last 7 days; simulated decisions from the Simulation Lab are counted separately.
        </p>
      </div>

      {openId && <PolicyEditorDrawer policyId={openId} onClose={() => setParam("policy", null)} onCreated={(id) => setParam("policy", id)} />}

      <ConfirmDialog
        open={!!confirmStop}
        onOpenChange={(o) => !o && setConfirmStop(null)}
        title={confirmStop?.patch.enabled === false ? "Disable this DENY policy?" : "Switch this DENY policy to monitor mode?"}
        description={confirmStop ? `“${confirmStop.policy.name}” currently blocks matching tool calls where integrations enforce decisions.` : undefined}
        confirmLabel={confirmStop?.patch.enabled === false ? "Disable policy" : "Switch to monitor"}
        destructive
        onConfirm={async () => {
          if (confirmStop) await applyPatch(confirmStop.policy, confirmStop.patch);
        }}
      >
        <p>
          {confirmStop?.patch.enabled === false
            ? "It will stop being evaluated. Calls it denies today will receive the next strongest matching outcome, or the default."
            : "Matches will only be recorded; calls it denies today will receive the next strongest matching outcome, or the default."}
        </p>
      </ConfirmDialog>
    </>
  );
}
