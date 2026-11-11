/** Rules tab: trust rules in evaluation order, with enable toggles, editing and deletion. */
import { useMemo, useState } from "react";
import { Pencil, Plus, ScanSearch, Trash2 } from "lucide-react";
import { Badge, Button, IconButton, TrustBadge, useToast } from "@/components/ui";
import { ConfirmDialog, DataTable, FilterBar, FilterSelect, SearchInput, SegmentedControl, type DataTableColumn } from "@/components/data";
import { pluralize } from "@/lib/format";
import { errorMessage, useDeleteRule, useTrustRules, useUpdateRule } from "./api";
import { CapabilityChips, Switch } from "./components";
import { reassessMessage, sourceTypeLabel } from "./meta";
import { RuleDialog } from "./RuleDialog";
import type { TrustRule } from "./types";
import type { SetParams } from "./urlState";

type ScopeFilter = "all" | "source" | "destination";

function scopeLabel(rule: TrustRule): string {
  const scope = rule.applies_to === "both" ? "Sources and destinations" : rule.applies_to === "source" ? "Sources" : "Destinations";
  return rule.source_type && rule.applies_to !== "destination" ? `${scope} · ${sourceTypeLabel(rule.source_type)}` : scope;
}

export function RulesTab({ params, set, canManage }: { params: URLSearchParams; set: SetParams; canManage: boolean }) {
  const toast = useToast();
  const rules = useTrustRules();
  const update = useUpdateRule();
  const remove = useDeleteRule();
  const [pending, setPending] = useState<ReadonlySet<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = useState<TrustRule | null>(null);
  const scope = (params.get("rscope") ?? "all") as ScopeFilter;
  const q = (params.get("rq") ?? "").toLowerCase();
  const status = params.get("rstatus") ?? "";
  const openRule = params.get("rule");

  const all = useMemo(() => rules.data?.items ?? [], [rules.data]);
  const items = useMemo(
    () =>
      all.filter(
        (r) =>
          (scope === "all" || r.applies_to === scope || r.applies_to === "both") &&
          (!status || (status === "enabled" ? r.enabled : !r.enabled)) &&
          (!q || `${r.name} ${r.pattern} ${r.description ?? ""}`.toLowerCase().includes(q)),
      ),
    [all, scope, status, q],
  );
  const editing = openRule && openRule !== "new" ? all.find((r) => r.id === openRule) ?? null : null;

  const toggle = async (rule: TrustRule, enabled: boolean) => {
    setPending((s) => new Set(s).add(rule.id));
    try {
      const saved = await update.mutateAsync({ id: rule.id, patch: { enabled } });
      toast.success(`“${saved.name}” ${enabled ? "enabled" : "disabled"}`, reassessMessage(saved.reassessment));
    } catch (err) {
      toast.error(`Couldn’t update “${rule.name}”`, errorMessage(err));
    } finally {
      setPending((s) => {
        const next = new Set(s);
        next.delete(rule.id);
        return next;
      });
    }
  };

  const columns: Array<DataTableColumn<TrustRule>> = [
    { key: "priority", header: "Priority", align: "right", width: 72, render: (r) => <span className="num text-fg-muted">{r.priority}</span> },
    {
      key: "name",
      header: "Rule",
      render: (r) => (
        <div className="min-w-0 max-w-[340px]">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className={r.enabled ? "font-medium text-fg" : "font-medium text-fg-faint"}>{r.name}</span>
            {r.is_default && <Badge>Default</Badge>}
            {r.is_override && <Badge tone="accent">Pinned destination</Badge>}
          </div>
          {r.description && (
            <div className="truncate text-2xs text-fg-faint" title={r.description}>
              {r.description}
            </div>
          )}
        </div>
      ),
    },
    { key: "scope", header: "Applies to", hideBelow: "lg", render: (r) => <span className="text-xs text-fg-muted">{scopeLabel(r)}</span> },
    {
      key: "pattern",
      header: "Matches",
      render: (r) => (
        <code className="block max-w-[260px] truncate font-mono text-xs text-fg" title={`${r.match_field}: ${r.pattern}`}>
          <span className="text-fg-faint">{r.match_field}:</span> {r.pattern}
        </code>
      ),
    },
    { key: "level", header: "Level", render: (r) => <TrustBadge level={r.trust_level} /> },
    {
      key: "grants",
      header: "Grants",
      hideBelow: "md",
      render: (r) =>
        r.applies_to === "destination" ? (
          <Badge tone={r.capabilities.includes("send") ? "allow" : "neutral"}>{r.capabilities.includes("send") ? "Send" : "No sending"}</Badge>
        ) : (
          <CapabilityChips capabilities={r.capabilities} />
        ),
    },
    {
      key: "usage",
      header: "Classifies now",
      hideBelow: "lg",
      render: (r) =>
        r.classified_sources || r.classified_destinations ? (
          <span className="text-xs text-fg-muted">
            {[r.classified_sources ? pluralize(r.classified_sources, "source") : "", r.classified_destinations ? pluralize(r.classified_destinations, "destination") : ""]
              .filter(Boolean)
              .join(" · ")}
          </span>
        ) : (
          <span className="text-xs text-fg-faint">Nothing</span>
        ),
    },
    {
      key: "enabled",
      header: "On",
      render: (r) => <Switch checked={r.enabled} onCheckedChange={(v) => void toggle(r, v)} label={`${r.enabled ? "Disable" : "Enable"} ${r.name}`} disabled={!canManage || pending.has(r.id)} />,
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      render: (r) => (
        <span className="inline-flex items-center gap-0.5">
          <IconButton label={canManage ? `Edit ${r.name}` : `View ${r.name}`} onClick={() => set({ rule: r.id }, { push: true })}>
            <Pencil className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          {canManage && (
            <IconButton label={`Delete ${r.name}`} onClick={() => setConfirmDelete(r)} className="hover:text-danger">
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
            </IconButton>
          )}
        </span>
      ),
    },
  ];

  const enabledCount = all.filter((r) => r.enabled).length;
  return (
    <div>
      <FilterBar
        onClear={() => set({ rscope: null, rq: null, rstatus: null })}
        canClear={scope !== "all" || !!q || !!status}
        actions={
          <>
            {rules.data && (
              <span className="num text-xs text-fg-muted">
                {pluralize(all.length, "rule")} · {enabledCount} enabled
              </span>
            )}
            {canManage && (
              <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => set({ rule: "new" }, { push: true })}>
                New rule
              </Button>
            )}
          </>
        }
      >
        <SegmentedControl<ScopeFilter>
          aria-label="Rule scope"
          value={scope}
          onChange={(v) => set({ rscope: v === "all" ? null : v })}
          options={[
            { value: "all", label: "All" },
            { value: "source", label: "Sources" },
            { value: "destination", label: "Destinations" },
          ]}
        />
        <SearchInput value={params.get("rq") ?? ""} onChange={(v) => set({ rq: v.trim() || null })} placeholder="Search name, pattern or description" label="Search rules" className="w-64" shortcut={false} />
        <FilterSelect label="Status" value={status} onChange={(v) => set({ rstatus: v || null })} options={[{ value: "enabled", label: "Enabled" }, { value: "disabled", label: "Disabled" }]} />
      </FilterBar>
      {rules.data && openRule && openRule !== "new" && !editing && (
        <div role="status" className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-surface-2/60 px-3 py-2 text-xs text-fg-muted">
          <span>The linked trust rule does not exist in this organisation. It may have been deleted; deletions are recorded in the audit log.</span>
          <Button size="xs" variant="ghost" onClick={() => set({ rule: null })}>
            Dismiss
          </Button>
        </div>
      )}
      <div className="panel">
        <DataTable
          aria-label="Trust rules in evaluation order"
          columns={columns}
          rows={items}
          rowKey={(r) => r.id}
          onRowClick={(r) => set({ rule: r.id }, { push: true })}
          selectedKey={openRule}
          loading={rules.isLoading}
          error={rules.error}
          onRetry={() => void rules.refetch()}
          rowClassName={(r) => (r.enabled ? undefined : "opacity-70")}
          empty={
            all.length
              ? { title: "No rules match these filters" }
              : {
                  icon: <ScanSearch className="h-5 w-5" aria-hidden />,
                  title: "No trust rules",
                  description: "Without rules every web page, file and MCP server is UNKNOWN: its content is data, never instructions. Add rules for the sources your organisation controls.",
                  action: canManage ? (
                    <Button size="sm" variant="primary" onClick={() => set({ rule: "new" }, { push: true })}>
                      Create a rule
                    </Button>
                  ) : undefined,
                }
          }
        />
      </div>
      <p className="pt-2 text-2xs text-fg-faint">
        Rules are listed in the order they are evaluated. Changing a rule re-assesses stored sources (except manually classified ones) and destinations
        immediately; the pipeline applies it to everything observed from then on.
      </p>

      {(openRule === "new" || editing) && (
        <RuleDialog key={editing?.id ?? "new"} open rule={editing} canManage={canManage} onClose={() => set({ rule: null })} />
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        onOpenChange={(o) => !o && setConfirmDelete(null)}
        title={`Delete “${confirmDelete?.name ?? ""}”?`}
        description={
          confirmDelete
            ? `${confirmDelete.is_default ? "This is one of the default rules. " : ""}It currently classifies ${pluralize(confirmDelete.classified_sources, "source")} and ${pluralize(confirmDelete.classified_destinations, "destination")}.`
            : undefined
        }
        confirmLabel="Delete rule"
        destructive
        onConfirm={async () => {
          if (!confirmDelete) return;
          const result = await remove.mutateAsync(confirmDelete.id);
          toast.success(`Rule “${confirmDelete.name}” deleted`, reassessMessage(result.reassessment));
        }}
      >
        <p>Everything it classifies is re-assessed with the remaining rules right away. Disable the rule instead if you may want it back. The deletion is audited.</p>
      </ConfirmDialog>
    </div>
  );
}
