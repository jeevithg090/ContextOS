/** Policies grouped by outcome in evaluation precedence, with inline mode / enabled controls. */
import type { MouseEvent } from "react";
import { Badge, DecisionBadge, SeverityBadge, Table, TD, TH, THead, TR } from "@/components/ui";
import { SegmentedControl, Sparkline } from "@/components/data";
import { DECISION_META, decisionTone, type Decision } from "@/lib/domain";
import { cn, formatDateTime, pluralize, timeAgo } from "@/lib/format";
import { Switch } from "./controls";
import { OUTCOME_HELP } from "./DefinitionForm";
import type { Policy, PolicyMode } from "./types";

const PRECEDENCE: Decision[] = ["DENY", "REQUIRE_APPROVAL", "RESTRICT", "AUDIT", "ALLOW"];

export interface PolicyTableProps {
  policies: Policy[];
  canManage: boolean;
  /** Policy ids with a toggle in flight (controls are disabled meanwhile). */
  pendingIds: ReadonlySet<string>;
  onOpen: (id: string) => void;
  onSetEnabled: (policy: Policy, enabled: boolean) => void;
  onSetMode: (policy: Policy, mode: PolicyMode) => void;
}

const stop = (e: MouseEvent) => e.stopPropagation();

function MatchCell({ policy }: { policy: Policy }) {
  const s = policy.stats;
  if (!s) return <span className="text-fg-faint">—</span>;
  const real = s.matched + s.monitor_matched;
  const parts = [
    `${pluralize(s.matched, "enforce match", "enforce matches")}`,
    `${pluralize(s.monitor_matched, "monitor match", "monitor matches")}`,
    `${s.simulated} in simulations`,
  ];
  const title = `Last ${s.window_days} days: ${parts.join(", ")}.${s.last_matched_at ? ` Last real match ${timeAgo(s.last_matched_at)} (${formatDateTime(s.last_matched_at)}).` : ""}`;
  return (
    <div className="flex items-center justify-end gap-2 whitespace-nowrap" title={title}>
      <span className={cn("num text-[13px]", real ? "text-fg" : "text-fg-faint")}>{real}</span>
      {s.simulated > 0 && <span className="num text-2xs text-accent">+{s.simulated} sim</span>}
      <Sparkline data={s.daily} variant="bar" width={48} height={20} tone={real ? decisionTone(policy.outcome) : "neutral"} aria-label={`Real matches per day for ${policy.name}, last ${s.window_days} days`} />
    </div>
  );
}

function PolicyRow({ policy, canManage, pending, onOpen, onSetEnabled, onSetMode }: { policy: Policy; canManage: boolean; pending: boolean } & Omit<PolicyTableProps, "policies" | "canManage" | "pendingIds">) {
  return (
    <TR onClick={() => onOpen(policy.id)} className={cn(!policy.enabled && "opacity-60")}>
      <TD className="w-full min-w-[240px] max-w-0">
        <div className="flex min-w-0 items-center gap-1.5">
          <button
            type="button"
            onClick={(e) => {
              stop(e);
              onOpen(policy.id);
            }}
            className="truncate text-left text-[13px] font-medium text-fg hover:text-accent"
          >
            {policy.name}
          </button>
          {!policy.enabled && <Badge tone="neutral">Disabled</Badge>}
        </div>
        <div className="mt-0.5 flex min-w-0 items-center gap-1.5 text-2xs text-fg-faint">
          {policy.is_builtin && (
            <span className="shrink-0 text-accent" title="Seeded built-in policy. It can be edited or disabled, not deleted.">
              Built-in
            </span>
          )}
          <span className="shrink-0 font-mono" title="Version · priority (ties between equal outcomes go to the higher priority)">
            v{policy.version} · p{policy.priority}
          </span>
          <span className="truncate font-mono" title={policy.explanation}>
            {policy.explanation}
          </span>
        </div>
      </TD>
      <TD>
        <SeverityBadge severity={policy.severity} />
      </TD>
      <TD>
        <div onClick={stop} onKeyDown={(e) => e.stopPropagation()} role="presentation">
          <SegmentedControl<PolicyMode>
            aria-label={`Mode for ${policy.name}`}
            value={policy.mode}
            onChange={(mode) => mode !== policy.mode && onSetMode(policy, mode)}
            options={[
              { value: "enforce", label: "Enforce", disabled: !canManage || pending },
              { value: "monitor", label: "Monitor", disabled: !canManage || pending },
            ]}
          />
        </div>
      </TD>
      <TD>
        <Switch checked={policy.enabled} disabled={!canManage || pending} label={`${policy.enabled ? "Disable" : "Enable"} ${policy.name}`} onCheckedChange={(v) => onSetEnabled(policy, v)} />
      </TD>
      <TD>
        <MatchCell policy={policy} />
      </TD>
    </TR>
  );
}

export function PolicyTable({ policies, canManage, pendingIds, onOpen, onSetEnabled, onSetMode }: PolicyTableProps) {
  const groups = PRECEDENCE.map((outcome) => ({ outcome, items: policies.filter((p) => p.outcome === outcome) })).filter((g) => g.items.length > 0);
  return (
    <div className="space-y-4">
      {groups.map(({ outcome, items }) => (
        <section key={outcome} aria-label={`${DECISION_META[outcome].label} policies`} className="panel overflow-hidden">
          <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
            <DecisionBadge decision={outcome} />
            <span className="text-xs text-fg-muted">{OUTCOME_HELP[outcome]}</span>
            <span className="num ml-auto text-2xs text-fg-faint">
              {items.filter((p) => p.enabled).length} of {pluralize(items.length, "policy", "policies")} enabled
            </span>
          </div>
          <Table>
            <THead>
              <tr>
                <TH>Policy</TH>
                <TH>Severity</TH>
                <TH>Mode</TH>
                <TH>Enabled</TH>
                <TH className="text-right">Matches · 7d</TH>
              </tr>
            </THead>
            <tbody>
              {items.map((p) => (
                <PolicyRow key={p.id} policy={p} canManage={canManage} pending={pendingIds.has(p.id)} onOpen={onOpen} onSetEnabled={onSetEnabled} onSetMode={onSetMode} />
              ))}
            </tbody>
          </Table>
        </section>
      ))}
    </div>
  );
}
