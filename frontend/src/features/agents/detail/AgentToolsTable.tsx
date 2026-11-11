import { Badge, DecisionBadge, SeverityBadge } from "@/components/ui";
import { DataTable, type DataTableColumn } from "@/components/data";
import { ENFORCEMENT_META, type EnforcementMode } from "@/lib/domain";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useAgentTools } from "../api";
import { DECISION_ORDER, sortedCounts, toolCategoryLabel } from "../meta";
import type { AgentTool } from "../types";

function Declaration({ tool }: { tool: AgentTool }) {
  if (tool.declared && tool.observed) return <span className="text-xs text-fg-muted">Declared · used</span>;
  if (tool.observed)
    return (
      <Badge tone="warn" title="Used by the agent but missing from its declared configuration">
        Undeclared
      </Badge>
    );
  return <span className="text-xs text-fg-faint">Declared · not used yet</span>;
}

const columns: Array<DataTableColumn<AgentTool>> = [
  {
    key: "name",
    header: "Tool",
    render: (t) => (
      <div className="min-w-0">
        <div className="truncate font-mono text-xs text-fg">{t.name}</div>
        <div className="truncate text-2xs text-fg-faint">{t.server ? `MCP server ${t.server}` : t.provider ?? "declared only"}</div>
      </div>
    ),
  },
  {
    key: "category",
    header: "Category",
    render: (t) => (
      <span className="text-fg-muted" title={t.classification_reason ?? undefined}>
        {toolCategoryLabel(t.category)}
      </span>
    ),
  },
  { key: "risk", header: "Inherent risk", render: (t) => <SeverityBadge severity={t.risk_level} /> },
  { key: "declared", header: "Configuration", hideBelow: "md", render: (t) => <Declaration tool={t} /> },
  { key: "calls", header: "Calls", align: "right", render: (t) => <span className="num">{t.invocation_count}</span> },
  {
    key: "decisions",
    header: "Decisions",
    render: (t) => {
      const entries = sortedCounts(t.decisions, DECISION_ORDER);
      if (!entries.length) return <span className="text-xs text-fg-faint">—</span>;
      return (
        <span className="flex flex-wrap gap-1">
          {entries.map(([decision, n]) => (
            <span key={decision} className="inline-flex items-center gap-1">
              <DecisionBadge decision={decision} />
              <span className="num text-2xs text-fg-muted">{n}</span>
            </span>
          ))}
        </span>
      );
    },
  },
  {
    key: "enforcement",
    header: "Enforcement",
    hideBelow: "lg",
    render: (t) => {
      const entries = sortedCounts(t.enforcement, ["enforced", "advisory", "observed"]);
      if (!entries.length) return <span className="text-xs text-fg-faint">—</span>;
      return (
        <span className="text-xs text-fg-muted">
          {entries.map(([mode, n]) => `${n} ${ENFORCEMENT_META[mode as EnforcementMode]?.label.toLowerCase() ?? mode}`).join(" · ")}
        </span>
      );
    },
  },
  {
    key: "credentials",
    header: "Credential calls",
    align: "right",
    hideBelow: "md",
    render: (t) => (
      <span className={t.credential_calls ? "num text-danger" : "num text-fg-faint"} title="Calls whose arguments carried a credential (stored only in redacted form)">
        {t.credential_calls}
      </span>
    ),
  },
  {
    key: "last",
    header: "Last used",
    align: "right",
    hideBelow: "sm",
    render: (t) =>
      t.last_used_at ? (
        <time dateTime={t.last_used_at} title={formatDateTime(t.last_used_at)} className="text-fg-muted">
          {timeAgo(t.last_used_at)}
        </time>
      ) : (
        <span className="text-xs text-fg-faint">Never</span>
      ),
  },
];

export function AgentToolsTable({ agentId }: { agentId: string }) {
  const tools = useAgentTools(agentId);
  const undeclared = (tools.data?.items ?? []).filter((t) => t.observed && !t.declared).length;
  const anyDeclared = (tools.data?.items ?? []).some((t) => t.declared);
  return (
    <div>
      {undeclared > 0 && anyDeclared && (
        <p className="border-b border-border bg-warn/10 px-4 py-2 text-xs text-fg">
          {undeclared} tool{undeclared === 1 ? " was" : "s were"} used without being declared. Unexpected tool use lowers the permission-exposure posture score; declare the tool or
          investigate why it was used.
        </p>
      )}
      <DataTable
        aria-label="Tools"
        columns={columns}
        rows={tools.data?.items}
        rowKey={(t) => t.tool_id ?? `declared:${t.name}`}
        loading={tools.isLoading}
        error={tools.error}
        onRetry={() => tools.refetch()}
        dense
        manualSort
        empty={{ title: "No tools declared or observed", description: "Tool calls appear here once the integration reports them. Declare tools by editing the agent." }}
      />
      <p className="px-4 py-2 text-2xs text-fg-faint">Category and inherent risk are classified by ContextOS from the tool name; individual calls can be riskier depending on their arguments.</p>
    </div>
  );
}
