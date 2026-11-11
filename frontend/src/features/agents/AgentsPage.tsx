/**
 * Agents — answers "which agents exist, what can they do, how risky are they right now, and who
 * delegates to whom?". Inventory table (URL-driven filters) and the identity & delegation graph.
 */
import { useCallback, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Bot, Plus } from "lucide-react";
import { Button, Card, Checkbox, PageHeader, TabPanel, Tabs } from "@/components/ui";
import { FilterBar, FilterSelect, Pagination, SearchInput } from "@/components/data";
import { useAuth } from "@/features/auth/AuthProvider";
import { pluralize } from "@/lib/format";
import { useAgents } from "./api";
import { AgentsTable } from "./AgentsTable";
import { RegisterAgentDialog } from "./forms/AgentDialogs";
import { AgentGraphView } from "./graph/AgentGraphView";
import { ENVIRONMENT_LABELS, frameworkLabel } from "./meta";
import type { AgentFilters, AgentSort, FacetCount } from "./types";

const SORTS: Array<{ value: AgentSort; label: string }> = [
  { value: "last_seen", label: "Last seen" },
  { value: "risk", label: "Highest session risk" },
  { value: "name", label: "Name" },
  { value: "created", label: "Newest" },
];
const STATUS_LABELS: Record<string, string> = { active: "Active", inactive: "Inactive", quarantined: "Quarantined" };
const PAGE_SIZE = 50;

const options = (facets: FacetCount[] | undefined, label: (v: string) => string) => (facets ?? []).map((f) => ({ value: f.value, label: label(f.value), count: f.count }));

export function AgentsPage() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const [registerOpen, setRegisterOpen] = useState(false);
  const view = params.get("view") === "graph" ? "graph" : "inventory";
  const includeSimulated = params.get("sim") === "1";
  const filters: AgentFilters = {
    q: params.get("q") || undefined,
    environment: params.get("environment") || undefined,
    framework: params.get("framework") || undefined,
    status: params.get("status") || undefined,
    include_simulated: includeSimulated,
    sort: (params.get("sort") as AgentSort) || "last_seen",
    limit: PAGE_SIZE,
    offset: Math.max(0, Number(params.get("offset")) || 0),
  };
  const filtered = !!(filters.q || filters.environment || filters.framework || filters.status);
  const agents = useAgents(filters);
  const facets = agents.data?.facets;

  const setParam = useCallback(
    (key: string, value: string | null, keepOffset = false) =>
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (value) next.set(key, value);
          else next.delete(key);
          if (!keepOffset) next.delete("offset");
          return next;
        },
        { replace: true },
      ),
    [setParams],
  );
  const clear = () =>
    setParams((prev) => {
      const next = new URLSearchParams();
      for (const key of ["view", "sim", "sort"]) if (prev.get(key)) next.set(key, prev.get(key)!);
      return next;
    });

  const hiddenSimulated = !includeSimulated ? (facets?.simulated ?? 0) : 0;
  const empty = filtered
    ? { title: "No agents match these filters", description: "Clear the filters or search for another name, owner or description." }
    : {
        title: "No agents yet",
        description:
          hiddenSimulated > 0
            ? `${pluralize(hiddenSimulated, "Simulation Lab agent")} hidden. Real agents appear when an integration reports its first event.`
            : "Agents appear when an integration reports its first event. Register one now to declare its tools in advance.",
        action:
          hiddenSimulated > 0 ? (
            <Button size="sm" variant="outline" onClick={() => setParam("sim", "1")}>
              Show simulated agents
            </Button>
          ) : can("write") ? (
            <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setRegisterOpen(true)}>
              Register agent
            </Button>
          ) : undefined,
      };

  return (
    <>
      <PageHeader
        title="Agents"
        description="Every agent ContextOS has observed or you registered: what it is declared and seen to do, how risky its active sessions are, and who delegates work to whom."
        actions={
          can("write") && (
            <Button variant="primary" size="sm" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setRegisterOpen(true)}>
              Register agent
            </Button>
          )
        }
      />
      <Tabs
        value={view}
        onValueChange={(v) => setParam("view", v === "graph" ? "graph" : null, true)}
        tabs={[
          { value: "inventory", label: "Inventory", count: agents.data?.total },
          { value: "graph", label: "Identity & delegation graph" },
        ]}
      >
        <TabPanel value="inventory" className="pt-4">
          <FilterBar
            onClear={clear}
            canClear={filtered}
            actions={<Checkbox label={`Include simulated${facets?.simulated ? ` (${facets.simulated})` : ""}`} checked={includeSimulated} onChange={(v) => setParam("sim", v ? "1" : null)} />}
          >
            <SearchInput value={filters.q ?? ""} onChange={(v) => setParam("q", v || null)} placeholder="Search name, owner, description…" className="w-64" />
            <FilterSelect label="Environment" value={filters.environment ?? ""} onChange={(v) => setParam("environment", v || null)} options={options(facets?.environments, (v) => ENVIRONMENT_LABELS[v] ?? v)} />
            <FilterSelect label="Framework" value={filters.framework ?? ""} onChange={(v) => setParam("framework", v || null)} options={options(facets?.frameworks, frameworkLabel)} />
            <FilterSelect label="Status" value={filters.status ?? ""} onChange={(v) => setParam("status", v || null)} options={options(facets?.statuses, (v) => STATUS_LABELS[v] ?? v)} />
            <FilterSelect label="Sort" value={filters.sort ?? "last_seen"} onChange={(v) => setParam("sort", v === "last_seen" ? null : v)} options={SORTS} allLabel={null} />
          </FilterBar>
          <Card className="overflow-hidden">
            <AgentsTable rows={agents.data?.items} loading={agents.isLoading} error={agents.error} onRetry={() => agents.refetch()} empty={{ ...empty }} />
          </Card>
          {agents.data && (
            <Pagination total={agents.data.total} limit={PAGE_SIZE} offset={filters.offset} onChange={(o) => setParam("offset", o ? String(o) : null, true)} itemLabel="agents" />
          )}
        </TabPanel>
        <TabPanel value="graph" className="pt-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <p className="flex items-center gap-2 text-xs text-fg-muted">
              <Bot className="h-3.5 w-3.5" aria-hidden />
              Select an agent to open it, or a relationship to see when it was observed.
            </p>
            <Checkbox label="Include simulated" checked={includeSimulated} onChange={(v) => setParam("sim", v ? "1" : null, true)} />
          </div>
          {view === "graph" && <AgentGraphView includeSimulated={includeSimulated} />}
        </TabPanel>
      </Tabs>
      <RegisterAgentDialog open={registerOpen} onOpenChange={setRegisterOpen} />
    </>
  );
}
