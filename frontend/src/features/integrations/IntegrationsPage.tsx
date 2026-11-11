/**
 * Integrations — answers "which frameworks are connected, and what can they enforce?".
 * Connected integrations (health from the last real event), the capability matrix (monitoring vs
 * enforcement with explicit enforced / advisory / observed claims), planned integrations shown as
 * planned, and setup guides. Deep link: ?setup=<kind> selects a guide.
 */
import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { InlineStat } from "@/components/data";
import { ErrorState, LoadingRows, PageHeader } from "@/components/ui";
import { formatNumber } from "@/lib/format";
import { useIntegrations } from "./api";
import { CapabilityMatrix, PlannedIntegrations } from "./CapabilityMatrix";
import { ConnectedIntegrations } from "./ConnectedIntegrations";
import { staleWindowLabel } from "./meta";
import { SetupGuides } from "./SetupGuides";
import type { IntegrationsOverview } from "./types";

function Summary({ data }: { data: IntegrationsOverview }) {
  const live = data.connected.filter((c) => c.health === "connected").length;
  const enforcing = data.connected.filter((c) => c.best_enforcement === "enforced").length;
  const enforced = data.connected.reduce((n, c) => n + c.decisions.enforced, 0);
  const notEnforced = data.connected.reduce((n, c) => n + c.decisions.advisory + c.decisions.observed, 0);
  return (
    <div className="mb-5 flex flex-wrap gap-x-6 gap-y-2" aria-label="Summary">
      <InlineStat label="Connected now" value={`${live} of ${data.connected.length}`} tone={live ? "ok" : undefined} hint={`Integrations with an event in the last ${staleWindowLabel(data)}`} />
      <InlineStat label="Can enforce" value={enforcing} hint="Integrations whose decisions are applied before the tool runs" />
      <InlineStat label="Enforced decisions" value={formatNumber(enforced)} hint="Decisions returned at an enforcing boundary (real traffic)" />
      <InlineStat label="Advisory or observed" value={formatNumber(notEnforced)} tone={notEnforced ? "warn" : undefined} hint="Decisions that could not be enforced: advisory integrations or tool calls reported after they ran" />
    </div>
  );
}

export function IntegrationsPage() {
  const overview = useIntegrations();
  const [params, setParams] = useSearchParams();
  const selected = params.get("setup") || "claude_code";

  const openSetup = useCallback(
    (kind: string) => {
      const next = new URLSearchParams(params);
      next.set("setup", kind);
      setParams(next, { replace: true });
      requestAnimationFrame(() => document.getElementById("setup")?.scrollIntoView({ behavior: "smooth", block: "start" }));
    },
    [params, setParams],
  );
  const selectGuide = (kind: string) => {
    const next = new URLSearchParams(params);
    next.set("setup", kind);
    setParams(next, { replace: true });
  };

  return (
    <>
      <PageHeader
        eyebrow="Integrations"
        title="Which frameworks are connected, and what can they enforce?"
        description="ContextOS only sees what an integration reports, and can only stop what an integration asks about before it acts. This page shows both, per integration, from the events actually received."
      />
      {overview.isLoading ? (
        <div className="panel">
          <LoadingRows rows={6} />
        </div>
      ) : overview.isError || !overview.data ? (
        <div className="panel">
          <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
        </div>
      ) : (
        <>
          <Summary data={overview.data} />
          <div className="space-y-5">
            <ConnectedIntegrations items={overview.data.connected} staleWindow={staleWindowLabel(overview.data)} onSetup={openSetup} />
            <CapabilityMatrix entries={overview.data.catalog} onSetup={openSetup} />
            <PlannedIntegrations entries={overview.data.catalog} onSetup={openSetup} />
            <SetupGuides entries={overview.data.catalog} selected={selected} onSelect={selectGuide} />
          </div>
        </>
      )}
    </>
  );
}
