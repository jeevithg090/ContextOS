/**
 * Trust Centre — answers "which sources and destinations do we trust, and for what?".
 * Header summary (classification per level, sources with findings, recent downgrades), then tabs:
 * Sources | Destinations | Rules | Tester. Deep links: ?tab=, ?source=<id>, ?destination=<id>, ?rule=<id|new>,
 * ?sim=1 (also count and list sources and destinations only Simulation Lab traffic observed).
 */
import { Checkbox, PageHeader, TabPanel, Tabs } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import type { TrustLevel } from "@/lib/domain";
import { useTrustSummary } from "./api";
import { DestinationDrawer } from "./DestinationDrawer";
import { DestinationsTab } from "./DestinationsTab";
import { RulesTab } from "./RulesTab";
import { SourceDrawer } from "./SourceDrawer";
import { SourcesTab } from "./SourcesTab";
import { TesterTab } from "./TesterTab";
import { TrustSummaryPanel } from "./TrustSummaryPanel";
import { includeSimulatedParam, useTrustParams } from "./urlState";

const TABS = ["sources", "destinations", "rules", "tester"] as const;
type Tab = (typeof TABS)[number];

export function TrustCentrePage() {
  const { can } = useAuth();
  const canManage = can("trust:manage");
  const { params, set } = useTrustParams();
  const includeSimulated = includeSimulatedParam(params);
  const summary = useTrustSummary(includeSimulated);
  const requested = params.get("tab");
  const tab: Tab = (TABS as readonly string[]).includes(requested ?? "")
    ? (requested as Tab)
    : params.get("destination")
      ? "destinations"
      : params.get("rule")
        ? "rules"
        : "sources";
  const sourceId = params.get("source");
  const destinationId = params.get("destination");

  const openSource = (id: string) => set({ source: id, destination: null }, { push: true });
  const openDestination = (id: string) => set({ destination: id, source: null }, { push: true });

  return (
    <>
      <PageHeader
        eyebrow="Trust Centre"
        title="Which sources and destinations do we trust, and for what?"
        description="Every piece of context an agent reads is classified by source, and every place it sends data by destination. Trust is contextual: a source approved for reading is not trusted to give instructions, and only TRUSTED content may direct the agent."
        actions={<Checkbox label="Include simulated" checked={includeSimulated} onChange={(on) => set({ sim: on ? "1" : null })} />}
      />
      <div className="space-y-5">
        <TrustSummaryPanel
          includeSimulated={includeSimulated}
          onSourceLevel={(level: TrustLevel) => set({ tab: "sources", slevel: level })}
          onDestinationLevel={(level: TrustLevel) => set({ tab: "destinations", dlevel: level })}
          onOpenSource={openSource}
          onOpenDestination={openDestination}
        />
        <Tabs
          value={tab}
          onValueChange={(v) => set({ tab: v === "sources" ? null : v })}
          tabs={[
            { value: "sources", label: "Sources", count: summary.data?.sources.total },
            { value: "destinations", label: "Destinations", count: summary.data?.destinations.total },
            { value: "rules", label: "Rules", count: summary.data?.rules.total },
            { value: "tester", label: "Tester" },
          ]}
        >
          <TabPanel value="sources" className="pt-4">
            <SourcesTab params={params} set={set} onOpen={openSource} />
          </TabPanel>
          <TabPanel value="destinations" className="pt-4">
            <DestinationsTab params={params} set={set} onOpen={openDestination} />
          </TabPanel>
          <TabPanel value="rules" className="pt-4">
            <RulesTab params={params} set={set} canManage={canManage} />
          </TabPanel>
          <TabPanel value="tester" className="pt-4">
            <TesterTab />
          </TabPanel>
        </Tabs>
      </div>

      {sourceId && <SourceDrawer key={sourceId} sourceId={sourceId} onClose={() => set({ source: null })} />}
      {destinationId && <DestinationDrawer key={destinationId} destinationId={destinationId} onClose={() => set({ destination: null })} />}
    </>
  );
}
