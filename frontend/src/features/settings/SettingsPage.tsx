import type { ReactElement } from "react";
import { useSearchParams } from "react-router-dom";
import { ErrorState, LoadingRows, PageHeader, TabPanel, Tabs } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { useOrg } from "./api";
import { ApiKeysTab } from "./ApiKeysTab";
import { MembersTab } from "./MembersTab";
import { OrganisationTab } from "./OrganisationTab";
import { PrivacyTab } from "./PrivacyTab";

const TABS = ["organisation", "members", "api-keys", "privacy"] as const;
type Tab = (typeof TABS)[number];

function isTab(value: string | null): value is Tab {
  return !!value && (TABS as readonly string[]).includes(value);
}

/** Organisation settings, members, API keys and data handling. Tab is kept in `?tab=` so it can be linked. */
export function SettingsPage() {
  const { can, me } = useAuth();
  const canAdmin = can("admin");
  const org = useOrg();
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab: Tab = isTab(raw) ? raw : "organisation";

  const showTab = (next: string) => {
    const nextParams = new URLSearchParams(params);
    if (next === "organisation") nextParams.delete("tab");
    else nextParams.set("tab", next);
    setParams(nextParams, { replace: true });
  };

  const orgView = (render: (data: NonNullable<typeof org.data>) => ReactElement) =>
    org.isLoading ? <LoadingRows rows={6} /> : org.isError || !org.data ? <ErrorState error={org.error} onRetry={() => void org.refetch()} /> : render(org.data);

  return (
    <>
      <PageHeader
        title="Settings"
        description={
          <>
            Configuration for <span className="text-fg">{org.data?.name ?? me?.organization.name}</span>: enforcement defaults, who has access,
            integration credentials and how data is handled.
          </>
        }
      />
      <Tabs
        value={tab}
        onValueChange={showTab}
        tabs={[
          { value: "organisation", label: "Organisation" },
          { value: "members", label: "Members", count: org.data?.member_count },
          { value: "api-keys", label: "API keys", count: canAdmin ? org.data?.active_api_key_count : undefined },
          { value: "privacy", label: "Data & privacy" },
        ]}
      >
        <TabPanel value="organisation" className="pt-5">
          {orgView((data) => (
            <OrganisationTab org={data} canAdmin={canAdmin} onShowTab={showTab} />
          ))}
        </TabPanel>
        <TabPanel value="members" className="pt-5">
          <MembersTab />
        </TabPanel>
        <TabPanel value="api-keys" className="pt-5">
          <ApiKeysTab canAdmin={canAdmin} />
        </TabPanel>
        <TabPanel value="privacy" className="pt-5">
          {orgView((data) => (
            <PrivacyTab org={data} canAdmin={canAdmin} />
          ))}
        </TabPanel>
      </Tabs>
    </>
  );
}
