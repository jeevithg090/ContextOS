import { Link } from "react-router-dom";
import { Sparkles } from "lucide-react";
import { PageHeader, TabPanel, Tabs } from "@/components/ui";
import { oneOf, useUrlState } from "../analytics/useUrlState";
import { useAiCatalogue, usePrompts, useTemplates } from "./api";
import { PrivacyNote } from "./controls";
import { SavedPromptsTab } from "./SavedPromptsTab";
import { TemplatesTab } from "./TemplatesTab";

const TABS = ["templates", "prompts"] as const;
type LibraryTab = (typeof TABS)[number];

/** "Reusable fix-prompt templates and saved prompts." */
export function PromptLibraryPage() {
  const { get, set } = useUrlState();
  const tab: LibraryTab = oneOf(get("tab"), TABS, "templates");
  const catalogue = useAiCatalogue();
  const templates = useTemplates();
  const promptCount = usePrompts({ limit: 1 });

  return (
    <>
      <PageHeader
        eyebrow="Engineering Workspace"
        title="Prompt Library"
        description="Templates capture how a coding agent should work on a kind of task. Saved prompts are the exact text generated for a task, with your edits."
        actions={
          <Link to="/work/fix-context" className="inline-flex h-8 items-center gap-2 rounded bg-accent px-3 text-[13px] font-medium text-accent-fg hover:bg-accent-strong">
            <Sparkles className="h-3.5 w-3.5" aria-hidden />
            New fix prompt
          </Link>
        }
      />
      <PrivacyNote detail={catalogue.data?.privacy_note} className="mb-4" />
      <Tabs
        value={tab}
        onValueChange={(v) => set({ tab: v === "templates" ? null : v, prompt: null, task: null })}
        tabs={[
          { value: "templates", label: "Templates", count: templates.data?.length },
          { value: "prompts", label: "Saved prompts", count: promptCount.data?.total },
        ]}
      >
        <TabPanel value="templates" className="pt-4">
          <TemplatesTab />
        </TabPanel>
        <TabPanel value="prompts" className="pt-4">
          <SavedPromptsTab />
        </TabPanel>
      </Tabs>
    </>
  );
}
