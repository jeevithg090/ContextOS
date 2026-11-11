/**
 * Context Explorer — answers "what information entered my agents, and from where?".
 * Items view: every piece of context an agent received (files, pages, tool output, prompts), with its
 * trust at ingest and what detection found. Sources view: where that context came from.
 * State lives in the URL (see filters.ts); ?item=<id> and ?src=<id> open the detail drawers.
 */
import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { Database, FileText } from "lucide-react";
import { Checkbox, PageHeader } from "@/components/ui";
import { SegmentedControl } from "@/components/data";
import { readView, type ExplorerView } from "./filters";
import { ItemDrawer } from "./ItemDrawer";
import { ItemsView } from "./ItemsView";
import { SourceDrawer } from "./SourceDrawer";
import { SourcesView } from "./SourcesView";

export function ContextExplorerPage() {
  const [params, setParams] = useSearchParams();
  const view = readView(params);
  const itemId = params.get("item");
  const sourceId = params.get("src");
  const includeSimulated = params.get("sim") === "1";

  /** Filter changes replace the history entry; opening a drawer or switching view pushes one. */
  const update = useCallback(
    (fn: (p: URLSearchParams) => URLSearchParams, push = false) => setParams((prev) => fn(new URLSearchParams(prev)), { replace: !push }),
    [setParams],
  );
  const setKey = (key: string, value: string | null, push = true) =>
    update((p) => {
      if (value) p.set(key, value);
      else p.delete(key);
      return p;
    }, push);

  const switchView = (next: ExplorerView) =>
    update((p) => {
      const kept = new URLSearchParams();
      if (next === "sources") kept.set("view", "sources");
      if (p.get("sim")) kept.set("sim", "1");
      return kept;
    }, true);

  return (
    <>
      <PageHeader
        eyebrow="Context Explorer"
        title="What information entered my agents?"
        description="Every file, page, tool result, MCP response and prompt an integration reported, with where it came from, how ContextOS classified it on arrival and what detection found. Content is redacted before storage; each item carries a signed receipt."
      />
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <SegmentedControl<ExplorerView>
          aria-label="Explorer view"
          value={view}
          onChange={switchView}
          size="md"
          options={[
            { value: "items", label: "Items", icon: <FileText /> },
            { value: "sources", label: "Sources", icon: <Database /> },
          ]}
        />
        <Checkbox label="Include simulations" checked={includeSimulated} onChange={(on) => setKey("sim", on ? "1" : null, false)} />
      </div>

      {view === "items" ? (
        <ItemsView params={params} update={update} selectedId={itemId} onOpen={(id) => setKey("item", id)} />
      ) : (
        <SourcesView params={params} update={update} selectedId={sourceId} onOpen={(id) => setKey("src", id)} />
      )}

      <ItemDrawer itemId={itemId} onClose={() => setKey("item", null, false)} />
      <SourceDrawer
        sourceId={itemId ? null : sourceId}
        includeSimulated={includeSimulated}
        onClose={() => setKey("src", null, false)}
        onOpenItem={(id) =>
          update((p) => {
            p.delete("src");
            p.set("item", id);
            return p;
          }, true)
        }
      />
    </>
  );
}
