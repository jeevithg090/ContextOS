/**
 * Route table. Each feature owns its page component under src/features/<feature>/; every page is
 * code-split (React.lazy) and rendered inside its own Suspense boundary, so only the code for the
 * screen being opened is downloaded. `handle.title` names the browser tab (see AppShell).
 */
import { lazy, Suspense, type ComponentType, type LazyExoticComponent } from "react";
import type { RouteObject } from "react-router-dom";
import { PageLoading } from "./PageLoading";

export interface RouteHandle {
  /** Browser-tab title for the route ("<title> · ContextOS"); pages may refine it with useDocumentTitle. */
  title: string;
}

/** One lazy component per page export, shared by routes that render the same page (/replay, /replay/:id). */
const lazyPages = new Map<string, LazyExoticComponent<ComponentType>>();

function lazyPage<M extends Record<string, unknown>>(loader: () => Promise<M>, name: keyof M & string) {
  let Page = lazyPages.get(name);
  if (!Page) {
    Page = lazy(() =>
      loader().then((module) => {
        const component = module[name];
        if (typeof component !== "function" && (typeof component !== "object" || component === null)) {
          throw new Error(`Page module has no component export named ${name}.`);
        }
        return { default: component as ComponentType };
      }),
    );
    lazyPages.set(name, Page);
  }
  return Page;
}

export interface PageEntry {
  /** URL pattern relative to the shell ("" is the overview at "/"). */
  path: string;
  title: string;
  load: () => Promise<Record<string, unknown>>;
  exportName: string;
}

/** Every routed page with its loader — lets tests prove each route resolves to a real component. */
export const PAGE_MANIFEST: PageEntry[] = [];

/** Route for a lazily loaded page, rendered in its own Suspense boundary with the page loading state. */
function page<M extends Record<string, unknown>>(path: string | undefined, title: string, loader: () => Promise<M>, name: keyof M & string): RouteObject {
  PAGE_MANIFEST.push({ path: path ?? "", title, load: loader, exportName: name });
  const Page = lazyPage(loader, name);
  const handle: RouteHandle = { title };
  const element = (
    <Suspense fallback={<PageLoading label={title} />}>
      <Page />
    </Suspense>
  );
  return path === undefined ? { index: true, element, handle } : { path, element, handle };
}

export const appRoutes: RouteObject[] = [
  page(undefined, "Overview", () => import("@/features/overview/OverviewPage"), "OverviewPage"),
  page("agents", "Agents", () => import("@/features/agents/AgentsPage"), "AgentsPage"),
  page("agents/:agentId", "Agent", () => import("@/features/agents/AgentDetailPage"), "AgentDetailPage"),
  page("sessions/:sessionId", "Session", () => import("@/features/agents/SessionDetailPage"), "SessionDetailPage"),
  page("context", "Context Explorer", () => import("@/features/context/ContextExplorerPage"), "ContextExplorerPage"),
  page("context/:itemId", "Context receipt", () => import("@/features/context/ContextReceiptPage"), "ContextReceiptPage"),
  page("provenance", "Provenance Graph", () => import("@/features/provenance/ProvenancePage"), "ProvenancePage"),
  page("trust", "Trust Centre", () => import("@/features/trust/TrustCentrePage"), "TrustCentrePage"),
  page("intelligence", "Security Intelligence", () => import("@/features/intelligence/IntelligencePage"), "IntelligencePage"),
  page("intelligence/:findingId", "Finding", () => import("@/features/intelligence/FindingDetailPage"), "FindingDetailPage"),
  page("policies", "Policy Studio", () => import("@/features/policies/PolicyStudioPage"), "PolicyStudioPage"),
  page("approvals", "Approval Centre", () => import("@/features/approvals/ApprovalCentrePage"), "ApprovalCentrePage"),
  page("incidents", "Incidents", () => import("@/features/incidents/IncidentsPage"), "IncidentsPage"),
  page("incidents/:incidentId", "Incident", () => import("@/features/incidents/IncidentDetailPage"), "IncidentDetailPage"),
  page("replay", "Replay Lab", () => import("@/features/replay/ReplayLabPage"), "ReplayLabPage"),
  page("replay/:sessionId", "Replay Lab", () => import("@/features/replay/ReplayLabPage"), "ReplayLabPage"),
  page("simulation", "Simulation Lab", () => import("@/features/simulation/SimulationLabPage"), "SimulationLabPage"),
  page("integrations", "Integrations", () => import("@/features/integrations/IntegrationsPage"), "IntegrationsPage"),
  page("audit", "Audit Log", () => import("@/features/audit/AuditLogPage"), "AuditLogPage"),
  page("settings", "Settings", () => import("@/features/settings/SettingsPage"), "SettingsPage"),
  page("work/my", "My Work", () => import("@/features/workspace/MyWorkPage"), "MyWorkPage"),
  page("work/boards", "Kanban Boards", () => import("@/features/workspace/boards/BoardsPage"), "BoardsPage"),
  page("work/boards/:boardId", "Board", () => import("@/features/workspace/boards/BoardPage"), "BoardPage"),
  page("work/tasks", "All Tasks", () => import("@/features/workspace/AllTasksPage"), "AllTasksPage"),
  page("work/tasks/:taskId", "Task", () => import("@/features/workspace/tasks/TaskPage"), "TaskPage"),
  page("work/remediation", "Security Remediation", () => import("@/features/workspace/RemediationPage"), "RemediationPage"),
  page("work/fix-context", "AI Fix Context", () => import("@/features/workspace/ai/FixContextPage"), "FixContextPage"),
  page("work/fix-context/:taskId", "AI Fix Context", () => import("@/features/workspace/ai/FixContextPage"), "FixContextPage"),
  page("work/prompts", "Prompt Library", () => import("@/features/workspace/ai/PromptLibraryPage"), "PromptLibraryPage"),
  page("work/context-packs", "Context Packs", () => import("@/features/workspace/ai/ContextPacksPage"), "ContextPacksPage"),
  page("work/analytics", "Engineering Analytics", () => import("@/features/workspace/EngineeringAnalyticsPage"), "EngineeringAnalyticsPage"),
];
