/** Route table. Each feature owns its page component under src/features/<feature>/. */
import { lazy } from "react";
import type { RouteObject } from "react-router-dom";

const p = <T extends Record<string, unknown>>(loader: () => Promise<T>, name: keyof T) =>
  lazy(() => loader().then((m) => ({ default: m[name] as React.ComponentType })));

const OverviewPage = p(() => import("@/features/overview/OverviewPage"), "OverviewPage");
const AgentsPage = p(() => import("@/features/agents/AgentsPage"), "AgentsPage");
const AgentDetailPage = p(() => import("@/features/agents/AgentDetailPage"), "AgentDetailPage");
const SessionDetailPage = p(() => import("@/features/agents/SessionDetailPage"), "SessionDetailPage");
const ContextExplorerPage = p(() => import("@/features/context/ContextExplorerPage"), "ContextExplorerPage");
const ContextReceiptPage = p(() => import("@/features/context/ContextReceiptPage"), "ContextReceiptPage");
const ProvenancePage = p(() => import("@/features/provenance/ProvenancePage"), "ProvenancePage");
const TrustCentrePage = p(() => import("@/features/trust/TrustCentrePage"), "TrustCentrePage");
const IntelligencePage = p(() => import("@/features/intelligence/IntelligencePage"), "IntelligencePage");
const FindingDetailPage = p(() => import("@/features/intelligence/FindingDetailPage"), "FindingDetailPage");
const PolicyStudioPage = p(() => import("@/features/policies/PolicyStudioPage"), "PolicyStudioPage");
const ApprovalCentrePage = p(() => import("@/features/approvals/ApprovalCentrePage"), "ApprovalCentrePage");
const IncidentsPage = p(() => import("@/features/incidents/IncidentsPage"), "IncidentsPage");
const IncidentDetailPage = p(() => import("@/features/incidents/IncidentDetailPage"), "IncidentDetailPage");
const ReplayLabPage = p(() => import("@/features/replay/ReplayLabPage"), "ReplayLabPage");
const SimulationLabPage = p(() => import("@/features/simulation/SimulationLabPage"), "SimulationLabPage");
const IntegrationsPage = p(() => import("@/features/integrations/IntegrationsPage"), "IntegrationsPage");
const AuditLogPage = p(() => import("@/features/audit/AuditLogPage"), "AuditLogPage");
const SettingsPage = p(() => import("@/features/settings/SettingsPage"), "SettingsPage");

const MyWorkPage = p(() => import("@/features/workspace/MyWorkPage"), "MyWorkPage");
const BoardsPage = p(() => import("@/features/workspace/boards/BoardsPage"), "BoardsPage");
const BoardPage = p(() => import("@/features/workspace/boards/BoardPage"), "BoardPage");
const AllTasksPage = p(() => import("@/features/workspace/AllTasksPage"), "AllTasksPage");
const TaskPage = p(() => import("@/features/workspace/tasks/TaskPage"), "TaskPage");
const RemediationPage = p(() => import("@/features/workspace/RemediationPage"), "RemediationPage");
const FixContextPage = p(() => import("@/features/workspace/ai/FixContextPage"), "FixContextPage");
const PromptLibraryPage = p(() => import("@/features/workspace/ai/PromptLibraryPage"), "PromptLibraryPage");
const ContextPacksPage = p(() => import("@/features/workspace/ai/ContextPacksPage"), "ContextPacksPage");
const EngineeringAnalyticsPage = p(() => import("@/features/workspace/EngineeringAnalyticsPage"), "EngineeringAnalyticsPage");

export const appRoutes: RouteObject[] = [
  { index: true, element: <OverviewPage /> },
  { path: "agents", element: <AgentsPage /> },
  { path: "agents/:agentId", element: <AgentDetailPage /> },
  { path: "sessions/:sessionId", element: <SessionDetailPage /> },
  { path: "context", element: <ContextExplorerPage /> },
  { path: "context/:itemId", element: <ContextReceiptPage /> },
  { path: "provenance", element: <ProvenancePage /> },
  { path: "trust", element: <TrustCentrePage /> },
  { path: "intelligence", element: <IntelligencePage /> },
  { path: "intelligence/:findingId", element: <FindingDetailPage /> },
  { path: "policies", element: <PolicyStudioPage /> },
  { path: "approvals", element: <ApprovalCentrePage /> },
  { path: "incidents", element: <IncidentsPage /> },
  { path: "incidents/:incidentId", element: <IncidentDetailPage /> },
  { path: "replay", element: <ReplayLabPage /> },
  { path: "replay/:sessionId", element: <ReplayLabPage /> },
  { path: "simulation", element: <SimulationLabPage /> },
  { path: "integrations", element: <IntegrationsPage /> },
  { path: "audit", element: <AuditLogPage /> },
  { path: "settings", element: <SettingsPage /> },
  { path: "work/my", element: <MyWorkPage /> },
  { path: "work/boards", element: <BoardsPage /> },
  { path: "work/boards/:boardId", element: <BoardPage /> },
  { path: "work/tasks", element: <AllTasksPage /> },
  { path: "work/tasks/:taskId", element: <TaskPage /> },
  { path: "work/remediation", element: <RemediationPage /> },
  { path: "work/fix-context", element: <FixContextPage /> },
  { path: "work/fix-context/:taskId", element: <FixContextPage /> },
  { path: "work/prompts", element: <PromptLibraryPage /> },
  { path: "work/context-packs", element: <ContextPacksPage /> },
  { path: "work/analytics", element: <EngineeringAnalyticsPage /> },
];
