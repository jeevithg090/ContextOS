/**
 * Agents & sessions data hooks. Backend contract: backend/app/api/routes/{agents,sessions}.py.
 *   GET   /agents                       -> AgentPage (read; q, environment, framework, status, include_simulated, sort)
 *   POST  /agents                       -> AgentDetail (write; declared tools classified server-side)
 *   GET   /agents/graph                 -> AgentGraph (read; include_simulated)
 *   GET   /agents/{id}                  -> AgentDetail
 *   PATCH /agents/{id}                  -> AgentDetail (write; environment/labels/status also need policy:manage)
 *   GET   /agents/{id}/sessions         -> Page<SessionSummary>
 *   GET   /agents/{id}/tools            -> Page<AgentTool>
 *   GET   /agents/{id}/posture          -> AgentPosture
 *   GET   /sessions                     -> Page<SessionSummary> (agent_id, status, min_risk, trifecta, include_simulated, q, sort)
 *   GET   /sessions/{id}                -> SessionDetail
 *   GET   /sessions/{id}/timeline       -> TimelinePage (limit, offset, invocation_id)
 *   POST  /policies                     -> creates the suggested quarantine policy (policy:manage)
 * Query keys start with "agents" / "sessions" so live agent.updated / session.updated events refresh them.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Page } from "@/lib/api";
import type {
  AgentCreateInput,
  AgentDetail,
  AgentFilters,
  AgentGraph,
  AgentPage,
  AgentPatchInput,
  AgentPosture,
  AgentTool,
  SessionDetail,
  SessionFilters,
  SessionSort,
  SessionSummary,
  SuggestedPolicy,
  TimelinePage,
} from "./types";

const enc = encodeURIComponent;
const notFound = (count: number, err: unknown) => !(err instanceof ApiError && (err.status === 404 || err.status === 403)) && count < 2;

export const agentKeys = {
  all: ["agents"] as const,
  list: (filters: AgentFilters) => ["agents", "list", filters] as const,
  detail: (id: string) => ["agents", "detail", id] as const,
  tools: (id: string) => ["agents", "tools", id] as const,
  posture: (id: string) => ["agents", "posture", id] as const,
  sessions: (id: string, params: Record<string, unknown>) => ["agents", "sessions", id, params] as const,
  graph: (includeSimulated: boolean) => ["agents", "graph", includeSimulated] as const,
};

export const sessionKeys = {
  all: ["sessions"] as const,
  list: (filters: SessionFilters) => ["sessions", "list", filters] as const,
  detail: (id: string) => ["sessions", "detail", id] as const,
  timeline: (id: string, params: Record<string, unknown>) => ["sessions", "timeline", id, params] as const,
};

/** Field-level messages from a 422 envelope. */
export function validationMessages(error: unknown): string[] {
  if (!(error instanceof ApiError) || error.status !== 422 || !Array.isArray(error.details)) return [];
  return (error.details as Array<{ loc?: unknown[]; msg?: string }>).map(
    (d) => `${(d.loc ?? []).slice(1).join(".") || "request"}: ${(d.msg ?? "invalid").replace(/^Value error, /, "")}`,
  );
}

/* ----------------------------------------------------------------------------- agents */

export function useAgents(filters: AgentFilters) {
  return useQuery({
    queryKey: agentKeys.list(filters),
    queryFn: () => api.get<AgentPage>("/agents", { ...filters }),
    placeholderData: keepPreviousData,
  });
}

export function useAgent(id: string | undefined) {
  return useQuery({
    queryKey: agentKeys.detail(id ?? ""),
    queryFn: () => api.get<AgentDetail>(`/agents/${enc(id ?? "")}`),
    enabled: !!id,
    retry: notFound,
  });
}

export function useAgentTools(id: string | undefined) {
  return useQuery({
    queryKey: agentKeys.tools(id ?? ""),
    queryFn: () => api.get<Page<AgentTool>>(`/agents/${enc(id ?? "")}/tools`, { limit: 500 }),
    enabled: !!id,
    retry: notFound,
  });
}

export function useAgentPosture(id: string | undefined) {
  return useQuery({
    queryKey: agentKeys.posture(id ?? ""),
    queryFn: () => api.get<AgentPosture>(`/agents/${enc(id ?? "")}/posture`),
    enabled: !!id,
    retry: notFound,
  });
}

export function useAgentSessions(id: string | undefined, params: { status?: string; sort?: SessionSort; limit: number; offset: number }) {
  return useQuery({
    queryKey: agentKeys.sessions(id ?? "", params),
    queryFn: () => api.get<Page<SessionSummary>>(`/agents/${enc(id ?? "")}/sessions`, { ...params }),
    enabled: !!id,
    placeholderData: keepPreviousData,
    retry: notFound,
  });
}

export function useAgentGraph(includeSimulated: boolean, enabled = true) {
  return useQuery({
    queryKey: agentKeys.graph(includeSimulated),
    queryFn: () => api.get<AgentGraph>("/agents/graph", { include_simulated: includeSimulated }),
    enabled,
  });
}

export function useRegisterAgent() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AgentCreateInput) => api.post<AgentDetail>("/agents", body),
    onSuccess: (agent) => {
      qc.setQueryData(agentKeys.detail(agent.id), agent);
      qc.invalidateQueries({ queryKey: agentKeys.all });
    },
  });
}

export function useUpdateAgent(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (patch: AgentPatchInput) => api.patch<AgentDetail>(`/agents/${enc(id)}`, patch),
    onSuccess: (agent) => {
      qc.setQueryData(agentKeys.detail(agent.id), agent);
      qc.invalidateQueries({ queryKey: agentKeys.all });
    },
  });
}

/** Creates the server-suggested DENY policy on the reserved quarantine label (Policy Studio API). */
export function useCreateQuarantinePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (policy: SuggestedPolicy) => api.post<{ id: string; name: string }>("/policies", policy),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: agentKeys.all });
      qc.invalidateQueries({ queryKey: ["policies"] });
    },
  });
}

/* ----------------------------------------------------------------------------- sessions */

export function useSessions(filters: SessionFilters) {
  return useQuery({
    queryKey: sessionKeys.list(filters),
    queryFn: () => api.get<Page<SessionSummary>>("/sessions", { ...filters }),
    placeholderData: keepPreviousData,
  });
}

export function useSession(id: string | undefined) {
  return useQuery({
    queryKey: sessionKeys.detail(id ?? ""),
    queryFn: () => api.get<SessionDetail>(`/sessions/${enc(id ?? "")}`),
    enabled: !!id,
    retry: notFound,
  });
}

export function useSessionTimeline(id: string | undefined, params: { limit: number; offset: number; invocation_id?: string }) {
  return useQuery({
    queryKey: sessionKeys.timeline(id ?? "", params),
    queryFn: () => api.get<TimelinePage>(`/sessions/${enc(id ?? "")}/timeline`, { ...params }),
    enabled: !!id,
    placeholderData: keepPreviousData,
    retry: notFound,
  });
}
