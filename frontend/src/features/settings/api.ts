/**
 * Settings data hooks. Backend contract: backend/app/api/routes/admin.py (prefix /org).
 *   GET    /org                      -> Org (read)
 *   PATCH  /org/settings             -> Org (admin)
 *   GET    /org/members              -> Page<Member> (read, signed-in users)
 *   POST   /org/members              -> Member (admin)
 *   PATCH  /org/members/{id}         -> Member (admin; owner changes need an owner)
 *   DELETE /org/members/{id}         -> 204 (admin)
 *   GET    /org/api-keys             -> Page<ApiKey> (admin)
 *   POST   /org/api-keys             -> ApiKeyCreated (admin; raw key returned once)
 *   DELETE /org/api-keys/{id}        -> 204 (admin; revokes)
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Page } from "@/lib/api";
import type { Role } from "@/lib/domain";

export type FailMode = "closed" | "open" | "ask";
export type DefaultDecision = "ALLOW" | "AUDIT";
export type ApiKeyScope = "ingest" | "decide" | "read";

export interface OrgSettings {
  retention_days: number;
  fail_mode: FailMode;
  default_decision: DefaultDecision;
  approval_timeout_s: number;
  store_previews: boolean;
}

export interface Org {
  id: string;
  name: string;
  slug: string;
  created_at: string;
  settings: OrgSettings;
  member_count: number;
  active_api_key_count: number;
}

export type OrgSettingsPatch = Partial<OrgSettings> & { name?: string };

export interface Member {
  id: string;
  user_id: string;
  name: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface NewMember {
  email: string;
  name: string;
  role: Role;
  password?: string;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: ApiKeyScope[];
  agent_id: string | null;
  agent_name: string | null;
  created_by_user_id: string | null;
  created_by_name: string | null;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  status: "active" | "expired" | "revoked";
}

export interface ApiKeyCreated extends ApiKey {
  /** The raw key. Returned exactly once; the server stores only its hash. */
  key: string;
}

export interface NewApiKey {
  name: string;
  scopes: ApiKeyScope[];
  agent_id?: string | null;
  expires_in_days?: number | null;
}

export interface AgentOption {
  id: string;
  name: string;
  framework?: string | null;
  environment?: string | null;
}

export const settingsKeys = {
  org: ["settings", "org"] as const,
  members: ["settings", "members"] as const,
  apiKeys: ["settings", "api-keys"] as const,
};

export function useOrg() {
  return useQuery({ queryKey: settingsKeys.org, queryFn: () => api.get<Org>("/org") });
}

export function useUpdateOrgSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (patch: OrgSettingsPatch) => api.patch<Org>("/org/settings", patch),
    onSuccess: (org, patch) => {
      qc.setQueryData(settingsKeys.org, org);
      // The organisation name is shown in the app header (from /auth/me).
      if (patch.name !== undefined) void qc.invalidateQueries({ queryKey: ["auth", "me"] });
    },
  });
}

export function useMembers() {
  return useQuery({
    queryKey: settingsKeys.members,
    queryFn: () => api.get<Page<Member>>("/org/members", { limit: 500 }),
  });
}

function useMemberMutation<TVars, TResult>(fn: (vars: TVars) => Promise<TResult>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: settingsKeys.members });
      void qc.invalidateQueries({ queryKey: settingsKeys.org });
      // Your own role may have changed.
      void qc.invalidateQueries({ queryKey: ["auth", "me"] });
    },
  });
}

export function useAddMember() {
  return useMemberMutation((body: NewMember) => api.post<Member>("/org/members", body));
}

export function useUpdateMemberRole() {
  return useMemberMutation(({ id, role }: { id: string; role: Role }) => api.patch<Member>(`/org/members/${encodeURIComponent(id)}`, { role }));
}

export function useRemoveMember() {
  return useMemberMutation((id: string) => api.delete<void>(`/org/members/${encodeURIComponent(id)}`));
}

export function useApiKeys(enabled: boolean) {
  return useQuery({
    queryKey: settingsKeys.apiKeys,
    queryFn: () => api.get<Page<ApiKey>>("/org/api-keys", { limit: 500 }),
    enabled,
  });
}

function useApiKeyMutation<TVars, TResult>(fn: (vars: TVars) => Promise<TResult>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: settingsKeys.apiKeys });
      void qc.invalidateQueries({ queryKey: settingsKeys.org });
    },
  });
}

export function useCreateApiKey() {
  return useApiKeyMutation((body: NewApiKey) => api.post<ApiKeyCreated>("/org/api-keys", body));
}

export function useRevokeApiKey() {
  return useApiKeyMutation((id: string) => api.delete<void>(`/org/api-keys/${encodeURIComponent(id)}`));
}

/** Agents for the API-key binding picker. Query key starts with "agents" so live updates refresh it. */
export function useAgentOptions(enabled: boolean) {
  return useQuery({
    queryKey: ["agents", "settings-options"],
    queryFn: () => api.get<Page<AgentOption>>("/agents", { limit: 200 }),
    enabled,
    retry: false,
  });
}
