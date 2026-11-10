/**
 * Session state. Backend contract (implemented in backend/app/api/routes/auth.py):
 *   GET  /auth/me            -> Me
 *   POST /auth/login         {email, password} -> Me  (sets httpOnly cookie)
 *   POST /auth/logout        -> 204
 *   GET  /auth/setup-status  -> {needs_setup: boolean}
 *   POST /auth/setup         {organization_name, name, email, password} -> Me (first run only)
 */
import { createContext, useContext, useEffect, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, setUnauthenticatedHandler } from "@/lib/api";

export interface Me {
  user: { id: string; email: string; name: string };
  organization: { id: string; name: string; slug: string };
  role: string;
  permissions: string[];
  memberships: Array<{ organization_id: string; organization_name: string; role: string }>;
}

interface AuthState {
  me: Me | null;
  loading: boolean;
  can: (permission: string) => boolean;
  refresh: () => Promise<unknown>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const meQuery = useQuery({
    queryKey: ["auth", "me"],
    queryFn: async (): Promise<Me | null> => {
      try {
        return await api.get<Me>("/auth/me");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    staleTime: 60_000,
    retry: false,
  });

  useEffect(() => {
    setUnauthenticatedHandler(() => qc.setQueryData<Me | null>(["auth", "me"], null));
  }, [qc]);

  const me = meQuery.data ?? null;
  const value: AuthState = {
    me,
    loading: meQuery.isLoading,
    can: (permission) => !!me?.permissions.includes(permission),
    refresh: () => meQuery.refetch(),
    logout: async () => {
      try {
        await api.post("/auth/logout");
      } finally {
        qc.clear();
        qc.setQueryData<Me | null>(["auth", "me"], null);
      }
    },
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
