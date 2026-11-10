/**
 * Plain-language descriptions for roles, API-key scopes and organisation settings.
 * Mirrors backend/app/domain/enums.py (ROLE_PERMISSIONS, API_KEY_SCOPES) — keep them in sync.
 */
import type { Role } from "@/lib/domain";
import type { ApiKeyScope, DefaultDecision, FailMode } from "./api";

export const ROLE_META: Record<Role, { label: string; summary: string; permissions: string[] }> = {
  owner: {
    label: "Owner",
    summary: "Full control, including granting and removing the owner role. Every organisation keeps at least one owner.",
    permissions: ["read", "write", "approve", "policy:manage", "trust:manage", "admin"],
  },
  admin: {
    label: "Admin",
    summary: "Manages members, API keys and organisation settings, plus everything an analyst can do. Cannot change owners.",
    permissions: ["read", "write", "approve", "policy:manage", "trust:manage", "admin"],
  },
  security_analyst: {
    label: "Security analyst",
    summary: "Triages findings and incidents, decides approval requests, and edits policies and trust rules.",
    permissions: ["read", "write", "approve", "policy:manage", "trust:manage"],
  },
  developer: {
    label: "Developer",
    summary: "Sees all security data and works findings, incidents and engineering tasks. Cannot approve actions or change policy.",
    permissions: ["read", "write"],
  },
  viewer: {
    label: "Viewer",
    summary: "Read-only access to the organisation's security data.",
    permissions: ["read"],
  },
};

export const ROLE_ORDER: Role[] = ["owner", "admin", "security_analyst", "developer", "viewer"];

export const PERMISSION_LABELS: Record<string, string> = {
  read: "View data",
  write: "Triage & tasks",
  approve: "Decide approvals",
  "policy:manage": "Edit policies",
  "trust:manage": "Edit trust",
  admin: "Administer",
};

export const SCOPE_META: Record<ApiKeyScope, { label: string; description: string }> = {
  ingest: {
    label: "Ingest",
    description: "Report events (POST /events): sessions, context the agent read, tool calls and their results.",
  },
  decide: {
    label: "Decide",
    description: "Ask for a policy decision before a tool runs (POST /decide) and poll pending approvals.",
  },
  read: {
    label: "Read",
    description: "Read this organisation's security data through the API, e.g. for CI checks or exports.",
  },
};

export const SCOPE_ORDER: ApiKeyScope[] = ["ingest", "decide", "read"];

export const FAIL_MODE_META: Record<FailMode, { label: string; description: string }> = {
  closed: {
    label: "Fail closed",
    description: "Deny the tool call. Safest choice; agents stop working while ContextOS is unreachable.",
  },
  ask: {
    label: "Ask",
    description: "Defer to the agent host's own permission prompt, so a person decides while ContextOS is unreachable.",
  },
  open: {
    label: "Fail open",
    description: "Allow the tool call. Agents keep working, but nothing is checked while ContextOS is down.",
  },
};

export const FAIL_MODE_ORDER: FailMode[] = ["closed", "ask", "open"];

export const DEFAULT_DECISION_META: Record<DefaultDecision, { description: string }> = {
  ALLOW: { description: "Tool calls that match no policy are allowed. Matching policies still apply." },
  AUDIT: { description: "Tool calls that match no policy are allowed and flagged for review, so gaps in policy coverage stay visible." },
};

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  if (seconds < 60) return `${seconds} s`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${Number.isInteger(minutes) ? minutes : minutes.toFixed(1)} min`;
  const hours = minutes / 60;
  return `${Number.isInteger(hours) ? hours : hours.toFixed(1)} h`;
}
