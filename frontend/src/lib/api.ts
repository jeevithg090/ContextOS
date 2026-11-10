/**
 * Thin, typed fetch client for the ContextOS API.
 *
 * - Same-origin requests to /api/v1 (Vite proxies to the backend in dev; the backend serves the
 *   built app in production).
 * - Authenticated by the httpOnly session cookie; every request carries the CSRF header.
 * - Errors are normalised to ApiError with the server's {error: {code, message, details}} envelope.
 *
 * Feature code should wrap these calls in TanStack Query hooks inside features/<name>/api.ts.
 */

export const API_BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  code: string;
  details: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

type Query = Record<string, string | number | boolean | null | undefined | string[]>;

export function buildQuery(params?: Query): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => search.append(key, v));
    else search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

let onUnauthenticated: (() => void) | null = null;
export function setUnauthenticatedHandler(handler: () => void) {
  onUnauthenticated = handler;
}

async function request<T>(method: string, path: string, body?: unknown, query?: Query): Promise<T> {
  const headers: Record<string, string> = { "X-Requested-With": "contextos", Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}${buildQuery(query)}`, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "network_error", "Cannot reach the ContextOS API. Is the backend running?");
  }
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  const data = text ? safeJson(text) : undefined;
  if (!response.ok) {
    const err = (data as { error?: { code?: string; message?: string; details?: unknown } })?.error;
    if (response.status === 401 && onUnauthenticated) onUnauthenticated();
    throw new ApiError(response.status, err?.code ?? "http_error", err?.message ?? `Request failed (${response.status})`, err?.details);
  }
  return data as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export const api = {
  get: <T>(path: string, query?: Query) => request<T>("GET", path, undefined, query),
  post: <T>(path: string, body?: unknown, query?: Query) => request<T>("POST", path, body ?? {}, query),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body ?? {}),
  delete: <T>(path: string) => request<T>("DELETE", path),
};

/** Trigger a browser download of JSON/text produced client-side (e.g. exported evidence). */
export function downloadFile(filename: string, content: string, mime = "application/json") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
