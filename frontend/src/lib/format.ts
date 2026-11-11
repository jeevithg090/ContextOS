import { formatDistanceToNowStrict, format } from "date-fns";

export { cn } from "./cn";

export function timeAgo(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return formatDistanceToNowStrict(new Date(iso), { addSuffix: true });
  } catch {
    return iso;
  }
}

export function formatDateTime(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return format(new Date(iso), "d MMM yyyy, HH:mm:ss");
  } catch {
    return iso;
  }
}

export function formatTime(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return format(new Date(iso), "HH:mm:ss.SSS");
  } catch {
    return iso;
  }
}

export function formatNumber(n?: number | null): string {
  if (n === undefined || n === null) return "—";
  return new Intl.NumberFormat("en-GB", { notation: n >= 10000 ? "compact" : "standard" }).format(n);
}

export function shortId(id?: string | null): string {
  if (!id) return "—";
  const [prefix, body] = id.split("_");
  return body ? `${prefix}_${body.slice(-6)}` : id.slice(-8);
}

export function truncate(value: string | null | undefined, max = 80): string {
  if (!value) return "";
  return value.length > max ? value.slice(0, max - 1) + "…" : value;
}

export function pluralize(n: number, word: string, plural?: string): string {
  return `${n} ${n === 1 ? word : plural ?? word + "s"}`;
}
