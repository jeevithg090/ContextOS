/**
 * Presentation vocabulary for the Context Explorer: source-type icons and labels, sensitivity tones,
 * detection techniques and provenance relations. Pure (no React state) so it is easy to test.
 */
import {
  AppWindow,
  BookOpen,
  Bot,
  CircleHelp,
  Cog,
  Database,
  FileText,
  GitBranch,
  Globe,
  Mail,
  MessageSquare,
  Plug,
  Server,
  SquareTerminal,
  Upload,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import type { Tone } from "@/lib/domain";
import type { ContextReceipt } from "./types";

export const SOURCE_TYPE_META: Record<string, { label: string; icon: LucideIcon }> = {
  web: { label: "Web page", icon: Globe },
  repository: { label: "Repository", icon: GitBranch },
  file: { label: "File", icon: FileText },
  document: { label: "Document", icon: BookOpen },
  email: { label: "Email", icon: Mail },
  api: { label: "API response", icon: Plug },
  mcp_server: { label: "MCP server", icon: Server },
  mcp_tool: { label: "MCP tool", icon: Wrench },
  browser: { label: "Browser page", icon: AppWindow },
  database: { label: "Database", icon: Database },
  user_upload: { label: "Uploaded file", icon: Upload },
  user_prompt: { label: "User prompt", icon: MessageSquare },
  tool_output: { label: "Tool output", icon: SquareTerminal },
  agent_output: { label: "Agent output", icon: Bot },
  system: { label: "System prompt", icon: Cog },
  other: { label: "Other", icon: CircleHelp },
};

export const SOURCE_TYPES = Object.keys(SOURCE_TYPE_META);

export function sourceTypeMeta(type: string | null | undefined) {
  return SOURCE_TYPE_META[type ?? ""] ?? SOURCE_TYPE_META.other;
}

export const SENSITIVITY_META: Record<string, { label: string; tone: Tone; description: string }> = {
  public: { label: "Public", tone: "neutral", description: "No sensitive markers were found." },
  internal: { label: "Internal", tone: "neutral", description: "Ordinary internal content." },
  confidential: { label: "Confidential", tone: "medium", description: "Contains personal data or low-confidence secret-like values." },
  secret: { label: "Secret", tone: "high", description: "Contains a credential or a secret seen earlier in the session." },
};
export const SENSITIVITIES = ["secret", "confidential", "internal", "public"] as const;

export function sensitivityMeta(value: string | null | undefined) {
  return SENSITIVITY_META[value ?? ""] ?? { label: value ?? "—", tone: "neutral" as Tone, description: "" };
}

/** How a detection was revealed (normalisation layer the engine matched on). */
export function techniqueLabel(technique: string): string {
  if (technique.startsWith("multilingual:")) return `Non-English text (${technique.split(":")[1]})`;
  const labels: Record<string, string> = {
    plain: "Visible text",
    zero_width: "Hidden with zero-width characters",
    homoglyph: "Look-alike characters",
    base64: "Base64-encoded",
    url_encoded: "URL-encoded",
    html_comment: "Hidden in an HTML comment",
    hidden_text: "Hidden (invisible) text",
    leetspeak: "Leetspeak spelling",
    reflowed: "Hard-wrapped lines re-joined",
  };
  return labels[technique] ?? technique.replace(/_/g, " ");
}

export const RELATION_LABELS: Record<string, string> = {
  source_produced_item: "produced",
  item_entered_session: "entered",
  invocation_returned_item: "returned",
  agent_messaged: "sent as a message",
  item_triggered_finding: "triggered",
};

export function relationLabel(relation: string): string {
  return RELATION_LABELS[relation] ?? relation.replace(/_/g, " ");
}

/** Row label for a group of edges seen from the item's side ("Returned by", "Triggered"). */
export function relationGroupLabel(relation: string, outgoing: boolean): string {
  const labels: Record<string, string> = {
    "invocation_returned_item:in": "Returned by",
    "agent_messaged:in": "Sent from",
    "item_triggered_finding:out": "Triggered",
    "source_produced_item:in": "Produced by",
    "item_entered_session:out": "Entered",
  };
  return labels[`${relation}:${outgoing ? "out" : "in"}`] ?? `${outgoing ? "" : "From: "}${relationLabel(relation)}`;
}

export function formatLength(chars: number): string {
  if (chars < 1000) return `${chars} chars`;
  if (chars < 1_000_000) return `${(chars / 1000).toFixed(chars < 10_000 ? 1 : 0)}k chars`;
  return `${(chars / 1_000_000).toFixed(1)}M chars`;
}

/** Signed difference between server receive time and client collection time, in words. */
export function describeSkew(seconds: number): string {
  const abs = Math.abs(seconds);
  const amount = abs < 1 ? `${Math.round(abs * 1000)} ms` : abs < 120 ? `${abs.toFixed(1)} s` : `${Math.round(abs / 60)} min`;
  if (abs < 0.0005) return "Received at the reported collection time";
  return seconds >= 0 ? `Received ${amount} after the reported collection time` : `Reported collection time is ${amount} after the server received it (client clock ahead)`;
}

/** The JSON a user downloads with "Export receipt": the signed fields plus how to verify them. */
export function receiptExport(receipt: ContextReceipt): string {
  return JSON.stringify(
    {
      kind: "contextos.context_receipt",
      receipt: receipt.receipt,
      signature: receipt.signature,
      signature_algorithm: receipt.verification.algorithm,
      signature_purpose: receipt.verification.purpose,
      verification_at_export: { status: receipt.verification.status, checked_at: receipt.generated_at },
      canonicalization: "JSON of `receipt` with sorted keys, compact separators (',' ':'), UTF-8, no NaN",
      statement: receipt.statement,
      is_simulation: receipt.is_simulation,
    },
    null,
    2,
  );
}

export function receiptFilename(itemId: string): string {
  return `context-receipt-${itemId.replace(/[^A-Za-z0-9_-]/g, "_")}.json`;
}
