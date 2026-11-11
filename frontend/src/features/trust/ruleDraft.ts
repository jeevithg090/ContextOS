/** Editable trust-rule draft: conversion to/from the API shape and client-side checks (the server
 * re-validates everything, including over-broad patterns and credentials). */
import type { TrustLevel } from "@/lib/domain";
import { capabilityAllowed, capabilityProblems, defaultCapabilities } from "./meta";
import type { AppliesTo, Capability, MatchField, SourceType, TrustRule, TrustRuleInput } from "./types";

export interface RuleDraft {
  name: string;
  description: string;
  applies_to: AppliesTo;
  source_type: SourceType | "";
  match_field: MatchField;
  pattern: string;
  trust_level: TrustLevel;
  capabilities: Capability[];
  priority: string;
  enabled: boolean;
}

export function emptyDraft(): RuleDraft {
  return {
    name: "",
    description: "",
    applies_to: "source",
    source_type: "",
    match_field: "domain",
    pattern: "",
    trust_level: "APPROVED",
    capabilities: defaultCapabilities("APPROVED", "source"),
    priority: "100",
    enabled: true,
  };
}

export function draftFromRule(rule: TrustRule): RuleDraft {
  return {
    name: rule.name,
    description: rule.description ?? "",
    applies_to: rule.applies_to,
    source_type: (rule.source_type as SourceType | null) ?? "",
    match_field: rule.match_field,
    pattern: rule.pattern,
    trust_level: rule.trust_level,
    capabilities: rule.capabilities,
    priority: String(rule.priority),
    enabled: rule.enabled,
  };
}

/** Changing the level or scope resets capabilities to that level's defaults (as the server does). */
export function withLevel(draft: RuleDraft, level: TrustLevel): RuleDraft {
  return { ...draft, trust_level: level, capabilities: defaultCapabilities(level, draft.applies_to) };
}

export function withScope(draft: RuleDraft, appliesTo: AppliesTo): RuleDraft {
  return {
    ...draft,
    applies_to: appliesTo,
    source_type: appliesTo === "destination" ? "" : draft.source_type,
    capabilities: defaultCapabilities(draft.trust_level, appliesTo),
  };
}

export function parsePriority(value: string): number | null {
  if (!/^\d{1,6}$/.test(value.trim())) return null;
  const n = Number(value.trim());
  return n >= 0 && n <= 100_000 ? n : null;
}

export function draftToInput(draft: RuleDraft): TrustRuleInput {
  return {
    name: draft.name.trim(),
    description: draft.description.trim() || null,
    applies_to: draft.applies_to,
    source_type: draft.applies_to === "destination" ? null : draft.source_type || null,
    match_field: draft.match_field,
    pattern: draft.pattern.trim(),
    trust_level: draft.trust_level,
    capabilities: draft.capabilities.filter((c) => capabilityAllowed(draft.trust_level, c)),
    priority: parsePriority(draft.priority) ?? 100,
    enabled: draft.enabled,
  };
}

/** Problems the user can fix before saving. */
export function draftProblems(draft: RuleDraft): string[] {
  const problems: string[] = [];
  if (!draft.name.trim()) problems.push("Give the rule a name.");
  if (!draft.pattern.trim()) problems.push("Enter a pattern.");
  if (draft.match_field === "domain" && /[/@:\s]/.test(draft.pattern.trim()))
    problems.push("A domain pattern matches host names only (e.g. *.acme.com). Use “Identifier” to match URLs or paths.");
  if (parsePriority(draft.priority) === null) problems.push("Priority must be a whole number from 0 to 100000.");
  problems.push(...capabilityProblems(draft.trust_level, draft.applies_to, draft.capabilities));
  return problems;
}

export const PATTERN_HELP: Record<MatchField, { summary: string; examples: Array<[string, string]> }> = {
  domain: {
    summary: "Matches the host name or its registrable domain. “*.” at the start covers the domain itself and every sub-domain.",
    examples: [
      ["*.acme.com", "acme.com, docs.acme.com, a.b.acme.com"],
      ["docs.python.org", "only that host"],
      ["api.*.acme.com", "api.eu.acme.com, api.eu.west.acme.com"],
    ],
  },
  identifier: {
    summary:
      "Matches the canonical identifier: a URL (scheme ignored), file path, repository (github.com/org/repo), email address or MCP name (server or server/tool). “*” stays within one path segment, a trailing “/*” covers everything below, “**” crosses segments.",
    examples: [
      ["github.com/acme/*", "every Acme repository, not github.com/acme-evil"],
      ["https://wiki.acme.com/eng/*", "that wiki section"],
      ["/srv/app/**", "every file below /srv/app"],
    ],
  },
};
