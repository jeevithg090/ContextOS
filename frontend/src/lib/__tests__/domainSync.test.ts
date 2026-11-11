/**
 * Drift guard: the frontend vocabulary must cover every value the backend can return.
 * Reads backend/app/domain/enums.py and the redaction engine sources directly, so adding an enum
 * value or a secret type on the server without a label here fails this test.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as domain from "@/lib/domain";

// frontend/src/lib/__tests__ → repository root. (Not `new URL(rel, import.meta.url)`: Vite rewrites
// that pattern into an asset URL.)
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const backend = (rel: string) => resolve(ROOT, "backend/app", rel);
const ENUMS = backend("domain/enums.py");
const REDACTION = ["engines/redaction/patterns.py", "engines/redaction/contextual.py", "engines/redaction/engine.py"].map(backend);
const available = existsSync(ENUMS) && REDACTION.every(existsSync);

/** `class Name(StrEnum):` blocks → {Name: [values]}. */
function parseStrEnums(source: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  let current: string | null = null;
  for (const line of source.split("\n")) {
    const head = /^class (\w+)\(StrEnum\):/.exec(line);
    if (head) {
      current = head[1];
      out[current] = [];
      continue;
    }
    if (current && /^\S/.test(line)) current = null;
    const member = current ? /^\s+[A-Z_0-9]+\s*=\s*"([^"]+)"/.exec(line) : null;
    if (current && member) out[current].push(member[1]);
  }
  return out;
}

/** Secret type names: pattern table entries, Candidate(...) literals and assigned kind names. */
function parseSecretTypes(sources: string[]): Set<string> {
  const found = new Set<string>();
  const patterns = [
    /_tp\(\s*"([a-z0-9_]+)"/g,
    /Candidate\(\s*"([a-z0-9_]+)"/g,
    /\bkind(?:, confidence)?\s*=\s*"([a-z0-9_]+)"/g,
    /\belse "([a-z0-9_]+)"/g,
    /^\s*"[a-z_]+":\s*"(generic_[a-z_]+)",?$/gm,
    /\(\s*"[a-z]+=",\s*re\.compile\([^\n]*\),\s*"([a-z0-9_]+)"/g,
    /^SENSITIVE_FIELD\s*=\s*"([a-z_]+)"/gm,
  ];
  for (const source of sources) for (const re of patterns) for (const m of source.matchAll(re)) found.add(m[1]);
  return found;
}

const FRONTEND: Record<string, readonly string[]> = {
  TrustLevel: domain.TRUST_LEVELS,
  TrustCapability: domain.TRUST_CAPABILITIES,
  Decision: domain.DECISIONS,
  PolicyMode: domain.POLICY_MODES,
  EnforcementMode: domain.ENFORCEMENT_MODES,
  Severity: domain.SEVERITIES,
  FindingCategory: domain.FINDING_CATEGORIES,
  FindingStatus: domain.FINDING_STATUSES,
  SourceType: domain.SOURCE_TYPES,
  ToolCategory: domain.TOOL_CATEGORIES,
  Sensitivity: domain.SENSITIVITIES,
  RiskLevel: domain.RISK_LEVELS,
  Role: domain.ROLES,
  Permission: domain.PERMISSIONS,
  EventType: domain.EVENT_TYPES,
  ApprovalStatus: domain.APPROVAL_STATUSES,
  IncidentStatus: domain.INCIDENT_STATUSES,
  ProvenanceNodeType: domain.PROVENANCE_NODE_TYPES,
  ProvenanceRelation: domain.PROVENANCE_RELATIONS,
  TaskPriority: domain.TASK_PRIORITIES,
  TaskType: domain.TASK_TYPES,
  VerificationStatus: domain.VERIFICATION_STATUSES,
};

const LABELS: Record<string, Record<string, unknown>> = {
  TrustLevel: domain.TRUST_META,
  TrustCapability: domain.TRUST_CAPABILITY_LABELS,
  Decision: domain.DECISION_META,
  PolicyMode: domain.POLICY_MODE_META,
  EnforcementMode: domain.ENFORCEMENT_META,
  Severity: domain.SEVERITY_META,
  FindingCategory: domain.FINDING_CATEGORY_LABELS,
  SourceType: domain.SOURCE_TYPE_LABELS,
  ToolCategory: domain.TOOL_CATEGORY_LABELS,
  Sensitivity: domain.SENSITIVITY_META,
  RiskLevel: domain.RISK_LEVEL_META,
  Role: domain.ROLE_LABELS,
  Permission: domain.PERMISSION_LABELS,
  EventType: domain.EVENT_TYPE_LABELS,
  ProvenanceNodeType: domain.PROVENANCE_NODE_LABELS,
  ProvenanceRelation: domain.PROVENANCE_RELATION_LABELS,
  TaskPriority: domain.TASK_PRIORITY_META,
  TaskType: domain.TASK_TYPE_LABELS,
  VerificationStatus: domain.VERIFICATION_STATUS_META,
};

describe.skipIf(!available)("frontend vocabulary mirrors the backend", () => {
  const enums = available ? parseStrEnums(readFileSync(ENUMS, "utf8")) : {};

  it("parses the backend enums", () => {
    expect(Object.keys(enums).length).toBeGreaterThanOrEqual(20);
    expect(enums.TrustLevel).toEqual(["TRUSTED", "APPROVED", "EXTERNAL", "UNKNOWN", "SUSPICIOUS", "BLOCKED"]);
  });

  it("mirrors every backend StrEnum, value for value", () => {
    expect(Object.keys(enums).sort()).toEqual(Object.keys(FRONTEND).sort());
    for (const [name, values] of Object.entries(enums)) {
      expect([...FRONTEND[name]].sort(), name).toEqual([...values].sort());
    }
  });

  it("has a display label for every value", () => {
    for (const [name, labels] of Object.entries(LABELS)) {
      for (const value of enums[name] ?? []) expect(labels[value], `${name}.${value}`).toBeTruthy();
    }
  });

  it("mirrors the outbound tool categories and API key scopes", () => {
    const source = readFileSync(ENUMS, "utf8");
    const outbound = /OUTBOUND_CATEGORIES = \{([^}]*)\}/.exec(source)?.[1] ?? "";
    const backendOutbound = [...outbound.matchAll(/ToolCategory\.([A-Z_]+)/g)].map((m) => m[1].toLowerCase()).sort();
    expect([...domain.OUTBOUND_TOOL_CATEGORIES].sort()).toEqual(backendOutbound);
    const scopes = /API_KEY_SCOPES = \{([^}]*)\}/.exec(source)?.[1] ?? "";
    const backendScopes = [...scopes.matchAll(/Permission\.([A-Z_]+)/g)].map((m) => m[1].toLowerCase()).sort();
    expect([...domain.API_KEY_SCOPES].sort()).toEqual(backendScopes);
  });

  it("labels every secret type the redaction engine emits", () => {
    const types = parseSecretTypes(REDACTION.map((file) => readFileSync(file, "utf8")));
    // Sanity: the parser found the provider table, structured credentials and sensitive_field.
    for (const known of ["github_token", "private_key", "database_credentials", "generic_password", "sensitive_field", "azure_storage_key"]) {
      expect(types.has(known), known).toBe(true);
    }
    const missing = [...types].filter((t) => !domain.SECRET_TYPE_LABELS[t]);
    expect(missing).toEqual([]);
  });
});

describe("secretTypeLabel", () => {
  it("labels known types and keeps unknown ones readable", () => {
    expect(domain.secretTypeLabel("github_token")).toBe("GitHub token");
    expect(domain.secretTypeLabel("sensitive_field")).toBe("Sensitive field value");
    expect(domain.secretTypeLabel("acme_widget_key")).toBe("Acme widget key");
    expect(domain.secretTypeLabel(null)).toBe("Secret");
  });
});
