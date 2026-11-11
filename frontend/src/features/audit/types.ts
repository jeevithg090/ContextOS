/** Types for the audit log. Mirrors backend/app/schemas/audit.py. */

export type AuditActorType = "user" | "api_key" | "system";

export interface AuditEntry {
  id: string;
  seq: number;
  occurred_at: string;
  actor_type: AuditActorType | string;
  actor_id: string | null;
  /** Display name when the actor still exists (members of the org, its API keys). */
  actor_label: string | null;
  /** User email (signed-in viewers only) or API key prefix. */
  actor_detail: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: Record<string, unknown>;
  prev_hash: string | null;
  hash: string;
}

export interface AuditFilters {
  action?: string;
  actor_type?: AuditActorType;
  actor_id?: string;
  target_type?: string;
  target_id?: string;
  since?: string;
  until?: string;
}

export interface AuditThreatModel {
  detects: string[];
  does_not_protect_against: string[];
  anchoring: string;
}

export interface AuditVerifyResult {
  valid: boolean;
  checked: number;
  head_seq: number;
  head_hash: string | null;
  first_invalid_seq: number | null;
  first_invalid_entry_id: string | null;
  reason: string | null;
  reason_explained: string | null;
  summary: string;
  verified_at: string;
  threat_model: AuditThreatModel;
}

export interface AuditExportResult {
  filename: string;
  throughSeq: string | null;
  headHash: string | null;
}
