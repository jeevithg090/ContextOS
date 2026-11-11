/** Types for the integration registry. Mirrors backend/app/schemas/integrations.py. */
import type { EnforcementMode } from "@/lib/domain";

export type IntegrationHealth = "connected" | "stale" | "never_seen";
export type CatalogStatus = "supported" | "planned";

export interface Capability {
  name: string;
  mode: EnforcementMode;
  description: string;
}

export interface CatalogEntry {
  kind: string;
  name: string;
  status: CatalogStatus;
  summary: string;
  /** Strongest enforcement the integration can provide; null for planned integrations. */
  best_enforcement: EnforcementMode | null;
  monitoring: Capability[];
  enforcement: Capability[];
  limitations: string[];
  integration_surface: string | null;
  available_today: string | null;
  interim_kind: string | null;
  docs_path: string | null;
  api_key_scopes: string[];
  /** Best health of this kind in the organisation. */
  health: IntegrationHealth;
  last_event_at: string | null;
}

export interface EnforcementCounts {
  enforced: number;
  advisory: number;
  observed: number;
}

export interface ConnectedIntegration {
  id: string;
  kind: string;
  name: string;
  display_name: string;
  supported: boolean;
  best_enforcement: EnforcementMode;
  health: IntegrationHealth;
  health_detail: string;
  first_seen_at: string;
  last_event_at: string | null;
  event_count: number;
  decision_count: number;
  events_24h: number;
  decisions: EnforcementCounts;
  agent_count: number;
  last_error: string | null;
}

export interface IntegrationsOverview {
  connected: ConnectedIntegration[];
  catalog: CatalogEntry[];
  stale_after_minutes: number;
  /** The same window in hours (24 by default); prefer it for display. */
  stale_after_hours?: number;
  generated_at: string;
}

export interface SetupCommand {
  language: string;
  code: string;
  title: string | null;
}

export interface SetupStep {
  title: string;
  description: string;
  commands: SetupCommand[];
  link: { label: string; href: string } | null;
}

export interface SetupScope {
  scope: string;
  required: boolean;
  purpose: string;
}

export interface SetupGuide {
  kind: string;
  name: string;
  status: CatalogStatus;
  interim_kind: string | null;
  server_url: string;
  server_url_note: string;
  api_key_scopes: SetupScope[];
  steps: SetupStep[];
  verification: string;
  notes: string[];
  docs_path: string | null;
}
