# Data model

The schema is defined by the SQLAlchemy models in `backend/app/models/` and owned by the Alembic
revisions in `backend/alembic/versions/` (`0001_initial_schema.py`, then `0002_incident_seq.py`, which adds
`organizations.incident_seq`). The table list
below was generated from `Base.metadata` (41 tables) and checked against the model files.

Regenerate the raw list (from `backend/`):

```bash
.venv/bin/python -c "import app.models; from app.database.base import Base; print('\n'.join(sorted(Base.metadata.tables)))"
```

Related: [ARCHITECTURE.md](ARCHITECTURE.md) (pipeline that writes these rows),
[API_SPECIFICATION.md](API_SPECIFICATION.md), [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Conventions

- **Ids** are prefixed ULIDs from `app.core.ids.new_id("<kind>")` (`org_…`, `agt_…`, `asn_…`,
  `fnd_…`, `dec_…`, `apr_…`, `evt_…`, …), stored as `String(40)` primary keys.
- **Tenancy**: every table except `organizations`, `users` and `auth_sessions` mixes in
  `OrgScopedMixin` — an indexed `organization_id` foreign key with `ON DELETE CASCADE`. All queries
  filter on it (`app.services.scoping`). Per-tenant uniqueness always includes `organization_id`.
- **Time**: `UTCDateTime` (timezone-aware, always UTC, also on SQLite). Server timestamps
  (`received_at`, `evaluated_at`, `observed_at`) are authoritative; client-reported times
  (`occurred_at`, `collected_at`) are kept for display only.
- **JSON**: `JSONType` = `JSON`, `JSONB` on PostgreSQL. In-place mutation is not tracked; services
  assign new values.
- **No raw content or secrets**: content is stored as a redacted, truncated preview plus a SHA-256
  hash; secrets as keyed HMAC fingerprints (`[{"type", "fingerprint"}]`); tool arguments as
  `arguments_redacted` plus `argument_hash`. Previews can be turned off per organisation
  (`store_previews`).
- **Simulation flag**: rows produced by the Simulation Lab carry `is_simulation=true` in the 10
  tables that have the flag (marked **sim** below). Lists, metrics and counters exclude them unless
  a caller passes `include_simulated=true`. `context_sources.is_simulation` stays true only while
  every observation of the source was simulated; real traffic clears it.
- **Naming**: constraints and indexes follow `Base.metadata` naming conventions
  (`app/database/base.py`).

## Tenancy and identity (`models/org.py`)

| Table | Key columns | Notes |
|---|---|---|
| `organizations` | `name`, `slug` (unique), `settings` (JSON), `audit_seq`, `event_seq`, `task_seq`, `incident_seq`, `audit_head_hash` | Not org-scoped (it is the tenant). `settings` holds `retention_days`, `fail_mode`, `default_decision`, `approval_timeout_s`, `store_previews` (`services/bootstrap.default_org_settings`). Counters are incremented atomically inside the owning transaction (`services/org_counters.reserve`); `incident_seq` numbers incidents (`INC-<n>`). |
| `users` | `email` (unique), `name`, `password_hash`, `is_active`, `last_login_at` | Global identity; membership gives org access. |
| `memberships` | `user_id` → users, `role` | Unique `(organization_id, user_id)`. Roles: `owner`, `admin`, `security_analyst`, `developer`, `viewer`. |
| `api_keys` | `name`, `prefix` (display), `key_hash` (unique), `scopes` (`ingest`/`decide`/`read`), `agent_id` → agents (bind), `expires_at`, `revoked_at`, `last_used_at` | Raw key shown once, never stored. |
| `auth_sessions` | `user_id` → users, `token_hash` (unique), `expires_at`, `revoked_at`, `user_agent` | Browser sessions; only the hash is stored. Not org-scoped (the org comes from membership). |

## Agents and sessions (`models/agent.py`)

| Table | Key columns | Notes |
|---|---|---|
| `agents` **sim** | `name`, `framework`, `owner`, `environment`, `labels`, `status` (`active`/`inactive`/`quarantined`), `version`, `declared_capabilities`, `integration_id` → integrations, `risk_score`, `last_seen_at` | Unique `(organization_id, name)`; auto-registered on first event. |
| `agent_sessions` **sim** | `agent_id` → agents, `external_session_id`, `parent_session_id` → agent_sessions, `status`, `started_at`, `ended_at`, `event_count`, `session_metadata`, `risk_state`, `risk_score`, `simulation_run_id` | Unique `(organization_id, agent_id, external_session_id)`. `risk_state` holds the lethal-trifecta conditions and their evidence. |
| `agent_relationships` | `parent_agent_id`, `child_agent_id` → agents, `relationship_type` (`delegates_to`/`messages`), `event_count`, `crosses_trust_boundary` | Observed delegation/messaging between agents. |

## Context and provenance (`models/context.py`)

| Table | Key columns | Notes |
|---|---|---|
| `context_sources` **sim** | `source_type`, `identifier` (canonical), `domain`, `trust_level`, `trust_capabilities`, `trust_reasons`, `trust_rule_id`, `manually_classified`, `observation_count`, `finding_count`, `max_finding_severity` | Unique `(organization_id, source_type, identifier)`. |
| `context_items` **sim** | `source_id` → context_sources, `agent_id`, `session_id` → agent_sessions, `event_id`, `collected_via`, `received_at`, `content_hash`, `content_length`, `redacted_preview`, `sensitivity`, `contains_secrets`, `secret_fingerprints`, `trust_level` (at ingest), `detection_summary`, `tool_invocation_id`, `origin_agent_id`, `receipt_signature` | One observed piece of context; doubles as the signed Context Receipt (keyed HMAC over `receipt_fields`). |
| `provenance_edges` | `src_type`, `src_id`, `dst_type`, `dst_id`, `relation`, `session_id`, `event_id`, `observed_at`, `confidence` (`observed`/`inferred`), `edge_metadata` | Observed relationships, not causation. Node/relation types: `domain.enums.ProvenanceNodeType` / `ProvenanceRelation`. |

## Tools and destinations (`models/tool.py`)

| Table | Key columns | Notes |
|---|---|---|
| `tools` | `name`, `provider` (`claude_code`, `mcp:<server>`, …), `server`, `category` (server-classified), `risk_level`, `tool_metadata` (classification reason, category hint, MCP schema, poisoning flags), `invocation_count` | Unique `(organization_id, provider, name)`. Simulated calls do not increment `invocation_count`. |
| `destinations` | `kind` (`domain`/`ip`/`email`/`service`/`agent`/`unknown`), `identifier`, `classification` (trust level), `trust_rule_id`, `verification` (checks performed), `transfer_count`, `blocked_count`, `sensitive_transfer_count` | Unique `(organization_id, kind, identifier)`. Simulated calls do not change the counters. |
| `tool_invocations` **sim** | `agent_id`, `session_id`, `tool_id`, `request_event_id`, `result_event_id`, `correlation_id`, `status`, `decision`, `enforcement`, `policy_decision_id`, `approval_id`, `arguments_redacted`, `argument_hash`, `resources`, `destination_id`, `sensitive_data_detected`, `secret_fingerprints`, `matched_session_fingerprints`, `result_summary`, `result_context_item_id`, `error` | Status flow: `requested` → `allowed`/`denied`/`pending_approval`/`approved`/`rejected`/`restricted` → `completed`/`failed`. |

## Security records (`models/security.py`)

| Table | Key columns | Notes |
|---|---|---|
| `trust_rules` | `applies_to` (`source`/`destination`/`both`), `source_type`, `match_field` (`identifier`/`domain`), `pattern` (glob), `trust_level`, `capabilities`, `priority`, `enabled` | 21 default rules seeded per organisation (`engines/trust/defaults.py`). |
| `security_policies` | `name`, `enabled`, `mode` (`enforce`/`monitor`), `priority`, `outcome`, `conditions` (DSL), `restrictions`, `severity`, `version`, `is_builtin`, `builtin_key` | 13 built-in policies seeded per organisation (`engines/policy/builtin.py`); built-ins can be disabled, not deleted. |
| `policy_decisions` **sim** | `agent_id`, `session_id`, `tool_invocation_id`, `event_id`, `decision`, `enforcement`, `matched_policies`, `monitor_matches`, `explanation`, `input_snapshot`, `evaluated_at`, `latency_ms` | Immutable. `input_snapshot` (redacted) is what counterfactual replay evaluates. |
| `approvals` **sim** | `policy_decision_id`, `tool_invocation_id`, `agent_id`, `session_id`, `status` (`pending`/`approved`/`rejected`/`expired`/`cancelled`), `summary`, `risk_summary`, `requested_at`, `expires_at`, `decided_at`, `decided_by_user_id`, `decision_note` | Expires lazily when polled or listed. `cancelled` = withdrawn by the integration. |
| `security_findings` **sim** | `agent_id`, `session_id`, `category`, `rule_id`, `title`, `explanation`, `severity`, `confidence`, `status` (`open`/`acknowledged`/`resolved`/`false_positive`), `evidence` (typed refs with redacted excerpts), `source_id`, `context_item_id`, `tool_invocation_id`, `policy_decision_id`, `destination_id`, `incident_id`, `fingerprint`, `occurrence_count`, `first_seen_at`, `last_seen_at`, `remediation`, `resolution_note` | Deduplicated by `(organization_id, fingerprint)`. |
| `incidents` **sim** | `number`, `title`, `summary`, `severity`, `status` (`open`/`investigating`/`contained`/`resolved`/`false_positive`), `assignee_user_id`, `primary_agent_id`, `primary_session_id`, `opened_at`, `resolved_at`, `created_by`, `resolution`, `tags` | Findings link to incidents via `security_findings.incident_id`. |
| `incident_activities` | `incident_id` → incidents, `actor`, `kind` (`note`/`status_change`/`finding_linked`/`assigned`/`exported`/`created`), `body` (redacted), `details` | |

## Platform (`models/platform.py`)

| Table | Key columns | Notes |
|---|---|---|
| `ingested_events` **sim** | `client_event_id`, `event_type`, `schema_version`, `sequence` (per-org, server-assigned), `agent_id`, `session_id`, `correlation_id`, `integration`, `occurred_at`, `received_at`, `payload_redacted`, `payload_hash`, `refs`, `processing_status` (`processed`/`error`), `processing_error`, `api_key_id` | Append-only event log; unique `(organization_id, client_event_id)` (idempotency). The basis for replay and timelines. |
| `audit_events` | `seq`, `occurred_at`, `actor_type` (`user`/`api_key`/`system`), `actor_id`, `action`, `target_type`, `target_id`, `details` (redacted), `prev_hash`, `hash` | Per-org keyed HMAC chain; unique `(organization_id, seq)`; head in `organizations.audit_head_hash`. Never purged. |
| `integrations` | `kind`, `name`, `status`, `config`, `last_event_at`, `event_count`, `decision_count`, `last_error` | Unique `(organization_id, kind, name)`. Connected = an event in the last 24 hours (`services/integrations_health.STALE_AFTER`). |
| `simulation_runs` | `scenario_id`, `scenario_name`, `suite_run_id`, `agent_id`, `session_id`, `status` (`running`/`completed`/`failed`), `passed`, `policy_snapshot`, `results`, `summary`, `triggered_by_user_id`, `error` | One row per scenario run; suites share `suite_run_id`. |

## Engineering Workspace (`models/workspace.py`)

| Table | Key columns | Notes |
|---|---|---|
| `boards` | `name`, `template`, `is_default`, `config`, `archived_at` | Templates: `software_development`, `security_remediation`, `incident_response`, `bug_tracking`, `feature_development`, `technical_debt`, `research_experiments`. |
| `board_columns` | `board_id` → boards, `name`, `position`, `wip_limit`, `status_key`, `is_done_column`, `requires_verification`, `automation` | `automation` triggers: `pr_linked`, `verification_passed`, `verification_failed`, `fix_attempt_started`. |
| `tasks` | `number` (unique per org), `board_id`, `column_id`, `position`, `title`, `description`, `task_type`, `priority`, `severity`, `reporter_user_id`, `due_date`, `parent_task_id` → tasks, `related_agent_id`, `related_incident_id`, `related_finding_id`, `related_files`, `links`, reproduction/expected/actual/acceptance fields, `verification_status`, `archived_at` | Soft-deleted via `archived_at`. |
| `task_labels`, `task_label_links` | label `name` (unique per org), `color`; link `(task_id, label_id)` unique | |
| `task_assignments` | `task_id`, `user_id` → users, `role` | Unique `(task_id, user_id)`. |
| `task_comments` | `task_id`, `author_user_id`, `body` (redacted), `edited_at` | |
| `task_dependencies` | `task_id`, `depends_on_task_id` → tasks, `kind` | Unique pair; `blocks` cycles refused. |
| `task_attachments` | `task_id`, `name`, `kind` (`link`/`log`/`stack_trace`/`note`), `url`, `content` (redacted, ≤ 100 KB), `size` | |
| `task_activities` | `task_id`, `actor_user_id`, `kind`, `from_value`, `to_value`, `details` | |
| `task_context_refs` | `task_id`, `ref_type`, `ref_id`, `note` | References security records by id instead of copying them; unique `(task_id, ref_type, ref_id)`. |
| `prompt_templates` | `name`, `mode`, `preset`, `options`, `section_overrides`, `is_builtin` | Custom templates; built-ins (`builtin:<mode>`) are defined in code. |
| `context_packs` | `task_id`, `profile` (`minimal`/`standard`/`deep`/`security_critical`/`full`), `items`, `token_estimate` | |
| `generated_prompts` | `task_id`, `mode`, `preset`, `options`, `sections`, `content`, `context_pack_id`, `template_id`, `version` | Deterministic fix-context output; editing bumps `version`. |
| `fix_attempts` | `task_id` → tasks, `generated_prompt_id`, `agent_tool`, `status`, `branch`, `commit_sha`, `pr_url` | |
| `verification_runs` | `task_id` → tasks, `fix_attempt_id`, `kind` (`test_run`/`code_review`/`manual`/`deployment`/`simulation`/`replay`), `status`, `evidence`, `simulation_run_id` | |

## Relationships at a glance

```
organizations ─┬─ memberships ── users ── auth_sessions
               ├─ api_keys (optional agent bind)
               ├─ agents ─┬─ agent_sessions (parent_session_id → agent_sessions)
               │          └─ agent_relationships (parent/child agents)
               ├─ context_sources ── context_items ── (session, tool_invocation, receipt)
               ├─ tools ── tool_invocations ── policy_decisions ── approvals
               │                └─ destinations
               ├─ security_findings ── incidents ── incident_activities
               ├─ provenance_edges (typed src/dst ids; observed relationships)
               ├─ ingested_events · audit_events · integrations · simulation_runs
               └─ boards ── board_columns ── tasks ── comments · refs · attachments · dependencies ·
                                                      assignments · activities · fix_attempts ·
                                                      verification_runs · context_packs · generated_prompts
```

Many cross-references are plain id columns without a database foreign key (for example
`policy_decisions.session_id`, `security_findings.incident_id`, `approvals.policy_decision_id`);
services resolve them with org-scoped lookups, and the retention purge deletes in dependency order.

## Retention

`contextos-server purge` (`services/retention.py`) deletes, per organisation, rows older than its
`retention_days` (1–3650, default `CONTEXTOS_RETENTION_DAYS`=90) by server timestamp, in this order:
`provenance_edges`, `approvals` (not pending), `policy_decisions`, `security_findings` (only
`resolved`/`false_positive`), `context_items`, `tool_invocations`, `ingested_events`,
`agent_sessions` (ended, nothing newer, no kept child). Never deleted: `audit_events`, evidence of
open incidents (`open`/`investigating`/`contained`), entities and configuration (agents, tools,
sources, destinations, policies, trust rules, incidents, integrations, simulation runs, workspace).
Each purge writes one `retention.purged` audit entry and live notification.

## Migrations

- `contextos-server init-db` applies the revisions; a database created by `create_all` (no
  revision recorded) is adopted (stamped) only when it matches the models exactly. The API refuses
  to start on an outdated, incomplete or uninitialised schema
  (`app.database.migrations.ensure_schema_ready`; outside production it also accepts an unversioned
  but complete schema, which is what test fixtures create).
- `backend/tests/integration/test_migrations.py` checks that a fresh upgrade matches the models and
  that downgrade/upgrade round-trips.
- How to add a migration: [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md#add-a-migration).
