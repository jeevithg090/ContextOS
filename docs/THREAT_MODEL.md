# ContextOS threat model (system)

Scope: the ContextOS server (`backend/app`), its HTTP API and dashboard, and the integrations in
`sdk/` (Claude Code hooks, MCP gateway, Python SDK `guard()`, CLI). Controls are described in
`docs/SECURITY_MODEL.md`; this document maps each threat to the control and the test that proves it.
A row is **mitigated** only when both exist; **partial** names what is missing; **accepted** is a
known residual risk with its reason. Reviewed 2026-11-11 (security hardening, wave 2).

## Assets
| Asset | Why it matters |
|---|---|
| Raw secrets and raw context content agents see | Must never be stored, logged, streamed or exported |
| Secret fingerprints, content hashes | Keyed (`CONTEXTOS_SECRET_KEY`); let ContextOS recognise a credential without storing it |
| API keys (`ctxk_…`), session tokens (`ctxs_…`) | Stored hashed; a raw key is shown once |
| Tenant data: agents, sessions, context items, findings, incidents, tasks, prompts | Confidential per organisation |
| Policies, trust rules, approvals | Decide what agents may do; an approval is a person's authorisation |
| Audit hash chain, `Organization.audit_head_hash` | Evidence that the record was not altered |
| `CONTEXTOS_SECRET_KEY` | Keys fingerprints, receipts and the audit chain |
| Exports (incident bundle, audit JSONL, context packs, AI fix-context prompts) | Leave the system boundary |

## Actors
1. **Content author** — writes a README, web page, issue, MCP tool description or tool result that an
   agent reads (prompt injection, credential exfiltration attempts).
2. **Manipulated or compromised agent** — produces tool calls (arguments) shaped by that content.
3. **Integration key holder** — a host running a hook/gateway/SDK with an API key, possibly bound to
   one agent, possibly leaked.
4. **Other tenant** — a signed-in user or key of another organisation on the same server.
5. **Lower-privileged member** — viewer/developer trying to administer, approve or escalate.
6. **Anonymous network client** — can reach the API but has no credential.
7. **Cross-site web page** — runs in a member's browser while they are signed in.
8. **Malicious MCP server** — behind the gateway; controls tool listings and results.
9. **Insider with database access** — can read or edit rows but does not hold the server secret.

## Entry points and trust boundaries
Agent ↔ host framework ↔ integration (`sdk/`) ↔ HTTP API ↔ services/engines ↔ database ↔ browser.
- Integration API (API keys): `POST /api/v1/events`, `POST /api/v1/decide`,
  `GET|POST /api/v1/decide/approvals/{id}[/cancel]`, `POST /api/v1/scan`, read routes for the CLI.
- Dashboard API (session cookie + `X-Requested-With`): every other `/api/v1/*` route, `GET /api/v1/stream` (SSE).
- Anonymous: `GET /api/v1/health`, `GET /api/v1/auth/setup-status`, `POST /api/v1/auth/setup`,
  `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, the SPA and `/api/docs`.
- Server CLI `contextos-server` (operator on the host) and `CONTEXTOS_*` configuration.
- Server-side file access: `CONTEXTOS_WORKSPACE_REPO_ROOT` (context packs; never taken from a request).

## Threats
L = likelihood, I = impact (L/M/H).

| ID | Threat (STRIDE / agent) | Entry | Control | Test | L | I | Status |
|---|---|---|---|---|---|---|---|
| T1 | Client supplies trust, risk, severity or decision (Tampering) | `/events`, `/decide` | `EventEnvelope` `extra="forbid"` (`app/events/envelope.py`); server classifies | `test_events_api.py::test_client_supplied_trust_and_decision_fields_are_rejected`, `test_agents_api.py::test_register_rejects_duplicates_reserved_labels_and_client_risk` | H | H | mitigated |
| T2 | Key reports events for another agent (Spoofing) | `/events`, `/decide` | `ingestion._attribution_error`; org from key | `test_events_api.py::test_bound_api_key_may_only_report_its_agent` | M | M | mitigated |
| T3 | Bound key reads other agents' data (Information disclosure) | read routes, `/stream` | `deps.require_org_wide` (403), `deps.check_bound_agent` (404), per-agent filters | `test_bound_api_keys.py` | M | M | mitigated |
| T4 | Bound key re-uses another agent's `event_id` to read its refs or decision | `/events`, `/decide` | `ingestion._visible_to` → rejected + audited | `test_bound_api_keys.py::test_reusing_another_agents_event_id_reveals_nothing` | L | M | mitigated |
| T5 | Duplicate / replayed events | `/events`, `/decide` | unique `(organization_id, client_event_id)`; duplicates return the original result | `test_events_api.py::test_duplicate_event_ids_are_idempotent` | M | L | mitigated |
| T6 | Raw secret persisted from content, arguments, results, metadata | ingestion | `app.engines.redaction` at every write; digests instead of content | `test_ingestion_redaction.py::test_no_raw_secret_is_persisted_anywhere` | H | H | mitigated |
| T7 | Raw secret persisted through identifiers or typed names | ingestion, admin, agents | `ingestion_identity.sanitize_identifiers`; `bootstrap.redact_name`; agent/declared-tool names | `test_identifier_redaction.py` | L | H | mitigated |
| T8 | Secret leaks via logs, error messages, validation errors | all | redacting log formatters; `safe_error_text`/`scrub_echoes`; `errors._echo` | `tests/unit/test_log_redaction.py`, `test_ingestion_redaction.py::test_processing_error_does_not_echo_raw_content`, `test_http_hardening.py::test_validation_errors_do_not_echo_secrets` | M | H | mitigated |
| T9 | Secret or content in SSE, notifications or exports | `/stream`, exports | `notify` ids only; exports from redacted data, redacted again | `test_ingestion_redaction.py::test_notifications_carry_ids_not_content`, `test_audit_api.py::test_export_redacts_details` | M | H | mitigated |
| T10 | Redaction bypass by encoding/obfuscation | ingestion | `app/engines/redaction/`, `app/engines/detection/normalize.py` | `tests/unit/test_redaction*.py`, `tests/corpus/` | M | H | partial — detectors cover known formats and encodings; an unrecognised secret format is stored redacted only if a later context match identifies it (`ingestion_known_secrets`) |
| T11 | Prompt injection in context steers tool use | content → `/decide` | detection + trust + session risk + policy (built-in pack) | `test_ingestion_usecases.py`, `tests/unit/test_detection*.py`, `docs/DETECTION_EVALUATION.md` | H | H | partial — deterministic detection (measured precision/recall in `DETECTION_EVALUATION.md`); novel phrasings can be missed |
| T12 | Credential exfiltration via tool arguments | `/decide` | fingerprints seen in context matched in arguments; built-in DENY/REQUIRE_APPROVAL policies | `test_ingestion_pipeline.py`, `test_decide_api.py` | H | H | mitigated for recognised secrets |
| T13 | Cross-tenant read/write by id, body reference, list filter or stream | all org routes | `scoping.scoped/get_scoped` → 404; bus per org | `test_org_isolation_sweep.py`, `test_stream.py::test_committed_notifications_reach_only_the_same_org` | M | H | mitigated |
| T14 | Privilege escalation in an org (Elevation) | admin, approvals, policies | `require(Permission…)`, owner rules in `auth_service` | `test_admin.py::test_non_admin_roles_cannot_administer`, `::test_owner_role_changes_require_an_owner`, `::test_last_owner_is_protected`, `route_audit.py` | M | H | mitigated |
| T15 | CSRF on cookie sessions | dashboard API | `X-Requested-With: contextos` on unsafe cookie requests; `SameSite=Lax`; JSON bodies need CORS preflight | `test_auth.py::test_cookie_session_requires_csrf_header_on_unsafe_requests` | M | H | mitigated (exports via `GET` accepted, see R5) |
| T16 | CORS misconfiguration exposes the API to any site | config | production refuses `*`; `*` never allows credentials | `test_http_hardening.py::test_production_refuses_insecure_settings`, `::test_wildcard_cors_never_allows_credentials` | L | H | mitigated |
| T17 | Password brute force / spraying | `/auth/login` | per (email, IP) and per-IP limits, uniform errors, dummy hash | `test_auth.py::test_login_rate_limited_after_five_failures`, `test_http_hardening.py::test_password_spraying_from_one_address_is_limited` | M | H | partial — per process; distributed attackers (R1) |
| T18 | Session theft or lingering access after logout/revocation | cookie, `/stream` | `HttpOnly`, `Secure` in production, server-side revocation, stream re-check | `test_auth.py::test_logout_revokes_session_and_clears_cookie`, `test_stream.py::test_stream_ends_when_its_credential_stops_being_valid` | M | H | mitigated |
| T19 | Setup hijack on a fresh server | `/auth/setup` | setup only while no user exists | `test_auth.py::test_setup_only_once` | L | H | accepted (R2) |
| T20 | Oversized or deeply nested body exhausts memory or fails late (DoS) | all | `RequestLimitsMiddleware` (413 before auth incl. chunked; depth > 64 → 422); per-event limit | `test_http_hardening.py`, `test_payload_limits.py`, `tests/unit/test_request_limits.py` | M | M | mitigated |
| T21 | ReDoS in user-supplied patterns | trust rules, policies | NFA glob matcher; `fnmatch` with node/depth limits; no user regex | `tests/unit/test_trust_matching.py::test_pathological_patterns_match_in_linear_time`, `tests/unit/test_policy_validation.py` | L | M | mitigated |
| T22 | Path traversal / symlink escape when reading repository files | context packs | `repo_files.resolve_repo_path` + `O_NOFOLLOW`, sensitive files never opened | `tests/unit/test_workspace_context_pack.py::test_traversal_outside_root_is_rejected_and_never_read`, `::test_symlink_escaping_root_is_rejected` | L | H | mitigated (R6) |
| T23 | SSRF via client-supplied URLs | trust verify, events | the server never fetches; verification looks at names only | `test_http_hardening.py::test_destination_verification_never_opens_a_connection` | L | H | mitigated |
| T24 | Prompt injection carried into generated fix-context prompts | workspace AI | evidence redacted, fenced and labelled untrusted | `test_workspace_ai_prompts.py`, `tests/unit/test_workspace_*` | M | M | partial — labelling reduces but cannot prevent a downstream model from following embedded text |
| T25 | Audit tampering, deletion, truncation (Repudiation) | database | keyed hash chain, head hash, `GET /audit/verify` | `test_audit_api.py::test_verify_detects_modified_entry`, `::test_verify_detects_deleted_and_truncated_entries` | L | H | mitigated against DB-only attackers (R3) |
| T26 | Concurrent writers break the chain or share sequence numbers | all writes | `org_counters.reserve` (`UPDATE … RETURNING`, row/DB write lock) | `test_audit_api.py::test_concurrent_appends_form_one_unbroken_chain`, `::test_concurrent_ingestion_assigns_distinct_event_sequences` | M | M | mitigated |
| T27 | Hook loosens permissions (`allow`) | Claude Code hook | `Verdict.to_output` refuses `allow` | `sdk/tests/test_claude_code_enforce.py::test_to_output_refuses_to_emit_allow` | L | H | mitigated |
| T28 | Server down/slow → call silently runs | integrations | fail mode `closed` default (`ask` org default in generated setup); hook time budget; spool | `test_claude_code_enforce.py::test_unreachable_server_follows_the_fail_mode`, `::test_server_errors_follow_the_fail_mode`, `sdk/tests/test_mcp_gateway_enforcement.py`, `sdk/tests/test_guard.py` | M | H | mitigated (R4 for `open`) |
| T29 | RESTRICT not applicable → call runs unrestricted | integrations | deny when a restriction cannot be applied | `sdk/tests/test_guard_restrictions.py`, `test_claude_code_enforce.py::test_path_restrictions_on_a_shell_command_fail_closed` | L | H | mitigated |
| T30 | Gateway bypass through other MCP methods | MCP gateway | only implemented handlers are served; tools only via `call_tool`, decided first | `sdk/tests/test_mcp_gateway_proxy.py`, `test_mcp_gateway_enforcement.py` | L | H | mitigated for the gateway; tools the host reaches without the gateway are out of scope |
| T31 | Approval spoofed, replayed or decided by a key | approvals | users with `approve` only; org + invocation scoped; 409 once decided/expired | `test_approvals_api.py::test_reject_blocks_the_call_and_a_second_decision_conflicts`, `::test_agent_bound_api_key_sees_only_its_agent` | L | H | mitigated |
| T32 | Misleading claims ("blocked" when observed; prospective trifecta read as session state) | decisions, UI | server-derived `enforcement`; `PROSPECTIVE_TRIFECTA_NOTE` | `test_decide_api.py::test_enforcement_claim_depends_on_integration`, `::test_prospective_trifecta_is_explained_and_not_reported_as_session_state` | M | M | mitigated |
| T33 | Counterfactual or simulated data read as real history | replay, Simulation Lab | snapshot-only replay, `is_simulation` flags and filters | `test_replay_api.py`, `test_trust_simulation_filter.py` | M | M | mitigated |
| T34 | API key sent in clear over the network | integrations | `doctor` and client warning for plain HTTP to another host; TLS is a deployment requirement | `sdk/tests/test_client.py::test_plain_http_to_another_host_is_detected`, `sdk/tests/test_cli.py::test_doctor_warns_when_the_api_key_travels_unencrypted` | M | H | partial — warned, not refused (R7) |
| T35 | Clickjacking, script injection, cache leaks in the browser | SPA, API | CSP (`script-src 'self'`, `frame-ancestors 'none'`), `X-Frame-Options`, `no-store` on API | `test_http_hardening.py::test_api_responses_carry_security_headers`, `::test_spa_gets_a_same_origin_csp_and_hsts_when_cookies_are_secure` | L | M | mitigated |

## Residual risks (accepted, with reason)
- **R1** Login limits are per process and per address; a distributed attacker gets 5 attempts per
  account per address per 5 minutes (50 failures per address across accounts). No breached-password check. Behind a proxy on another host, set `FORWARDED_ALLOW_IPS` or all users share the proxy's limit. Mitigation outside ContextOS: put
  the dashboard behind SSO/VPN or a rate-limiting proxy.
- **R2** `POST /auth/setup` is open until the first user exists. Run `contextos-server create-org`
  (or complete setup) before exposing a new server.
- **R3** An attacker with database write access AND `CONTEXTOS_SECRET_KEY` can rewrite the audit
  chain. Export `audit_head_hash` periodically to write-once storage.
- **R4** Fail mode `open` runs the call whenever ContextOS cannot decide — including an input too
  large to evaluate, which a manipulated agent can produce. It is opt-in and documented; `closed`
  is the integration default and `ask` the organisation default.
- **R5** Export endpoints are `GET` requests that write an audit entry; a cross-site navigation can
  trigger an export (the attacker cannot read it). Impact: a spurious audit entry.
- **R6** `repo_files` resolves a path and then opens it; a concurrent symlink swap of an intermediate
  directory by someone who can write to the repository could race the check (the final component is
  opened `O_NOFOLLOW`).
- **R7** The SDK warns but does not refuse plain HTTP; TLS termination in front of the server is a
  deployment requirement (`docs/DEPLOYMENT_GUIDE.md`).
- **R8** Detection is deterministic pattern- and heuristic-based (T10, T11); measured numbers and
  known gaps are in `docs/DETECTION_EVALUATION.md`.

## Assumptions
- TLS terminates in front of the server; `CONTEXTOS_COOKIE_SECURE=true` in production.
- `CONTEXTOS_SECRET_KEY` is random, ≥ 32 characters and managed outside the database.
- One API process (the live bus and login limits are in-process); several replicas need a shared
  bus and limiter.
- Hosts enforce what the integration answers (Claude Code honours `deny`/`ask`; tools behind the MCP
  gateway are reachable only through it).

## Test scenarios (how to re-verify)
```bash
cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests/integration/test_bound_api_keys.py \
  tests/integration/test_identifier_redaction.py tests/integration/test_http_hardening.py \
  tests/integration/test_stream.py tests/integration/test_audit_api.py tests/integration/test_org_isolation_sweep.py \
  tests/integration/test_ingestion_redaction.py tests/unit/test_request_limits.py tests/unit/test_log_redaction.py
cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_claude_code_enforce.py \
  tests/test_mcp_gateway_enforcement.py tests/test_guard.py tests/test_guard_restrictions.py tests/test_client.py
backend/.venv/bin/python scripts/audit/route_audit.py   # from the repository root
```
