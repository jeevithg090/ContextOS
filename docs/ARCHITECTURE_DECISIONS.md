# Architecture decisions

ADR-style records of the decisions the implementation embodies. Each lists where the decision
lives in code, so it can be checked. Status is **Accepted** unless noted. To change one, add a new
record that supersedes it.

## ADR-001 Modular monolith
- **Context**: one product with many tightly related areas (pipeline, investigation, workspace),
  a small team and a need for transactional consistency between an event, its finding, decision
  and audit entry.
- **Decision**: a single FastAPI process with modules separated by layer (`engines`, `services`,
  `api/routes`, `schemas`, `models`) and one relational database. The API process also serves the
  built SPA when `CONTEXTOS_SERVE_FRONTEND=true`.
- **Consequences**: one deployable and one transaction per event; scaling out needs a shared bus and
  shared rate limiting (ADR-004, PRODUCT_IMPROVEMENTS). Boundaries are enforced by convention and
  review (`docs/engineering/backend-architecture.md`), not by packages.

## ADR-002 Pure engines
- **Decision**: redaction, detection, trust, policy, risk and provenance live in
  `backend/app/engines/<name>/` with no database, FastAPI or service imports; each `__init__.py`
  docstring is the contract. Engineering Workspace logic follows the same rule (`app/workspace/`).
- **Why**: exhaustive unit tests (`backend/tests/unit/`), reuse by replay, Simulation Lab and the
  detection corpus evaluator, and independent review of security logic.
- **Consequences**: services assemble inputs (specs, history) and persist outputs; engines take
  dataclasses and return dataclasses.

## ADR-003 SQLite for development, PostgreSQL for production; Alembic owns the schema
- **Decision**: SQLAlchemy 2 models with portable types (`UTCDateTime`, `JSONType` = JSON/JSONB);
  enums persisted as strings. Alembic revisions create and upgrade databases
  (`contextos-server init-db`); `Base.metadata.create_all` is only for test fixtures. The API
  refuses to start on an outdated or incomplete schema (`app/database/migrations.py`).
- **Consequences**: zero-setup local development; the same suite runs on PostgreSQL via
  `CONTEXTOS_TEST_DATABASE_URL` (the full suite, 1676 tests at the time, passed on PostgreSQL 17.11 on 2026-11-11). Every schema change
  needs a migration and `tests/integration/test_migrations.py` stays green.

## ADR-004 In-process event bus with ids-only notifications
- **Decision**: `app/events/bus.py` fans out `{"type", "id", …ids}` messages over SSE
  (`GET /stream`); `services/notify.py` publishes only after commit. Clients refetch details.
- **Why**: no broker to operate; no sensitive payload can travel over the stream.
- **Consequences**: live updates reach only browsers connected to the same process. Replace with
  Redis/NATS when running several replicas.

## ADR-005 Opaque session tokens and a CSRF header (not JWT)
- **Decision**: browser sessions are random `ctxs_…` tokens stored as SHA-256 hashes in
  `auth_sessions`, sent in an httpOnly `SameSite=Lax` cookie (`Secure` in production); cookie
  requests with unsafe methods must carry `X-Requested-With: contextos`. Integrations use hashed
  `ctxk_…` API keys with scopes.
- **Why**: instant revocation (logout, member removal, key revoke) without token blacklists; no
  signing-key management; a custom header cannot be sent cross-site without CORS approval.
- **Consequences**: one database lookup per request.

## ADR-006 Keyed HMAC audit chain
- **Decision**: per organisation, `hash_n = HMAC(CONTEXTOS_SECRET_KEY, canonical(entry_n) ‖ hash_{n-1})`,
  head stored in `organizations.audit_head_hash` (`services/audit.py`); `GET /audit/verify`
  recomputes it; entries are never purged.
- **Why**: detects modification, deletion, reordering and truncation by anyone who can write to the
  database but does not hold the server secret.
- **Consequences**: an attacker with both the database and the secret can rewrite the chain (export
  the head hash to write-once storage); rotating the secret breaks verification of old entries.

## ADR-007 Server-side classification only
- **Decision**: the event envelope (`app/events/envelope.py`) is `extra="forbid"` and has no fields
  for trust, risk, severity, enforcement or decisions; the organisation comes from the API key; a
  key bound to an agent may only report that agent. `category_hint` is recorded for comparison only.
- **Why**: a compromised or buggy integration must not be able to downgrade its own risk.

## ADR-008 Honest enforcement vocabulary
- **Decision**: every decision carries `enforced`, `advisory` or `observed`, computed by the server
  from the call path and integration kind (`ENFORCING_INTEGRATIONS` in
  `services/ingestion_state.py`). UI and docs say "blocked" only for `enforced`. A new adapter is
  `advisory` until tests prove its boundary.
- **Consequences**: overview and integrations pages report enforcement coverage; provenance risky
  paths state `prevented` / `awaiting_approval` / `advisory_only` / `not_prevented`.

## ADR-009 Claude Code hooks never answer `allow`
- **Decision**: the `PreToolUse` hook returns no decision on ALLOW/AUDIT, `deny` on DENY, `ask` or
  `deny` for unresolved approvals; `Verdict` in `sdk/contextos/integrations/claude_code/enforce.py`
  refuses `allow`.
- **Why**: `allow` would skip Claude Code's own permission prompt; ContextOS should only make the
  host stricter.
- **Consequences**: ContextOS cannot pre-approve calls in Claude Code; a broken install exits 2 so
  Claude Code blocks the call (fail closed).

## ADR-010 MCP security gateway as a stdio proxy
- **Decision**: `contextos mcp-gateway` is started by the host in place of an MCP server, starts the
  real server as a child process and decides every `tools/call` via `/decide` before contacting it;
  listings, results, resources and prompts are reported and scanned
  (`sdk/contextos/integrations/mcp_gateway/`).
- **Why**: works with any stdio MCP host without host support; the upstream server never sees
  ContextOS credentials (`CONTEXTOS_*` stripped).
- **Consequences**: HTTP upstreams, sampling/elicitation and subscriptions are not proxied
  ([integrations/mcp.md](integrations/mcp.md#limitations)).

## ADR-011 Deterministic detection first, optional classifier
- **Decision**: rule-based detection over normalised views (decoding, hidden-text extraction,
  homoglyph folding, re-flowing) with explanations and redacted excerpts; `register_classifier` is
  an optional hook that is never the only control.
- **Why**: explainable, testable, no external calls; measured on a published corpus
  ([DETECTION_EVALUATION.md](DETECTION_EVALUATION.md)).
- **Consequences**: semantic paraphrases without trigger vocabulary are missed (documented).

## ADR-012 Redact before persistence; fingerprints instead of secrets
- **Decision**: all agent-supplied text and structures pass through `engines/redaction` before any
  column, log, audit detail, notification, export or prompt; secrets become
  `[REDACTED:<type>:<fp8>]` with keyed HMAC fingerprints; raw content is kept only as a SHA-256.
- **Why**: a security tool must not become the place secrets leak from; fingerprints still let it
  match a secret read in context with the same secret in an outbound call.

## ADR-013 Simulation Lab through the real pipeline
- **Decision**: scenarios (`app/simulations/`) submit envelopes to `ingest_event` /
  `decide_tool_request` with `is_simulation=True`; nothing is executed. Rows carry the flag and the
  run id; metrics, lists and counters exclude them unless `include_simulated=true`. Demo data
  (`seed-demo`) is produced the same way.
- **Why**: tests real controls, never fakes data in product surfaces (CONTRIBUTING.md rule 7).
- **Evidence**: runs of the `malicious-web-page` and `poisoned-mcp-server` scenarios exposed two
  gaps that led to the built-in policies "Deny credentials in tool arguments after prompt
  injection" (DENY) and "Require approval for outbound calls after prompt injection"
  (REQUIRE_APPROVAL).

## ADR-014 Counterfactuals from recorded input snapshots
- **Decision**: `PolicyDecision.input_snapshot` stores the exact (redacted) evaluation input;
  counterfactual replay re-evaluates it with the pure policy engine under a hypothetical policy set
  and labels the result a simulation. Missing snapshots are "not evaluable", never reconstructed;
  nothing is persisted (`services/replay_service_counterfactual.py`).

## ADR-015 No external AI calls in fix context
- **Decision**: fix-context prompts, hypotheses, breakdowns and context packs are generated
  deterministically on the server from org-scoped records (`app/workspace/`,
  `services/workspace_ai*.py`). Repository files are read only from the operator-configured
  `CONTEXTOS_WORKSPACE_REPO_ROOT`, never from a request path.
- **Why**: no data leaves the deployment; output is reproducible and reviewable.
- **Consequences**: the prompt is handed to a coding agent by the user; ContextOS does not run it.

## ADR-016 Fail modes per integration
- **Decision**: when ContextOS cannot decide, the SDK and the MCP gateway default to `closed`
  (deny); the Claude Code hook defaults to `ask` (Claude Code's own prompt decides, because a person
  is usually at the keyboard). Invalid or under-scoped keys always deny; undecided attempts are
  spooled and recorded later as observed.

## ADR-017 Approvals belong to one call and are withdrawn when nobody waits
- **Decision**: an approval expires after `approval_timeout_s`; an adapter that stops waiting calls
  `POST /decide/approvals/{id}/cancel`, so a reviewer cannot approve a call that will never run. A
  retry is a new request.

## ADR-018 Retention as an operator command; audit never purged
- **Decision**: `contextos-server purge` deletes recorded event data older than each organisation's
  `retention_days` by server timestamps, keeps evidence of open incidents, and never deletes audit
  entries (the chain would break). It is scheduled externally (cron, Kubernetes CronJob).
