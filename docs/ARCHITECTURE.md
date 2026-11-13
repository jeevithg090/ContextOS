# ContextOS Architecture

ContextOS is a **modular monolith**: one FastAPI process (API, live-update stream and, optionally,
the built React SPA), one relational database (SQLite for local development, PostgreSQL in
production, schema owned by Alembic), an in-process event bus for live updates, and client-side
integrations that report events and — where the host allows it — ask ContextOS for a decision
*before* a tool runs.

Related: [DATA_MODEL.md](DATA_MODEL.md) (tables), [API_SPECIFICATION.md](API_SPECIFICATION.md)
(endpoints), [INTEGRATION_SPECIFICATION.md](INTEGRATION_SPECIFICATION.md) (event contract and
adapters), [SECURITY_MODEL.md](SECURITY_MODEL.md) (controls), [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md)
(why it is built this way).

```
 Agent hosts                              ContextOS server (one process)                  People
 ───────────                              ─────────────────────────────────────────       ──────
 Claude Code ── hooks ──────────┐         ┌────────────── /api/v1 ───────────────┐
 MCP host ── stdio ── gateway ──┼ ctxk_ ─▶│ POST /events   POST /decide           │
 Python code ── guard() ────────┘   key   │ GET /decide/approvals/{id}  POST /scan│◀── browser
                                          │ GET /stream (SSE)                     │   (cookie +
                                          └──┬──────────────┬────────────────▲───┘    CSRF header)
                                             │ ingestion    │ decision        │ notifications
                                             ▼ pipeline     ▼                 │ (ids only)
            ┌──────────────── engines (pure, DB-free) ──────────────────┐  │
            │ redaction · detection · trust · policy · risk · provenance │  │
            └───────────────────────────┬────────────────────────────────┘  │
                                        ▼                                   │
              services (persistence, scoping, audit, notify) ── bus ────────┘
                                        ▼
                      SQLAlchemy 2 models ── SQLite / PostgreSQL (Alembic)
```

## Repository modules

| Path | What lives there |
|---|---|
| `backend/app/core/` | settings (`config.py`, `CONTEXTOS_*`), error envelope (`errors.py`), ids (`ids.py`), hashing/HMAC (`security.py`), logging |
| `backend/app/domain/enums.py` | shared vocabulary: trust levels, decisions, enforcement modes, severities, roles → permissions, event types |
| `backend/app/events/` | `envelope.py` (integration event contract v1.0), `bus.py` (in-process pub/sub) |
| `backend/app/engines/` | `redaction`, `detection`, `trust`, `policy`, `risk`, `provenance` — pure functions, no DB, no FastAPI |
| `backend/app/workspace/` | pure Engineering Workspace logic: board templates, prompt modes, context packs, fix-context sections, hypotheses, breakdown |
| `backend/app/simulations/` | Simulation Lab scenarios, payloads, checks and the runner |
| `backend/app/services/` | orchestration and persistence: ingestion pipeline (`ingestion*.py`), findings, incidents, approvals, trust, policies, replay, overview, retention, workspace, audit, notify, scoping |
| `backend/app/api/` | `deps.py` (authentication, permissions, CSRF), `router.py`, `routes/*` (22 thin route modules) |
| `backend/app/schemas/` | Pydantic request/response models (`*In`, `*Out`, `Page[T]`) |
| `backend/app/models/` | SQLAlchemy tables (41), `database/` engine, session, Alembic integration |
| `backend/alembic/` | migrations (`versions/0001_initial_schema.py`, `0002_incident_seq.py`) |
| `sdk/contextos/` | Python SDK, `contextos` CLI, `integrations/claude_code`, `integrations/codex`, `integrations/mcp_gateway` |
| `frontend/src/` | React 18 + TypeScript SPA: `app/` (routes, nav), `features/<area>/`, `components/`, `hooks/useLiveEvents.ts`, `lib/domain.ts` |

## Layers and dependency rules

| Layer | Path | May import | Must not |
|---|---|---|---|
| Engines | `app/engines/<name>/` | `app.domain`, `app.core.security` (HMAC), stdlib | DB, FastAPI, services |
| Workspace logic | `app/workspace/` | engines, domain | DB, FastAPI |
| Services | `app/services/` | engines, models, other services | FastAPI request objects |
| Routes | `app/api/routes/` | services, schemas, deps | business rules inline |
| Schemas | `app/schemas/` | domain | models (use `from_attributes`) |

Engines are pure so they can be unit-tested exhaustively, reused by replay, Simulation Lab and the
detection corpus evaluator, and audited independently. Each engine's `__init__.py` docstring is
its contract. Integration adapters (`sdk/`) never import server code; they speak the HTTP event
contract only, so a new framework adapter does not touch the security core.

Tenancy: every org-owned table carries `organization_id` (`OrgScopedMixin`); every query goes
through `app.services.scoping` (`scoped`, `get_scoped`, `find_scoped`) with `principal.org_id`.
Another organisation's id answers 404. `backend/tests/integration/test_org_isolation_sweep.py`
enumerates every route and fails on any cross-org leak or an unclassified new route.

## Authentication and authorisation (`app/api/deps.py`)

- **Browser users**: an opaque session token (`ctxs_…`, stored as a hash in `auth_sessions`) in an
  httpOnly, `SameSite=Lax` cookie. Cookie-authenticated `POST/PUT/PATCH/DELETE` requests must send
  `X-Requested-With: contextos` (CSRF defence). `X-ContextOS-Org` selects an organisation when a
  user belongs to several. Roles map to permissions in `ROLE_PERMISSIONS`
  (`owner`/`admin`: all; `security_analyst`: read, write, approve, policy:manage, trust:manage;
  `developer`: read, write; `viewer`: read).
- **Integrations**: API keys `Authorization: Bearer ctxk_…` (stored hashed) with scopes `ingest`,
  `decide`, `read` (keys never get `write`, `approve` or admin permissions). A key bound to one
  agent may only report that agent; the organisation overview refuses bound keys.
- First run: `POST /auth/setup` (the login page offers it while `needs_setup` is true) or
  `contextos-server create-org`. Both seed the built-in policy pack and default trust rules.

## The ingestion pipeline (`app/services/ingestion.py`)

`ingest_event(db, ctx, envelope)` and `decide_tool_request(db, ctx, envelope)` are the only entry
points that turn integration events into security state. They are called by `POST /events`
(`ingest_batch`, one SAVEPOINT per event), `POST /decide` and the Simulation Lab runner
(`IngestContext.is_simulation=True`).

1. **Validate** — `EventEnvelope` (Pydantic, `extra="forbid"`): no client trust, risk, severity or
   decision fields. Per-event size limit `CONTEXTOS_MAX_EVENT_BYTES` (rejected on `/events`, 413
   on `/decide`); request bodies over 4× the limit are refused with 413 before authentication.
2. **Authorise attribution** — a key bound to an agent may only report that agent
   (`attribution_rejected`, 403).
3. **Idempotency** — `(organization_id, client_event_id)` is unique; a duplicate returns
   `duplicate` (on `/decide`, the original decision).
4. **Redact** — content, arguments and results pass through `redaction.redact_text/value`; secret
   fingerprints (keyed HMAC) are kept, raw values discarded; SHA-256 of the raw content kept.
   Fragments of secrets seen in the event are scrubbed from excerpts too (`PipelineState.scrub`).
5. **Resolve entities** (`ingestion_entities.py`) — upsert Agent (by name), AgentSession (by external
   id), ContextSource, Tool (server-side `risk.classify_tool`), Destination
   (`trust.assess_destination`), Integration (last event time, counts).
6. **Classify trust** — `trust.assess_source` with the org's TrustRules and the source's recorded
   history (evidence can downgrade to SUSPICIOUS even a manually trusted source).
7. **Detect** — `detection.analyze_content` on context; `detection.analyze_tool_request` on tool
   calls; secret fingerprints in tool arguments are matched against fingerprints seen in the
   session's context (credential flow, `ToolInvocation.matched_session_fingerprints`).
8. **Provenance** — observed-relationship edges: source→item→session, session→invocation→
   tool/resource/destination, invocation→returned item, session→delegated session, item→finding,
   invocation→decision (`confidence="observed"`). A secret-fingerprint match between context and a
   later tool call is stored on the invocation (`matched_session_fingerprints`) and presented as an
   inferred relationship.
9. **Risk** — `risk.compute_session_risk` (lethal-trifecta conditions with evidence) →
   `AgentSession.risk_state`.
10. **Policy** (`tool.requested`) — build `EvaluationInput`, `policy.evaluate`, persist
    `PolicyDecision` with the redacted `input_snapshot`; `REQUIRE_APPROVAL` creates an `Approval`
    that expires after the org's `approval_timeout_s`.
11. **Findings and incidents** — `services.findings.record_finding` (deduplicated by fingerprint)
    and `services.incidents.escalate_finding` (critical findings, and high ones in `exfiltration`,
    `lethal_trifecta`, `secret_exposure`, `cross_agent_contamination`, open an incident).
12. **Persist, audit, notify** — `IngestedEvent` (redacted payload, server sequence, `refs`),
    `append_audit` for security-relevant outcomes, `notify` after commit.

Failure handling: an exception while processing an event rolls back that event's SAVEPOINT and
records the (redacted) event with `processing_status="error"` — logged and visible, never silently
dropped. `decide_tool_request` then raises `DecisionFailedError` (HTTP 500) so the integration
applies its fail mode. A tool result that arrives for a call ContextOS did not allow raises
`CTX-DECISION-NOT-HONOURED` (or the low-severity `CTX-APPROVED-AT-HOST-PROMPT` when the Claude Code
hook reports that a person approved the call at Claude Code's own prompt).

## Enforcement model

The server states, for every decision, how much it can claim (`PolicyDecision.enforcement`,
computed in `app/services/ingestion_state.py`):

| Mode | Meaning | When |
|---|---|---|
| `enforced` | Decision returned at a real execution boundary that honours DENY and approvals | `POST /decide` from an integration in `ENFORCING_INTEGRATIONS` = `claude_code` (PreToolUse hook), `openai_codex` (Codex PreToolUse hook), `mcp_gateway` (`tools/call`), `python_sdk` (`guard()`) |
| `advisory` | Decision returned, but the caller may ignore it | `POST /decide` from any other `integration` value (default `custom`) |
| `observed` | Reported after execution; nothing could be prevented | `POST /events` (e.g. `tool.completed`, `context.ingested`, a `tool.requested` spooled while ContextOS was unreachable) |

Policy `mode` is separate: `enforce` policies decide the outcome; `monitor` policies are recorded
in `monitor_matches` only (dry run). Precedence among enforce matches:
DENY > REQUIRE_APPROVAL > RESTRICT > AUDIT > ALLOW; no match → the org's `default_decision`.
Integrations must apply every RESTRICT restriction or deny, and treat unknown decisions as DENY.
What each adapter covers, and what bypasses it, is in [INTEGRATION_SPECIFICATION.md](INTEGRATION_SPECIFICATION.md).

## Investigation features

- **Replay** (`replay_service.py`) — a session's recorded events in server sequence order, with the
  recorded decision of each step and the session risk recomputed from the recorded events.
- **Counterfactual replay** (`replay_service_counterfactual.py`) — a *simulation*: every recorded
  `PolicyDecision` is re-evaluated by the pure policy engine against its stored `input_snapshot`
  under a hypothetical policy set. Missing inputs are reported as not evaluable, never
  reconstructed; nothing is persisted.
- **Incidents** — timeline merged from recorded events, findings, decisions, approvals and activity
  (an observed sequence, not causation); evidence bundle export with `integrity.sha256` written to
  the audit chain.
- **Provenance graph** — built from `provenance_edges` by `engines/provenance`; risky paths
  (untrusted origin → session → sensitive access / non-approved destination) state their outcome
  (`prevented`, `awaiting_approval`, `advisory_only`, `not_prevented`) and that edges are observed
  relationships.
- **Simulation Lab** (`app/simulations/`) — nine scenarios whose steps are submitted as envelopes
  through the real pipeline with `is_simulation=True`; nothing is executed. Checks compare the
  recorded rows with expectations. Simulated rows are excluded from metrics, lists and counters
  unless a caller passes `include_simulated=true`.

## Live updates

`services/notify.notify(db, org_id, type, **ids)` queues a tiny message (`{"type", "id", …ids}`)
that is published to `events/bus.py` only after the transaction commits (dropped on rollback).
`GET /api/v1/stream` (SSE, `read`, ping every 15 s) fans messages out to the organisation's
connected browsers. `frontend/src/hooks/useLiveEvents.ts` maps each type (`event.ingested`,
`decision.made`, `finding.created`, `approval.created`, `incident.updated`, `simulation.completed`,
`retention.purged`, …) to TanStack Query keys to invalidate; the UI then refetches details through
the API. The bus is in-process: live updates reach only browsers connected to the same API process.

## Engineering Workspace

Kanban boards, tasks and AI fix context that turn findings into fixes. Tasks reference security
records through `task_context_refs` instead of copying event data. The fix-context generator
(`app/workspace/fix_context.py`, `services/workspace_ai*.py`) is deterministic and runs on the
server: it assembles sections (problem, evidence, codebase context, hypotheses, constraints,
acceptance criteria, verification) from org-scoped records and a token-budgeted context pack.
**No external AI provider is called.** Repository files are read only when the operator sets
`CONTEXTOS_WORKSPACE_REPO_ROOT`; otherwise packs say that repository files could not be verified.
Verification can run a Simulation Lab scenario (`verify-with-simulation`); columns can require a
passed verification and automate moves (`pr_linked`, `verification_passed`, …).

## Data lifecycle

`contextos-server purge` (`services/retention.py`) deletes recorded event data older than each
organisation's `retention_days` (server timestamps only). Audit entries are never deleted (keyed
hash chain); evidence of open incidents is kept until the incident closes. See
[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md).

## Cross-module contracts (stable)

- `app/events/envelope.py` — integration event contract v1.0 (`EventEnvelope`, `EventBatch`,
  `EventResult`, `DecisionResponse`).
- `app/services/loaders.py` — `load_policy_specs`, `load_trust_rule_specs`.
- `app/services/findings.py` — `record_finding(...) -> (finding, created)`.
- `app/services/incidents.py` — `create_incident`, `add_activity`, `escalate_finding`.
- `app/services/approvals.py` — `create_approval`, `get_approval_status`, `cancel_approval`.
- `app/services/audit.py` — `append_audit`, `verify_chain`.
- `app/services/notify.py` — `notify(db, org_id, type, **ids)`; types mirrored in
  `frontend/src/hooks/useLiveEvents.ts`.
- Engine `__init__.py` docstrings define each engine's public API.
- `GET /api/v1/auth/me` shape — see `frontend/src/features/auth/AuthProvider.tsx`.
- `GET /api/v1/overview/nav-counts` → `{pending_approvals, open_incidents, open_findings}`.

## Frontend

- `src/app/routes.tsx` — route table (lazy page per route); `src/app/nav.ts` — sidebar sections
  Security, Engineering, Platform. Each feature owns `src/features/<feature>/`.
- `src/components/ui` — design-system primitives and status badges (colour semantics from
  `src/lib/domain.ts`); `src/components/data` — shared data-display components.
- Data fetching: TanStack Query hooks in `features/<feature>/api.ts`; query keys start with the
  feature name so SSE invalidation works. Every view has loading, error and empty states.
- Auth: httpOnly session cookie + `X-Requested-With: contextos` on every request.
- Served either by Vite in development (`npm run dev`, proxies `/api` to `127.0.0.1:8000`) or by the
  API process from `frontend/dist` (`CONTEXTOS_SERVE_FRONTEND=true`; unknown non-API paths return
  `index.html`).

## Why these choices
See [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md): modular monolith, pure engines,
SQLite/PostgreSQL via SQLAlchemy and Alembic, in-process bus (no broker until multiple replicas),
opaque session tokens over JWT, keyed hash-chain audit, server-side classification only, hooks that
never emit `allow`, the stdio MCP gateway, Simulation Lab through the real pipeline,
counterfactuals from input snapshots, and deterministic fix context without external AI calls.
