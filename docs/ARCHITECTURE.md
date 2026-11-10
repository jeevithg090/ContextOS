# ContextOS Architecture

ContextOS is a **modular monolith**: one FastAPI process (API + optional static frontend), one
relational database (SQLite for local development, PostgreSQL in production), an in-process event
bus for live updates, and client-side integrations that report events and — where the host
framework allows — ask ContextOS for a decision *before* a tool runs.

```
 Agent frameworks                      ContextOS server                                   Users
 ────────────────                      ──────────────────────────────────────────          ──────────────
 Claude Code ──hooks──┐                ┌────────────── API (/api/v1) ─────────────┐
 MCP gateway ─proxy───┼─ ctxk_ key ───▶│ POST /events   POST /decide   GET /stream│◀── browser (cookie)
 Python SDK ─guard()──┘                └───┬──────────────┬─────────────────▲─────┘
                                           │ ingestion    │ decision         │ SSE notifications
                                           ▼ pipeline     ▼                  │ (ids only)
          ┌──────────────── engines (pure, DB-free) ─────────────────┐       │
          │ redaction · detection · trust · policy · risk · provenance│       │
          └──────────────────────────┬────────────────────────────────┘       │
                                     ▼                                        │
                       services (persistence, audit, notify) ── bus ──────────┘
                                     ▼
                     SQLAlchemy models  ──  SQLite / PostgreSQL (Alembic)
```

## Layers and dependency rules

| Layer | Path | May import | Must not |
|---|---|---|---|
| Engines | `app/engines/<name>/` | `app.domain`, `app.core.security` (HMAC), stdlib | DB, FastAPI, services |
| Workspace logic | `app/workspace/` | engines, domain | DB, FastAPI |
| Services | `app/services/` | engines, models, other services | FastAPI request objects |
| Routes | `app/api/routes/` | services, schemas, deps | business rules inline |
| Schemas | `app/schemas/` | domain | models (use `from_attributes`) |

Engines are pure so they can be unit-tested exhaustively, reused by replay/simulation, and
audited independently. Integration adapters (in `sdk/`) never import server code; they speak the
HTTP event contract only — so a framework adapter can be added without touching the security core.

## The ingestion pipeline (`app/services/ingestion.py`)

`ingest_event(db, ctx, envelope)` and `decide_tool_request(db, ctx, envelope)` are the only entry
points that turn integration events into security state. Both are called by `POST /events`,
`POST /decide` and the Simulation Lab (with `ctx.is_simulation=True`).

1. **Validate** — `EventEnvelope` (Pydantic, `extra="forbid"`): no client trust/risk/decision fields.
2. **Authorise attribution** — API keys bound to an agent may only report that agent.
3. **Idempotency** — `(organization_id, client_event_id)` unique; duplicates return `duplicate`.
4. **Redact** — content, arguments and results pass through `redaction.redact_text/value`;
   secret fingerprints (keyed HMAC) are kept, raw values discarded. SHA-256 of raw content kept.
5. **Resolve entities** — upsert Agent (by name), AgentSession (by external id), ContextSource,
   Tool (server-side `risk.classify_tool`), Destination (`trust.assess_destination`).
6. **Classify trust** — `trust.assess_source` with org TrustRules + source history.
7. **Detect** — `detection.analyze_content` on context; `detection.analyze_tool_request` on tool calls;
   secret fingerprints in tool arguments are matched against fingerprints previously seen in the
   session's context (credential flow).
8. **Provenance** — edges: source→item→session, session→invocation→tool/resource/destination,
   invocation→returned item, session→delegated session, item→finding, invocation→decision.
9. **Risk** — `risk.compute_session_risk` (lethal trifecta with evidence) → `AgentSession.risk_state`.
10. **Policy** (tool.requested) — build `EvaluationInput`, `policy.evaluate`, persist
    `PolicyDecision` with the redacted `input_snapshot`; REQUIRE_APPROVAL creates an `Approval`.
11. **Findings & incidents** — `services.findings.record_finding` (deduplicated) and
    `services.incidents.escalate_finding`.
12. **Persist + audit + notify** — `IngestedEvent` row (redacted payload, server sequence),
    `append_audit` for security-relevant outcomes, `notify` after commit.

Fail modes: if the pipeline errors, `/decide` returns HTTP 5xx and the integration applies its
configured fail mode (`fail_closed` default for enforcement, `fail_open` opt-in). Detection or
risk engine failure inside the pipeline is logged and recorded as a processing error on the event —
never silently ignored.

## Enforcement model

| Mode | Meaning | Where |
|---|---|---|
| `enforced` | Decision returned at a real execution boundary that honours DENY/approval | Claude Code `PreToolUse` hook, MCP gateway `tools/call`, SDK `guard()` |
| `advisory` | Decision returned but the host may ignore it | SDK in report-only mode |
| `observed` | Event reported after execution; nothing can be prevented | `PostToolUse`, `context.ingested` |

## Cross-module contracts (stable)

- `app/events/envelope.py` — integration event contract v1.0.
- `app/services/loaders.py` — `load_policy_specs`, `load_trust_rule_specs`.
- `app/services/findings.py` — `record_finding(...) -> (finding, created)`.
- `app/services/incidents.py` — `create_incident`, `add_activity`, `escalate_finding`.
- `app/services/approvals.py` — `create_approval`, `get_approval_status`.
- `app/services/audit.py` — `append_audit`, `verify_chain`.
- `app/services/notify.py` — `notify(db, org_id, type, **ids)`; types listed in
  `frontend/src/hooks/useLiveEvents.ts`.
- Engine `__init__.py` docstrings define each engine's public API.
- `GET /api/v1/auth/me` shape — see `frontend/src/features/auth/AuthProvider.tsx`.
- `GET /api/v1/overview/nav-counts` → `{pending_approvals, open_incidents, open_findings}`.

## Frontend

- `src/app/routes.tsx` — route table; each feature owns `src/features/<feature>/`.
- `src/components/ui` — design-system primitives and status badges (single source of colour
  semantics in `src/lib/domain.ts`). `src/components/data` — shared data-display components.
- Data fetching: TanStack Query hooks in `features/<feature>/api.ts`; query keys start with the
  feature name so SSE invalidation works.
- Auth: httpOnly session cookie + `X-Requested-With: contextos` CSRF header on every request.

## Why these choices
See `docs/ARCHITECTURE_DECISIONS.md` (ADRs): modular monolith, SQLite/Postgres via SQLAlchemy,
in-process bus (no broker until multiple replicas), pure engines, keyed hash-chain audit,
opaque session tokens over JWT, deterministic detection first with optional classifier.
