# Contributing to ContextOS

Thanks for working on ContextOS. This file holds the rules every change must follow; the
path-specific engineering guides are in [docs/engineering/](docs/engineering/) and step-by-step
checklists (secure feature, integration adapter, test and verify, code review, architecture review,
threat model, repository audit, release readiness) are in
[docs/engineering/checklists/](docs/engineering/checklists/).

Read before major changes: [CONTEXT.md](CONTEXT.md) (current state) →
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) → [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) →
the doc for the area you touch ([docs/DATA_MODEL.md](docs/DATA_MODEL.md),
[docs/API_SPECIFICATION.md](docs/API_SPECIFICATION.md),
[docs/INTEGRATION_SPECIFICATION.md](docs/INTEGRATION_SPECIFICATION.md), `docs/integrations/*.md`).
Where a doc and the code disagree, the module docstrings and tests are authoritative.

## Repository layout
- `backend/` FastAPI modular monolith (Python 3.12, SQLAlchemy 2, Pydantic 2, Alembic)
  - `app/engines/*` pure, DB-free logic (redaction, detection, trust, policy, risk, provenance)
  - `app/services/*` orchestration + persistence; `app/api/routes/*` thin HTTP layer
  - `app/models/*` all tables; `app/events/envelope.py` the typed event contract
  - `app/workspace/*` pure Engineering-Workspace logic (fix context, context packs, templates)
- `sdk/` Python SDK + `contextos` CLI + integrations (Claude Code hooks, MCP gateway)
- `frontend/` React 18 + TS + Vite + Tailwind + TanStack Query + React Flow
- `docs/` authoritative product/architecture/security docs; `docs/engineering/` engineering rules and checklists
- `scripts/` smoke run and repository audit scripts

## Commands
- Backend tests: `cd backend && .venv/bin/python -m pytest -q`
- SDK tests: `cd sdk && ../backend/.venv/bin/python -m pytest -q tests`
- Run API: `cd backend && .venv/bin/uvicorn app.main:app --reload --port 8000` (refuses an
  un-migrated database: run `.venv/bin/contextos-server init-db` first)
- Migrations: `cd backend && .venv/bin/alembic upgrade head`
- Frontend: `cd frontend && npm run dev` (proxies /api → :8000), `npm run typecheck`, `npm test`, `npm run build`
- Lint: `cd backend && .venv/bin/ruff check app tests`; `cd frontend && npm run lint`
- Whole-system smoke run (fresh DB, real server): `backend/.venv/bin/python scripts/smoke.py`

## Non-negotiable rules
1. **Never persist raw secrets or raw context content.** Redact with `app.engines.redaction`
   before writing to the DB, logs, audit details, SSE messages or exports. Store hashes/fingerprints.
2. **Tenant isolation:** every org-owned query filters by `principal.org_id`
   (`app.services.scoping.scoped/get_scoped`). Return 404, not 403, for other orgs' ids.
3. **Never trust client-supplied trust/risk/decisions.** The event envelope forbids them; the
   server computes all classifications.
4. **Honest enforcement claims.** Distinguish `enforced` / `advisory` / `observed`. Only call
   something "blocked" when the integration enforces the decision at an execution boundary.
5. **Provenance ≠ causation.** Edges are observed relationships; UI and docs must say so.
6. **Counterfactuals are simulations** — label them, evaluate against recorded
   `PolicyDecision.input_snapshot`, never fabricate missing history.
7. **No fake data in product surfaces.** Metrics come from persisted rows. Demo data is produced
   by running Simulation Lab scenarios through the real pipeline and is flagged `is_simulation`.
8. Errors use `app.core.errors` types (uniform JSON envelope). No silent `except: pass`.
9. Every feature ships with tests; security logic needs adversarial cases.
10. Schema changes need an Alembic migration in `backend/alembic/versions/`.

## Conventions
- IDs: `app.core.ids.new_id("<kind>")` → prefixed ULIDs (`agt_…`, `fnd_…`).
- API: `/api/v1`, lists return `Page[T]` (`items,total,limit,offset`), `*Out` Pydantic models.
- State changes write an audit entry via `app.services.audit.append_audit` and publish a live
  notification via `app.services.notify.notify` (ids only).
- Frontend: semantic Tailwind tokens only (`bg-surface`, `text-fg-muted`, `trust-*`, `sev-*`,
  `dec-*`); status badges from `@/components/ui`; data via TanStack Query hooks in
  `features/<name>/api.ts`; every view has loading, error and empty states.
- Keep files focused (< ~500 lines); split by responsibility.

## Before you open a pull request

```bash
make lint          # ruff check + ruff format --check, ESLint, TypeScript
make test          # backend, SDK and frontend suites (three separate processes)
make build         # production frontend build
```

CI (`.github/workflows/ci.yml`) runs the same steps. After significant work, update
[CONTEXT.md](CONTEXT.md) (what works, what changed, known problems, next steps).
