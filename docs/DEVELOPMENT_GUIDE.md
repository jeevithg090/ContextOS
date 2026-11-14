# Development guide

How to set up ContextOS, run it, and extend it the way the codebase expects. The rules every change
must follow are in [../CONTRIBUTING.md](../CONTRIBUTING.md) (the ten non-negotiable rules) and the path-scoped
files in `docs/engineering/`; the step-by-step procedures are `docs/engineering/checklists/<name>.md`
(`secure-feature`, `integration-builder`, `test-and-verify`, `code-review`, …).

## Setup

Requirements: Python 3.12 (3.11+ works), Node.js 22.12+ with npm, `make`.

```bash
make install PYTHON=python3.12   # backend/.venv (backend[dev,postgres] + sdk[mcp], editable) and npm ci in frontend/
```

Equivalent manual steps:

```bash
python3.12 -m venv backend/.venv
backend/.venv/bin/python -m pip install -e "backend[dev,postgres]" -e "sdk[mcp]"
cd frontend && npm ci
```

One virtualenv serves the server, the SDK, the `contextos` CLI and both test suites
(`backend/.venv/bin/contextos-server`, `backend/.venv/bin/contextos`).

## Running locally

```bash
cd backend
.venv/bin/contextos-server init-db                 # or: make migrate (from the root)
.venv/bin/contextos-server create-org --name "Acme AI" --email owner@example.com --name-of-owner "Ada Owner"
.venv/bin/contextos-server create-api-key --org-slug acme-ai --name "dev laptop" --scopes ingest,decide,read
.venv/bin/uvicorn app.main:app --reload --port 8000  # or: make dev-backend
cd ../frontend && npm run dev                       # or: make dev-frontend → http://localhost:5173
```

- The database defaults to `sqlite:///./data/contextos.db` relative to the working directory
  (`backend/data/contextos.db`); set `CONTEXTOS_DATABASE_URL` or pass
  `contextos-server --database-url …` to use another one.
- The API refuses to start on an un-migrated database and names the fix (`init-db`).
- Demo data: `.venv/bin/contextos-server seed-demo --org-slug acme-ai` runs the Simulation Lab
  scenarios through the real pipeline (rows flagged `is_simulation`).
- API docs of the running server: `http://127.0.0.1:8000/api/docs`.
- Vite proxies `/api` to `127.0.0.1:8000`. To serve the built SPA from the API instead:
  `make serve`.

## Everyday commands

| Task | Command |
|---|---|
| All tests | `make test` (backend, SDK, frontend as three processes) |
| Backend tests | `make test-backend` or `cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests` |
| SDK tests | `make test-sdk` or `cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests` |
| Frontend tests | `make test-frontend` or `cd frontend && npx vitest run` |
| Lint and types | `make lint` (`ruff check app tests`, `eslint src`, `tsc -b --noEmit`) |
| Frontend build | `make build` (`frontend/dist`) |
| Detection corpus | `cd backend && .venv/bin/python -m tests.corpus.evaluate` |
| Route auth/isolation audit | `backend/.venv/bin/python scripts/audit/route_audit.py` |
| Docs reference missing paths | `backend/.venv/bin/python scripts/audit/doc_paths.py` |
| Clean-environment smoke run | `backend/.venv/bin/python scripts/smoke.py` |

### Why the backend and SDK suites run separately

`backend/tests` and `sdk/tests` are both Python packages named `tests`, and many backend tests
import `tests.integration.*`. One pytest process cannot collect both: the second `tests` package
resolves to the first and collection fails with "No module named 'tests.test_…'". So `make test`
runs them as separate processes, each from its own directory (`backend/pyproject.toml` and
`sdk/pyproject.toml` pin their `testpaths`). Never point one pytest run at both directories. SDK
tests never import `app.*` (except the optional contract check in `test_client_contract.py`).

## Conventions (summary)

- **Layers**: engines and `app/workspace` are pure (no DB, no FastAPI); services take `db` and
  `org_id`; routes are thin (parse, call a service, commit, return an `*Out`). See
  [ARCHITECTURE.md](ARCHITECTURE.md#layers-and-dependency-rules).
- **Tenancy**: `scoped(Model, principal.org_id)` / `get_scoped` / `find_scoped`; foreign ids → 404.
- **Redaction** before anything reaches a column, log, audit `details`, notification, export or
  prompt (`app.engines.redaction.redact_text` / `redact_value`).
- **Ids**: `app.core.ids.new_id("<kind>")`; add new kinds to `PREFIXES` (3-letter prefix).
- **Time**: `app.core.timeutil.utcnow()`.
- **Errors**: `app.core.errors` types; never `HTTPException` or `except: pass`.
- **State changes**: `append_audit(...)` and `notify(...)` (ids only) in the same transaction.
- **Frontend**: semantic Tailwind tokens (`bg-surface`, `text-fg-muted`, `trust-*`, `sev-*`,
  `dec-*`), status badges from `@/components/ui`, TanStack Query hooks in `features/<name>/api.ts`,
  loading/error/empty states on every view.
- Files stay focused (< ~500 lines); split by responsibility.

## How to …

### Add a detection rule
1. Content rules: add a `Rule(...)` to `CONTENT_RULES` in
   `backend/app/engines/detection/rules.py` (stable `rule_id`, `FindingCategory`, severity,
   confidence, plain-language explanation, pattern). Tool-request rules: `ToolRule` in
   `tool_rules.py`.
2. Unit tests in `backend/tests/unit/test_detection.py`: the attack, obfuscated variants and
   near-miss benign text.
3. Add seeds to `backend/tests/corpus/seeds.py`, regenerate (`.venv/bin/python -m tests.corpus.generate`)
   and evaluate (`.venv/bin/python -m tests.corpus.evaluate`); the floors in
   `tests/unit/test_detection_corpus.py` must still pass. Update
   [DETECTION_EVALUATION.md](DETECTION_EVALUATION.md) with the new numbers.

Trust, policy and risk rules follow the same pattern: defaults in `engines/trust/defaults.py`,
built-in policies in `engines/policy/builtin.py` (every `conditions` must pass
`validate_conditions`; seeding is idempotent by `builtin_key`), tool classification in
`engines/risk/tool_names.py`. Update the engine's `__init__.py` docstring when its public API grows.

### Add an endpoint
Follow `docs/engineering/checklists/secure-feature.md`. In short: schema (`app/schemas/<area>.py`,
`*In` with `extra="forbid"`, `*Out`), scoped service with redaction, audit and notify, route with
`Depends(require(Permission.X.value))` (static paths before `/{id}`), register new modules in
`app/api/router.py`, tests (happy path, 422, 403 per role/scope, 404, `other_org` isolation), add a
new notify type to `INVALIDATIONS` in `frontend/src/hooks/useLiveEvents.ts`, classify the route in
`tests/integration/test_org_isolation_sweep.py` (the sweep fails on unclassified routes), and add
the row to [API_SPECIFICATION.md](API_SPECIFICATION.md).

### Add a dashboard page
1. `frontend/src/features/<feature>/` with `api.ts` (TanStack Query hooks; query keys start with
   the feature name so live invalidation works), `types.ts`, the page component and `__tests__/`.
2. Register it in `frontend/src/app/routes.tsx` (`page(path, title, loader, exportName)`) and, if it
   is a top-level area, in `frontend/src/app/nav.ts` with its one-line question.
3. Loading, error and empty states; status badges from `@/components/ui`; tokens only.
4. `cd frontend && npx tsc -b --noEmit && npx eslint src && npx vitest run`, then describe the page
   in [PRODUCT_SPECIFICATION.md](PRODUCT_SPECIFICATION.md).

### Add a migration
Every schema change ships an Alembic revision (see `docs/engineering/database-migrations.md`).
Generate it against a scratch database, never `backend/data/contextos.db`:

```bash
cd backend && S=$(mktemp -d) && export CONTEXTOS_DATABASE_URL=sqlite:///$S/m.db \
  && .venv/bin/alembic upgrade head \
  && .venv/bin/alembic revision --autogenerate --rev-id 0002_<slug> -m "<what changed>"
```

Then read and fix the file (no application imports; `sa.DateTime(timezone=True)`; the module-level
`JSON_TYPE` as in `0001_initial_schema.py`; batch mode for SQLite; a real `downgrade()`), verify
`alembic upgrade head`, `alembic check`, `alembic downgrade base && alembic upgrade head`, and keep
`tests/integration/test_migrations.py` green. Update [DATA_MODEL.md](DATA_MODEL.md).

### Add an integration adapter
Follow `docs/engineering/checklists/integration-builder.md` and `docs/engineering/integration-adapters.md`:
pure `mapping.py`, HTTP only via `ContextOSClient`, fail closed, never forward an unrestricted call
under RESTRICT, spool on failure, tests per hook/message type. A new integration kind is
`advisory` until it is added to `ENFORCING_INTEGRATIONS` with tests proving the boundary. Document
it in `docs/integrations/` and [INTEGRATION_SPECIFICATION.md](INTEGRATION_SPECIFICATION.md).

## Working with PostgreSQL locally

Run the backend suite against a dedicated test database (its name must contain `test`; tables are
dropped and recreated once per run and truncated before each test):

```bash
cd backend && CONTEXTOS_TEST_DATABASE_URL=postgresql+psycopg://user:pw@127.0.0.1:18432/contextos_test \
  .venv/bin/python -m pytest -q -p no:cacheprovider tests
```

## Documentation

Docs describe what the code does today (`docs/engineering/documentation.md`). After significant work,
update [../CONTEXT.md](../CONTEXT.md) and the area doc in the same change.
