# Test and verify

> Run the right ContextOS test suites, linters and type checks for a change, interpret failures correctly, and report verified results with exact counts. Use after any code change and before saying work is done, when a suite is red and you need to know whether it is yours, or when asked to "run the tests", "verify", or "check nothing broke".

Never report "tests pass" without the command and its count. Never delete, skip, xfail or loosen
a test to get green; fix the code or the test's wrong assumption and say which.

## 1. Map the change to suites
`git status --short` and `git diff --stat` list what changed. Then:

| Changed | Run (from repo root unless noted) |
|---|---|
| `backend/app/engines/<x>/` | `cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit -k <x>` then the integration files that exercise it (`grep -rl "<x>" tests/integration`) |
| `backend/app/services/<area>*`, `api/routes/<area>.py`, `schemas/<area>.py` | `tests/integration/test_<area>*_api.py` (+ `test_ingestion_*.py` for ingestion) |
| `backend/app/services/ingestion*`, `events/envelope.py` | `tests/integration/test_ingestion_*.py test_events_api.py test_decide_api.py`, then **all SDK tests** (contract) |
| `backend/app/models/`, `alembic/` | full backend suite + migration round trip (§3) |
| `backend/app/core/`, `api/deps.py`, `services/scoping.py`, `services/audit.py` | full backend suite |
| `sdk/` | `cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests` |
| `frontend/src/features/<f>/` | `cd frontend && npx vitest run src/features/<f>` + tsc + eslint on the paths |
| `frontend/src/components/`, `lib/`, `hooks/` | `cd frontend && npx vitest run` (all) + tsc + eslint |
| `scripts/` | `backend/.venv/bin/python -m pytest -q -p no:cacheprovider scripts` |

Always add, for any backend change: `cd backend && .venv/bin/ruff check app tests`.

## 2. Commands (exact)
```bash
# Backend — targeted, then full before finishing (full ≈ 5 min on a loaded machine)
cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests/integration/test_findings_api.py
cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests
cd backend && .venv/bin/ruff check app tests
# SDK (uses the backend virtualenv; never imports app.*)
cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests
# Frontend
cd frontend && npx tsc -b --noEmit
cd frontend && npx eslint src            # or specific paths
cd frontend && npx vitest run            # or src/features/<f>
cd frontend && npm run build             # tsc -b && vite build; needed before the smoke test serves the UI
# Whole system from a clean database (real server process, real HTTP; random port 18000-18999)
backend/.venv/bin/python scripts/smoke.py
# Org-isolation coverage of the API
backend/.venv/bin/python scripts/audit/route_audit.py
```
Use a 10-minute timeout for full suites. Useful flags: `-x` (stop at first failure), `-k <expr>`,
`--lf` is unavailable with `-p no:cacheprovider` — re-run the failing node ids instead
(`pytest -q -p no:cacheprovider "tests/integration/test_x.py::test_y"`).

## 3. Migrations (when models or `backend/alembic/` changed)
```bash
cd backend && S=$(mktemp -d) && export CONTEXTOS_DATABASE_URL=sqlite:///$S/a.db \
  && .venv/bin/alembic upgrade head && .venv/bin/alembic check \
  && .venv/bin/alembic downgrade base && .venv/bin/alembic upgrade head; rm -rf "$S"; unset CONTEXTOS_DATABASE_URL
```
Expect "No new upgrade operations detected." from `alembic check`.

## 4. Interpreting failures
- **Is it mine?** `git diff --stat -- <failing test file> <code it covers>`. If neither you nor the
  test's subject changed, re-run that file alone. Still red with unrelated code → someone else's
  in-flight change (parallel work happens in this tree): report it with the node id and error; do
  not "fix" files you don't own. Never use `git stash`/`checkout` to get a baseline in a shared tree.
- **ImportError / AttributeError at collection** → a module or contract changed; check the stable
  contracts list in `docs/ARCHITECTURE.md`; extend, don't break signatures.
- **`AuthenticationError`/`AppError` raised inside TestClient** instead of a status code → the app
  under test was built without `register_error_handlers` (use the `client` fixture / `create_app()`).
- **422 with `validation_failed`** → request body violates a schema (`extra="forbid"` rejects
  unknown fields — intended for the event envelope).
- **404 where 200 expected** → you queried another org's id or forgot `seeded_org` (no policies or
  trust rules installed → different decisions).
- **Decision differs from expectation** (`ALLOW` vs `DENY`) → built-in pack ordering/priority
  (`backend/app/engines/policy/builtin.py`) or missing `seeded_org`; print `response["reason"]`.
- **`database is locked`** → two sessions writing the same SQLite file concurrently; use the
  per-test `engine` fixture, commit before calling the API from the test session.
- **Redaction test lists a leak** → a new column/log/notify received raw text; redact at the write site.
- **Timeouts / slowness** → the machine is loaded; raise the timeout, run a narrower set first.
- **Frontend `tsc` errors in files you didn't touch** → a backend `*Out` changed and its
  `types.ts` mirror wasn't updated; report to the owner.
- **`PytestAssertRewriteWarning` / `PytestDeprecationWarning`** → harmless.

## 5. Report (return this)
```text
Verified (<date>):
- cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests  → <N> passed, <M> failed (<duration>)
- cd backend && .venv/bin/ruff check app tests                           → All checks passed | <n> errors
- cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests → <N> passed
- cd frontend && npx tsc -b --noEmit / npx eslint src / npx vitest run   → clean / clean / <N> passed
Not run: <suite> — <why>
Failures not mine: <node id> — <error>, owner/area <x>
```
Compare counts with the last numbers recorded in `CONTEXT.md`; a drop in the number of tests is
itself a finding.
