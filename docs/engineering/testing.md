# Testing

Applies to: `backend/tests/**`, `sdk/tests/**`, `frontend/src/**/__tests__/**`, `frontend/src/**/*.test.{ts,tsx}`, `frontend/src/test/**`

Layout and commands
- Backend: `backend/tests/unit/` (pure engines and workspace logic, no DB), `backend/tests/integration/`
  (HTTP via `TestClient` + SQLite), shared builders in `tests/integration/*_support.py`, attack
  corpus in `tests/corpus/seeds.py`. Run `cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider <paths>`.
- SDK: `sdk/tests/` — run from `sdk/` with `../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests`.
  SDK tests never import `app.*`; fake the server with `sdk/tests/sdk_fakes.py`.
- Frontend: `src/features/<feature>/__tests__/` with Vitest + Testing Library;
  `cd frontend && npx vitest run <paths>`.

Fixtures (`backend/tests/conftest.py`)
- `client` (TestClient on a fresh per-test SQLite file), `db`, `org` / `other_org` (`OrgCtx` with
  `user_headers` and `api_headers`), `seeded_org` (built-in policies and trust rules installed),
  `make_org(name, role=..., scopes=[...])` for role and API-key-scope variants.
- Drive behaviour through the HTTP API where a route exists; call services directly only for
  logic with no route. Do not mock the engines in integration tests — the real pipeline is the
  thing under test.

Required cases
- Every feature: happy path, validation errors (422 envelope), permissions (viewer and
  `make_org(..., scopes=["ingest"])` get 403 on writes/reads they lack), not-found.
- Every org-owned route: a test that takes `other_org` and asserts 404 for each id route
  (GET/PATCH/DELETE/POST sub-resources), absence from lists/stats, and 404 when a foreign id is
  referenced in a request body. `backend/.venv/bin/python scripts/audit/route_audit.py`
  lists routes no `other_org` test exercises.
- Security logic (redaction, detection, trust, policy, risk, enforcement mapping): adversarial
  cases — obfuscation (case, unicode, zero-width, base64/URL encoding), boundary sizes, malformed
  input, near-miss benign text (false positives), and a client trying to supply trust/risk/decision
  fields (must be rejected by the envelope).
- Redaction end to end: after ingesting a canary secret, assert the raw value is absent from every
  persisted column, audit details and API response (see `tests/integration/test_ingestion_redaction.py`).
- Honest wording: assert `enforcement` values and that "blocked" copy appears only for `enforced`.

Data hygiene
- No real secrets, ever. Use canaries (`CTXOS-CANARY-…` from `tests/corpus/seeds.py`), tokens built
  at runtime from obviously fake parts (`"ghp_" + "Zq8R…"` as in `tests/integration/ingestion_support.py`).
- Hosts: reserved names (`example.com`, `*.test`, `*.invalid`, `*.example`, `203.0.113.0/24`) by
  default. A real service domain (e.g. `webhook.site`) appears only when the detection under test
  targets it, as an inert string — tests never open network connections.
- Tests are isolated: no shared state between tests, no network, no reliance on wall-clock order
  beyond `utcnow()`; never touch `backend/data/` or ports 8000/5173.
- A failing test is fixed or the code is fixed — never deleted, skipped or loosened to pass.
