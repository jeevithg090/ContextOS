# Testing strategy

ContextOS is a security product: its tests must show that controls hold against adversarial input,
that organisations cannot see each other's data, that secrets never reach storage, and that
enforcement claims are honest. Rules for writing tests: `.claude/rules/testing.md`; how to run and
read the suites: `.claude/skills/test-and-verify/SKILL.md`.

## Layers

| Layer | Location | What it proves | Runs with |
|---|---|---|---|
| Unit | `backend/tests/unit/` (28 files) | Pure engines and workspace logic: redaction formats and paths, detection rules and normalisation, trust canonicalisation/matching/destinations, policy DSL, validation and built-ins, risk (tools, resources, shell parsing, session trifecta, posture), provenance paths and receipts, fix context, context packs, modes, templates, breakdown | `make test-backend` |
| Integration | `backend/tests/integration/` (39 files) | The HTTP API through FastAPI's `TestClient` on a fresh database per test: every route family, the ingestion pipeline and its redaction, payload limits, approvals, incidents, replay, Simulation Lab, retention, migrations, CLI operations, SSE stream, auth and CSRF | `make test-backend` |
| End to end | `backend/tests/e2e/` (6 files) | The twelve-step product workflow and a security investigation through the public API; **live** tests that start a real `contextos-server` process and run the real Claude Code hook, MCP gateway, SDK example and CLI as subprocesses (marker `live`) | `make test-backend` |
| Organisation isolation sweep | `backend/tests/integration/test_org_isolation_sweep.py` | Enumerates **every** route from the app. Organisation B (owner session and API key) requests each with organisation A's ids in path, query and body, and with non-existent ids: answers must be 404 (or an identical 403 for a missing scope), no response may contain A's ids, no 5xx, and A's rows must be byte-identical afterwards. A new, unclassified route fails the sweep. | `make test-backend` |
| Detection corpus | `backend/tests/corpus/`, `tests/unit/test_detection_corpus.py`, `test_detection_tuning.py` | Precision/recall floors on a labelled, reproducible corpus (below) | `make test-backend` |
| SDK, CLI, adapters | `sdk/tests/` (19 files) | Client retries and spool, envelope contract against the server model, `guard()` decisions/restrictions/fail modes (sync and async), CLI commands, Claude Code mapping per hook and decision → hook answer (never `allow`), installer, MCP gateway mapping, enforcement, proxy (in-memory MCP stack) and an integration run against the real backend | `make test-sdk` |
| Frontend | `frontend/src/**/__tests__/` (46 files) | Pages and components with Vitest + Testing Library: loading/error/empty states, filters, forms and validation, live invalidation, honest wording (e.g. simulated and advisory labels) | `make test-frontend` |
| Smoke | `.claude/skills/release-readiness/scripts/smoke.py` | Fresh database, real server process, real HTTP: setup, ingest, deny with `enforcement=enforced`, approval end to end, incident and audit chain, redaction at rest and in logs, org isolation | run by hand before a release |

Every feature has happy-path, validation (422), permission (403 per role/scope), not-found and
cross-organisation (404) cases; security logic has adversarial cases (obfuscation, encodings,
boundary sizes, malformed input, near-miss benign text, attempts to send trust/risk/decision
fields). Redaction tests ingest canary secrets and assert they are absent from every persisted
column, audit detail, response, notification and log.

## Detection corpus

Measured numbers (held-out **test** split; details, method and blind spots in
[DETECTION_EVALUATION.md](DETECTION_EVALUATION.md)):

| Split | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| Content, test (1269 samples in total, 604 in test) | 0.968 | 0.931 | 0.949 | 0.045 |
| Tool requests, test (91 in total, 46 in test) | 1.000 | 0.895 | 0.944 | 0.000 |

Targets were ≥ 0.90 precision and ≥ 0.85 recall; both sets meet them. Tool-request precision was
0.850 on the first held-out run (one benign seed, `echo $PATH`); the rule was narrowed afterwards,
so 1.000 is not a clean held-out estimate (disclosed in DETECTION_EVALUATION.md). The regression
floors in `test_detection_corpus.py` sit just below the measured numbers (content P ≥ 0.96, R ≥ 0.92;
tool requests P ≥ 0.95, R ≥ 0.89; per-technique recall ≥ 0.80). The dev split was used for tuning, so
its perfect scores are not evidence of real-world accuracy.

```bash
cd backend
.venv/bin/python -m tests.corpus.evaluate              # both splits, text report
.venv/bin/python -m tests.corpus.generate --check      # committed corpus matches the generator
```

## How to run

```bash
make test                     # backend, SDK, frontend (three separate processes)
make lint                     # ruff, ESLint, TypeScript

cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests              # backend only
cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests -m "not live"  # without subprocess e2e tests
cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests        # SDK only
cd frontend && npx tsc -b --noEmit && npx eslint src && npx vitest run            # frontend
```

The backend and SDK suites cannot share one pytest process (both packages are named `tests`); see
[DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md#why-the-backend-and-sdk-suites-run-separately).

**PostgreSQL**: set `CONTEXTOS_TEST_DATABASE_URL` to a dedicated database whose name contains
`test` (for example `postgresql+psycopg://user:pw@127.0.0.1:18432/contextos_test`); tables are
recreated once per run and truncated before each test. Tests that build their own SQLite
databases (CLI, migrations) keep doing so.

Live Claude Code verification (needs a Claude Code login and network):
`PYTHONPATH=sdk backend/.venv/bin/python examples/claude_code/live_verify.py --model haiku`
([integrations/claude-code.md](integrations/claude-code.md#live-verification)).

## Last recorded results (2026-11-13)

| Suite | Result |
|---|---|
| Backend, SQLite | 1780 passed (≈ 1.5 min; 1751 at the 2026-11-11 release review) |
| Backend, PostgreSQL 17.11 scratch database | 1751 passed (2026-11-11 release review; not re-run since) |
| SDK | 387 passed |
| Frontend | `tsc` clean, ESLint clean, 492 tests passed in 66 files (every page has a `*.page.test.tsx`) |
| `ruff check app tests` | clean |

Suites grow as work lands; re-run them rather than trusting these numbers, and record new counts
in [../CONTEXT.md](../CONTEXT.md).

## Hygiene

No real secrets (canaries such as `CTXOS-CANARY-…`, tokens assembled at runtime), reserved hosts
(`example.com`, `*.test`, `*.invalid`, `*.example`, `203.0.113.0/24`), no network, no shared state
between tests, never `backend/data/` or ports 8000/5173. Live tests use free ports in 18000–18999
and temporary databases. A failing test is fixed — never deleted, skipped or loosened.
