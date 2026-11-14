# ContextOS

**A security, trust, provenance and observability layer for autonomous AI agents.**

AI coding and tool-using agents read files, web pages, MCP tool results and messages from other
agents — and any of that context can carry a prompt injection or lure an agent into leaking a
credential. ContextOS sits at the agent's execution boundaries: it records what context each agent
consumed and where it came from, classifies how far each source can be trusted, detects prompt
injection and credential exfiltration, decides tool calls against policy *before they run* where the
agent host allows it, and keeps the evidence you need to investigate afterwards. An Engineering
Workspace turns findings into tracked fixes.

It runs as one server (FastAPI + SQLite or PostgreSQL) with a React web UI, and connects to agents
through Claude Code hooks, OpenAI Codex hooks, an MCP security gateway and a Python SDK.

## Features

| Pillar | What ContextOS does | Where |
|---|---|---|
| **Context observability** | Records every piece of context an agent receives (prompts, files, web pages, tool and MCP results, sub-agent replies) as a redacted, hashed, signed *Context Receipt*. Raw content and secrets are never stored. | Context Explorer, Agents, Sessions |
| **Trust** | Classifies sources and outbound destinations (`TRUSTED` … `BLOCKED`) from rules plus recorded evidence; content from untrusted sources is data, never instructions. | Trust Centre |
| **Provenance** | Draws the observed relationships from source → context → session → tool call → destination, and highlights risky paths. Edges are observed relationships, not proof of causation. | Provenance Graph |
| **Threat detection** | Deterministic detection of prompt injection, instruction override, credential seeking, exfiltration instructions, MCP tool poisoning, cross-agent contamination, dangerous tool use and the *lethal trifecta* (untrusted content + private data + an outbound channel). | Security Intelligence |
| **Policy enforcement** | Evaluates each tool call against policies (`ALLOW`, `AUDIT`, `RESTRICT`, `REQUIRE_APPROVAL`, `DENY`) and states honestly whether the decision was `enforced`, `advisory` or only `observed`. | Policy Studio, Approval Centre, Integrations |
| **Investigation** | Incidents with timelines and verifiable evidence exports, session replay, counterfactual policy replay (a simulation over recorded inputs), a Simulation Lab of attack scenarios run through the real pipeline, and a keyed hash-chained audit log. | Incidents, Replay Lab, Simulation Lab, Audit Log |

Plus the **Engineering Workspace**: Kanban boards, remediation tasks linked to findings and
incidents, deterministic AI fix-context prompts and context packs for coding agents (no external
AI calls), fix attempts and verification (including re-running a Simulation Lab scenario).

## What is enforced, honestly

| Integration | Enforced before the action | Observed only |
|---|---|---|
| Claude Code hooks | tool calls through `PreToolUse` (`deny`/`ask`; the hook never answers `allow`) | sessions, prompts, tool results, subagents |
| OpenAI Codex hooks | tool calls through `PreToolUse` (exit 2 blocks; an undecided approval blocks; never `ask`) | sessions, prompts, successful tool results, sub-agents |
| MCP gateway | every `tools/call`, before the upstream server is contacted | tool listings (poisoning scan), results, resources, prompts |
| Python SDK `guard()` | each guarded function call | `AgentSession` events |

Anything that bypasses those boundaries (disabled or untrusted hooks, an MCP server not behind the
gateway, a function not wrapped by `guard()`) is not enforced. Details and limits:
[docs/INTEGRATION_SPECIFICATION.md](docs/INTEGRATION_SPECIFICATION.md).

## Tech stack

| Layer | Technology |
|---|---|
| API server | Python 3.12, FastAPI, Pydantic 2, SQLAlchemy 2, Alembic, Uvicorn, SSE (sse-starlette) |
| Database | SQLite (development), PostgreSQL 17 (production, via psycopg 3) |
| Web UI | React 18, TypeScript, Vite, Tailwind CSS, TanStack Query, React Router 7, React Flow, Recharts, Radix UI |
| SDK / CLI / integrations | Python package `contextos` (httpx, Typer, Rich); Claude Code and Codex hooks, MCP stdio gateway |
| Tooling | pytest, Vitest + Testing Library, Ruff (lint + format), ESLint, TypeScript, mypy (engines), GitHub Actions, Docker |

## Architecture

```
  agent hosts                          ContextOS server (backend/app)                         web UI (frontend/)
 ┌──────────────────┐   HTTP    ┌────────────────────────────────────────────────────┐   /api/v1 + SSE  ┌──────────────┐
 │ Claude Code hooks│──────────▶│ api/routes   thin HTTP layer, auth, CSRF, scoping  │◀────────────────▶│ React SPA    │
 │ Codex hooks      │  events,  │ services     ingestion pipeline, persistence,      │                  │ dashboards,  │
 │ MCP gateway      │  /decide  │              audit chain, notifications            │                  │ investigation│
 │ Python guard()   │◀──────────│ engines      pure logic: redaction, detection,     │                  │ workspace    │
 └──────────────────┘ decision  │              trust, policy, risk, provenance       │                  └──────────────┘
                                │ models       41 tables, schema owned by Alembic    │
                                └────────────────────────────────────────────────────┘
```

- **Ingestion pipeline**: validate → attribute → deduplicate → redact → extract entities →
  classify trust → detect → build provenance → score risk → evaluate policy → findings/incidents →
  persist, audit, notify. Raw content and secrets never reach the database; only redacted previews,
  hashes and keyed fingerprints do.
- **Engines** (`backend/app/engines/`) are pure and database-free, so the security logic is unit
  tested in isolation. Services orchestrate and persist; routes stay thin.
- **Tenancy**: every organisation-owned query is scoped to the caller's organisation, and other
  organisations' ids answer 404.
- **Integrations** speak HTTP only and fail in a configurable mode (`closed`, `ask`, `open`) when
  the server is unreachable.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Quick start (local development)

Requirements: Python 3.12 (3.11+ works), Node.js 22.12+ with npm, `make`. Commands run from the
repository root unless a `cd` is shown.

```bash
make install PYTHON=python3.12     # backend/.venv with backend + SDK (+ dev, Postgres, MCP extras); npm ci in frontend/

cd backend
.venv/bin/contextos-server init-db                       # applies the Alembic migrations (SQLite: backend/data/contextos.db)
.venv/bin/contextos-server create-org --name "Acme AI" --email owner@example.com --name-of-owner "Ada Owner"
                                                         # prompts for the owner password (min 10 characters)
.venv/bin/contextos-server create-api-key --org-slug acme-ai --name "Claude Code laptop" --scopes ingest,decide,read
                                                         # prints a ctxk_… key once — keep it
.venv/bin/uvicorn app.main:app --reload --port 8000      # API on http://127.0.0.1:8000 (same as `make dev-backend`)
```

In a second terminal:

```bash
cd frontend && npm run dev                               # UI on http://localhost:5173 (proxies /api to :8000)
```

Sign in with the owner account. Instead of `create-org` you can open the UI on an empty database:
the login page offers **Create your organisation** (first run only). The organisation starts with
13 built-in policies and 21 default trust rules.

Optional:

```bash
cd backend && .venv/bin/contextos-server seed-demo --org-slug acme-ai   # runs the 9 Simulation Lab scenarios; every row is flagged simulated
make serve                                                              # build the SPA and serve API + UI from one process on :8000
```

The server warns that it is using the insecure development secret until you set
`CONTEXTOS_SECRET_KEY`. Production settings: [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md).

## Connect an agent: Claude Code in five minutes

With the server running and a key with `ingest,decide` (add `read` for the CLI data commands):

```bash
cd /path/to/your/project
/path/to/ContextOS/backend/.venv/bin/contextos init --url http://127.0.0.1:8000 --api-key ctxk_... --claude-code
/path/to/ContextOS/backend/.venv/bin/contextos doctor
```

`init` checks the server and the key's scopes, stores the key in `~/.contextos/config.json`
(mode 600), writes `.contextos/config.json` and merges the hooks into `.claude/settings.json`
(a backup is kept; `--scope local` or `--scope user` for other settings files). `doctor` should
report every check green and "enforcing via PreToolUse". Start `claude` in the project and trust the
folder: from now on every tool call is decided by ContextOS before it runs, and sessions, prompts
and tool results appear in the UI live. Try it on a destructive command — "Deny destructive shell
commands" answers `deny` and Claude Code does not run it.

The hook's default fail mode is `ask` (if ContextOS is unreachable, Claude Code's own permission
prompt decides). Full contract, configuration and a recorded live run:
[docs/integrations/claude-code.md](docs/integrations/claude-code.md).

OpenAI Codex: `contextos init --codex`, then trust the ContextOS hooks in Codex's `/hooks` — see
[docs/integrations/codex.md](docs/integrations/codex.md).

MCP servers: `contextos mcp-gateway --name <name> -- <server command>` — see
[docs/integrations/mcp.md](docs/integrations/mcp.md). Python agents: `@guard(...)` — see
[sdk/README.md](sdk/README.md).

## Configuration

Every server setting is a `CONTEXTOS_*` environment variable (`backend/app/core/config.py`). For
Docker Compose, copy [.env.example](.env.example) to `.env` and fill in the values marked REQUIRED;
never commit the real `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `CONTEXTOS_ENV` | `development` | `development`, `test` or `production`. Production refuses to start with the development secret, a secret shorter than 32 characters, or insecure cookies. |
| `CONTEXTOS_DATABASE_URL` | `sqlite:///./data/contextos.db` | SQLAlchemy URL; `postgresql+psycopg://…` in production. |
| `CONTEXTOS_SECRET_KEY` | insecure development value | **Required in production** (≥ 32 random characters, e.g. `openssl rand -hex 32`). Keys secret fingerprints, receipt signatures and the audit hash chain. |
| `CONTEXTOS_COOKIE_SECURE` | `false` | Send the session cookie over HTTPS only (must be `true` in production). |
| `CONTEXTOS_CORS_ORIGINS` | `["http://localhost:5173","http://127.0.0.1:5173"]` | Browser origins allowed to call the API. |
| `CONTEXTOS_SESSION_TTL_HOURS` / `CONTEXTOS_SESSION_COOKIE_NAME` | `12` / `contextos_session` | Browser session lifetime and cookie name. |
| `CONTEXTOS_LOG_LEVEL` / `CONTEXTOS_LOG_JSON` | `INFO` / `false` | Logging. |
| `CONTEXTOS_PREVIEW_CHARS`, `CONTEXTOS_MAX_EVENT_BYTES`, `CONTEXTOS_MAX_CONTENT_CHARS` | `600`, `512000`, `200000` | Content inspection limits. |
| `CONTEXTOS_RETENTION_DAYS` | `90` | Default retention for new organisations (`contextos-server purge` deletes expired data). |
| `CONTEXTOS_APPROVAL_DEFAULT_TIMEOUT_S` | `600` | How long an approval request waits. |
| `CONTEXTOS_WORKSPACE_REPO_ROOT` | unset | Repository the Engineering Workspace context-pack builder may read. |
| `CONTEXTOS_SERVE_FRONTEND` / `CONTEXTOS_FRONTEND_DIST` | `true` / unset | Serve the built SPA from the API process. |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `CONTEXTOS_PORT` | see `.env.example` | Docker Compose only. |

Integration-side variables (`CONTEXTOS_URL`, `CONTEXTOS_API_KEY`, `CONTEXTOS_FAIL_MODE`, …) belong on
the machine running the agent — see [docs/integrations/](docs/integrations/).

## Test, lint and build

```bash
make test          # backend (pytest), SDK (pytest) and frontend (Vitest) as three separate processes
make lint          # Ruff lint + format check (backend, SDK, scripts), ESLint, TypeScript type check
make format        # apply Ruff formatting to the Python code
make build         # production build of the SPA into frontend/dist
make smoke         # fresh database, real server process, real HTTP: ingest, deny, approval, isolation, redaction
```

The backend and SDK suites must run as separate pytest processes (both are packages named
`tests`). Set `CONTEXTOS_TEST_DATABASE_URL` to run the backend suite on PostgreSQL. CI
([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs lint, the migration check, all test
suites, the smoke run, the frontend build and a Docker image build on every push and pull request.
See [docs/TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md).

## Deployment

The [Dockerfile](Dockerfile) builds one image that serves the API and the SPA from a single
process (non-root user, health check on `/api/v1/health`). With PostgreSQL:

```bash
cp .env.example .env               # set POSTGRES_PASSWORD and CONTEXTOS_SECRET_KEY
docker compose up --build          # applies migrations on start; UI + API on http://127.0.0.1:8080
docker compose exec app contextos-server create-org --name "Acme AI" --email owner@example.com --name-of-owner "Ada"
```

Put it behind TLS for anything beyond a local trial, schedule `contextos-server purge` daily and
back up the database. Production settings, backups, retention and upgrades:
[docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md).

## Project structure

```
backend/                 FastAPI modular monolith (package contextos-server)
  app/api/routes/        thin HTTP layer under /api/v1
  app/services/          ingestion pipeline, persistence, audit, notifications
  app/engines/           pure logic: redaction, detection, trust, policy, risk, provenance
  app/models/            SQLAlchemy tables      app/events/   typed event envelope
  app/workspace/         Engineering Workspace logic (fix context, context packs)
  app/simulations/       Simulation Lab attack scenarios
  alembic/               database migrations
  tests/                 unit, integration, detection-corpus and end-to-end tests (real server process)
sdk/                     Python SDK, `contextos` CLI, Claude Code / Codex hooks, MCP gateway
frontend/                React + TypeScript SPA (features/<area>, components/ui, hooks)
examples/                runnable examples for each integration
scripts/                 whole-system smoke run and repository audit scripts
docs/                    product, architecture, security, API, data model and integration docs
```

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md): it lists the non-negotiable rules (no raw secrets at rest,
tenant isolation, server-side classification, honest enforcement wording) and the conventions every
change follows.

## Documentation

| Document | Contents |
|---|---|
| [CONTEXT.md](CONTEXT.md) | current milestone, what works, known problems, next steps |
| [docs/PRODUCT_VISION.md](docs/PRODUCT_VISION.md) · [docs/PROBLEM_AND_SOLUTION.md](docs/PROBLEM_AND_SOLUTION.md) | why ContextOS exists |
| [docs/PRODUCT_SPECIFICATION.md](docs/PRODUCT_SPECIFICATION.md) | what each dashboard area does today |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · [docs/ARCHITECTURE_DECISIONS.md](docs/ARCHITECTURE_DECISIONS.md) | modules, pipeline, enforcement model, ADRs |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) · [docs/API_SPECIFICATION.md](docs/API_SPECIFICATION.md) | tables and endpoints |
| [docs/INTEGRATION_SPECIFICATION.md](docs/INTEGRATION_SPECIFICATION.md) · [docs/integrations/](docs/integrations/) | event contract, adapters |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) · [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | security controls and threats |
| [docs/DETECTION_EVALUATION.md](docs/DETECTION_EVALUATION.md) | detection corpus, precision and recall |
| [docs/DEVELOPMENT_GUIDE.md](docs/DEVELOPMENT_GUIDE.md) · [docs/TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md) | contributing |
| [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | production settings, PostgreSQL, Docker, backups, retention |
| [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md) · [docs/ROADMAP.md](docs/ROADMAP.md) · [docs/PRODUCT_IMPROVEMENTS.md](docs/PRODUCT_IMPROVEMENTS.md) | release, plans, known gaps |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [docs/engineering/](docs/engineering/) | contribution rules, engineering guides and checklists |
