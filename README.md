# ContextOS

ContextOS is a security, trust, provenance and observability layer for autonomous AI agents. It
records what context your agents consume and where it came from, classifies how far each source
can be trusted, detects prompt injection and credential exfiltration, decides tool calls against
policy *before they run* where the agent host allows it, and gives you the records to investigate
what happened. An Engineering Workspace turns the findings into tracked fixes.

It runs as one server (FastAPI + SQLite or PostgreSQL) with a web UI, and connects to agents
through Claude Code hooks, OpenAI Codex hooks, an MCP security gateway and a Python SDK.

## The six pillars

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

## Quick start (local development)

Requirements: Python 3.12 (3.11+ works), Node.js 22 with npm, `make`. Commands run from the
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

## Claude Code in five minutes

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

## Tests

```bash
make test        # backend (pytest), SDK (pytest) and frontend (Vitest) as three separate processes
make lint        # ruff, ESLint and the TypeScript type check
```

The backend and SDK suites must run as separate pytest processes (both are packages named
`tests`). See [docs/TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md).

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
| [CLAUDE.md](CLAUDE.md) · [AGENTS.md](AGENTS.md) | rules for coding agents working on this repository |
