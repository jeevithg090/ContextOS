# Deployment guide

How to run ContextOS for real users: production settings, PostgreSQL, migrations, the Docker
files, serving the web UI, backups, retention and upgrades. Local development is in
[DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md); the security controls are in
[SECURITY_MODEL.md](SECURITY_MODEL.md).

## What you deploy

One process (`contextos-server serve`, i.e. uvicorn running `app.main:app`) that serves the API
under `/api/v1`, the SSE stream and — when `CONTEXTOS_SERVE_FRONTEND=true` and a built
`frontend/dist` exists — the web UI from the same origin. Plus one database (PostgreSQL in
production). Run **one replica**: live updates (`GET /stream`) and the sign-in rate limiter are
in-process ([ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md#adr-004-in-process-event-bus-with-ids-only-notifications)).
Put it behind a TLS-terminating reverse proxy.

## Production settings

Every setting is an environment variable (or `.env` in the working directory) read by
`backend/app/core/config.py`. `.env.example` at the repository root lists them with comments.

| Variable | Default | Production |
|---|---|---|
| `CONTEXTOS_ENV` | `development` | `production` |
| `CONTEXTOS_SECRET_KEY` | insecure development value | **required**: ≥ 32 random characters (`openssl rand -hex 32`). Keys secret fingerprints, Context Receipt signatures and the audit chain — back it up; rotating it invalidates all three |
| `CONTEXTOS_DATABASE_URL` | `sqlite:///./data/contextos.db` | `postgresql+psycopg://user:password@host:5432/contextos` |
| `CONTEXTOS_COOKIE_SECURE` | `false` | `true` (session cookie over HTTPS only) |
| `CONTEXTOS_CORS_ORIGINS` | `["http://localhost:5173","http://127.0.0.1:5173"]` | not needed when the UI is served by the API (same origin); otherwise the UI's origin as a JSON list |
| `CONTEXTOS_SESSION_TTL_HOURS` | `12` | browser session lifetime |
| `CONTEXTOS_LOG_LEVEL`, `CONTEXTOS_LOG_JSON` | `INFO`, `false` | `INFO`, `true` (logs carry ids, never content, arguments or tokens) |
| `CONTEXTOS_PREVIEW_CHARS` | `600` | length of stored redacted previews |
| `CONTEXTOS_MAX_EVENT_BYTES` | `512000` | per-event limit on `/events` and `/decide` (bodies over 4× are refused before auth) |
| `CONTEXTOS_MAX_CONTENT_CHARS` | `200000` | content inspected per event |
| `CONTEXTOS_RETENTION_DAYS` | `90` | default retention for new organisations (each can change it in Settings → Data & privacy) |
| `CONTEXTOS_APPROVAL_DEFAULT_TIMEOUT_S` | `600` | approval expiry for new organisations |
| `CONTEXTOS_WORKSPACE_REPO_ROOT` | unset | optional repository working copy the context-pack builder may read |
| `CONTEXTOS_SERVE_FRONTEND`, `CONTEXTOS_FRONTEND_DIST` | `true`, `frontend/dist` next to `backend/` | serve the built SPA from the API process |

**Validation**: with `CONTEXTOS_ENV=production` the server refuses to start when the secret is the
development value or shorter than 32 characters, or when `CONTEXTOS_COOKIE_SECURE` is not true
(`Settings.validate_for_production`). It also refuses to start on a database that is not at the
latest migration. Outside production, `serve` prints a warning while the development secret is in
use.

## Install without Docker

```bash
python3.12 -m venv /opt/contextos/venv
/opt/contextos/venv/bin/pip install --editable "./backend[postgres]"   # from a checkout of this repository
cd frontend && npm ci && npm run build                                 # produces frontend/dist
```

Install **editable**, as the Dockerfile does: the server locates `alembic.ini` and the migrations
relative to `backend/app` (`app/database/migrations.py`), so it must run from the source tree. The
default `CONTEXTOS_FRONTEND_DIST` is `frontend/dist` next to `backend/`; set it when the build lives
elsewhere. Put `/opt/contextos/venv/bin` on `PATH` (or call the scripts by full path).

```bash
cd backend
export CONTEXTOS_ENV=production CONTEXTOS_SECRET_KEY=... CONTEXTOS_COOKIE_SECURE=true \
       CONTEXTOS_DATABASE_URL=postgresql+psycopg://contextos:...@db.internal:5432/contextos
contextos-server init-db
contextos-server create-org --name "Acme AI" --email owner@example.com --name-of-owner "Ada Owner"
contextos-server serve --host 127.0.0.1 --port 8000
```

`create-org` is optional: on an empty database the web UI's login page offers the first-run setup.
Create integration keys in Settings → API keys or with
`contextos-server create-api-key --org-slug acme-ai --name "<machine>" --scopes ingest,decide`.

## PostgreSQL

- Driver: `psycopg` 3 (the `postgres` extra), URL scheme `postgresql+psycopg://`. JSON columns use
  `JSONB`.
- Verified on 2026-11-11 against PostgreSQL 17.11 (scratch instance): `init-db`, `create-org`,
  `seed-demo`, `purge --dry-run`, `alembic downgrade base && alembic upgrade head`, and the full
  backend suite as it stood then (1676 passed with `CONTEXTOS_TEST_DATABASE_URL`).
- The compose file uses `postgres:17-alpine`.

## Migrations

The schema is owned by Alembic (`backend/alembic/versions/`). Run `contextos-server init-db` before
starting a new version; it upgrades to the latest revision and reports what it did (`upgraded`,
`unchanged`, or `adopted` for a database created without migrations that matches the models). The
API refuses to start until the database is current and names the command to run.

## Docker

The repository contains a `Dockerfile` and `docker-compose.yml`. **They have not been built or run
yet** — Docker was not available on the build machine — so treat them as a starting point and
verify them in your environment.

- `Dockerfile`: stage 1 builds the SPA with `node:22-bookworm-slim` (`npm ci`, `npm run build`);
  stage 2 is `python:3.12-slim` with the backend installed (`pip install --editable ".[postgres]"`),
  the migrations, and the built SPA at `/app/frontend/dist`. It runs as the non-root user
  `contextos`, exposes port 8000, declares `VOLUME /app/data`, has a `HEALTHCHECK` on
  `/api/v1/health`, and sets `CONTEXTOS_ENV=production`, `CONTEXTOS_COOKIE_SECURE=true`,
  `CONTEXTOS_SERVE_FRONTEND=true`, `CONTEXTOS_LOG_JSON=true` and a SQLite default of
  `sqlite:////app/data/contextos.db`. You must supply `CONTEXTOS_SECRET_KEY`.
- `docker-compose.yml`: `db` (PostgreSQL 17 with a health check and the `pgdata` volume) and `app`
  (built from the Dockerfile, `env_file: .env`, `CONTEXTOS_DATABASE_URL` assembled from the
  `POSTGRES_*` values, runs `contextos-server init-db` and then `serve` on every start, published on
  `127.0.0.1:${CONTEXTOS_PORT:-8080}`).

Intended use:

```bash
cp .env.example .env            # set POSTGRES_PASSWORD (URL-safe) and CONTEXTOS_SECRET_KEY
docker compose up --build
docker compose exec app contextos-server create-org --name "Acme AI" --email owner@example.com --name-of-owner "Ada"
```

`.dockerignore` keeps `.git`, `.env` files, local databases, `node_modules`, tests, docs, the SDK
and examples out of the build context.

## Serving the web UI

With `CONTEXTOS_SERVE_FRONTEND=true` and a built `dist`, the API mounts `/assets` and returns
`index.html` for every other non-API path (client-side routing); `/api/*` paths that do not exist
answer a JSON 404. The UI then calls the API on the same origin, so no CORS entry is needed. If you
host the SPA elsewhere, add its origin to `CONTEXTOS_CORS_ORIGINS` and keep cookies `Secure`.

Reverse proxy notes: terminate TLS; pass `Host` and the client address; do not buffer
`/api/v1/stream` (the server sends `X-Accel-Buffering: no` and a ping every 15 s; allow long-lived
connections). Responses carry `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
`X-Frame-Options: DENY`.

Health: `GET /api/v1/health` (liveness) and `GET /api/v1/ready` (also queries the database).

## Backups

- **Database**: PostgreSQL with `pg_dump`/your managed backups; SQLite with an online copy
  (`sqlite3 contextos.db ".backup backup.db"`; the database runs in WAL mode, so copy with
  `.backup` rather than `cp`).
- **`CONTEXTOS_SECRET_KEY`**: store it in your secret manager. Without it you cannot verify the audit
  chain, Context Receipts or match secret fingerprints after a restore.
- **Audit head**: periodically record the chain head (`head_seq`, `head_hash` from
  `GET /api/v1/audit/verify`, or the full `GET /api/v1/audit/export`) in write-once storage. This is
  what detects an attacker who has both the database and the secret rewriting history.

## Retention

Recorded event data is deleted by `contextos-server purge`, not by the server process. Schedule it
daily:

```bash
contextos-server purge --dry-run          # counts per table, deletes nothing
contextos-server purge                    # every organisation; --org-slug to limit; --json for scripts
docker compose exec app contextos-server purge
```

It uses each organisation's `retention_days` and server timestamps, keeps evidence of open
incidents, never deletes audit entries, and writes a `retention.purged` audit entry. What is and is
not deleted: [DATA_MODEL.md](DATA_MODEL.md#retention).

## Upgrading

1. Back up the database (and confirm you have the secret key).
2. Update the checkout (or image) and reinstall: `pip install --editable "./backend[postgres]"`;
   rebuild the SPA (`npm ci && npm run build`).
3. `contextos-server init-db` (applies new migrations; with compose it runs on start).
4. Restart the server and check `GET /api/v1/ready` and Audit Log → Verify.
5. Update integrations on agent machines (`pip install` of the `sdk` package) and run
   `contextos doctor`; the hooks installed by `contextos init --claude-code` call the interpreter
   that installed them.
