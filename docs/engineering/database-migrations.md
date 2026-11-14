# Database models and migrations (SQLite for dev/tests, PostgreSQL in production)

Applies to: `backend/app/models/**`, `backend/app/database/**`, `backend/alembic/**`, `backend/alembic.ini`

Models (`backend/app/models/`)
- Tenant-owned tables mix in `OrgScopedMixin` (indexed `organization_id`, `ON DELETE CASCADE`) and
  usually `TimestampMixin`; primary key `id: Mapped[str] = id_column()` filled with `new_id("<kind>")`.
- Datetimes: annotate `Mapped[datetime]` (maps to `UTCDateTime`) — never a bare
  `DateTime()` column; SQLite drops tzinfo otherwise.
- JSON: annotate `Mapped[dict[str, Any]]` / `Mapped[list[Any]]` (maps to `JSONType` = JSON, JSONB on
  PostgreSQL). Mutating a JSON value in place is not tracked — assign a new dict/list.
- Uniqueness that is per tenant includes `organization_id` (e.g. `(organization_id, client_event_id)`).
- Name constraints through `Base.metadata` naming conventions (`app/database/base.py`); do not
  hand-name indexes unless a migration needs a stable name.
- Rows produced by the Simulation Lab carry `is_simulation=True` where the table has the flag.
- Never add a column that stores raw context content, raw tool arguments or secrets — store
  redacted values, hashes (`sha256_hex`) or fingerprints (`fingerprint_secret`).
- Export every new model from `app/models/__init__.py` (Alembic and tests rely on it).

Migrations (`backend/alembic/versions/`)
- Every schema change ships an Alembic revision in the same change. `Base.metadata.create_all`
  is only for test fixtures (`tests/conftest.py`); real databases are created by migrations.
- Generate against a scratch database, never `backend/data/contextos.db`:
  `cd backend && S=$(mktemp -d) && export CONTEXTOS_DATABASE_URL=sqlite:///$S/m.db && .venv/bin/alembic upgrade head && .venv/bin/alembic revision --autogenerate --rev-id 0002_<slug> -m "<what changed>"`
  (next number after the current head; one linear chain — a single head), then read and fix the file.
- SQLite needs batch mode for ALTER: keep `op.batch_alter_table(...)` blocks
  (`alembic/env.py` sets `render_as_batch` for SQLite). Name every constraint you create.
- Revisions never import application code (models change; history must not). Fix autogenerate
  output before committing: it renders `app.database.base.UTCDateTime(timezone=True)` → write
  `sa.DateTime(timezone=True)`; it renders `postgresql.JSONB(astext_type=Text())` with `Text`
  unimported → use the module-level
  `JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")`
  as `backend/alembic/versions/0001_initial_schema.py` does.
- The app refuses to start on a database behind the latest revision
  (`app.database.migrations.ensure_schema_ready`, run in the lifespan); `contextos-server init-db`
  upgrades. `backend/tests/integration/test_migrations.py` checks that a fresh upgrade matches the
  models and round-trips — keep it green.
- Write a real `downgrade()`. Backfill data in the revision when a new NOT NULL column needs it
  (`server_default` or an `op.execute` update), then tighten.
- Verify before finishing (fresh scratch DB): `alembic upgrade head`, `alembic check` ("No new
  upgrade operations detected"), `alembic downgrade base && alembic upgrade head` — the exact
  command is in `docs/engineering/checklists/test-and-verify.md` §3. For PostgreSQL-specific behaviour also
  run against a scratch Postgres (`initdb` + `pg_ctl -o "-p <18000-18999>"`, URL
  `postgresql+psycopg://…`) and stop it afterwards.
- Add a test for the behaviour the schema change enables, plus an isolation test if the table is
  org-owned (see `docs/engineering/testing.md`).
