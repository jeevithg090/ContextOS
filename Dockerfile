# syntax=docker/dockerfile:1
#
# ContextOS: one image serving the API (/api/v1) and the built React SPA from a single process.
#
#   docker build -t contextos .
#   docker run --env-file .env -p 127.0.0.1:8080:8000 contextos     # see docker-compose.yml for Postgres
#
# The schema is owned by Alembic: run `contextos-server init-db` before (or as part of) starting the
# server — the API refuses to start on an un-migrated database. docker-compose.yml does this on start.

# ---------------------------------------------------------------------------- frontend build
FROM node:22-bookworm-slim AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------- runtime
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system contextos \
    && useradd --system --gid contextos --home-dir /app --no-create-home --shell /usr/sbin/nologin contextos

WORKDIR /app/backend
# The server runs from its source tree: app/ plus alembic/ and alembic.ini (the migrations ship with it).
COPY backend/pyproject.toml backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/app ./app
RUN pip install --editable ".[postgres]" \
    && mkdir -p /app/data \
    && chown contextos:contextos /app/data

COPY --from=frontend /src/frontend/dist /app/frontend/dist

# Production defaults. Supply CONTEXTOS_SECRET_KEY (>= 32 random characters) and a database URL at run
# time; production refuses to start with the development secret or without CONTEXTOS_COOKIE_SECURE=true.
ENV CONTEXTOS_ENV=production \
    CONTEXTOS_COOKIE_SECURE=true \
    CONTEXTOS_SERVE_FRONTEND=true \
    CONTEXTOS_FRONTEND_DIST=/app/frontend/dist \
    CONTEXTOS_DATABASE_URL=sqlite:////app/data/contextos.db \
    CONTEXTOS_LOG_JSON=true

USER contextos
VOLUME ["/app/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; r = urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4); sys.exit(0 if r.status == 200 else 1)"]

CMD ["contextos-server", "serve", "--host", "0.0.0.0", "--port", "8000"]
