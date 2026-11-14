# ContextOS developer tasks. Run `make help` for the list.
#
# Test layout: backend/tests and sdk/tests are BOTH Python packages named `tests` (many backend tests
# import `tests.integration.*`). A single pytest process cannot collect both — the second `tests`
# package resolves to the first and collection fails with "No module named 'tests.test_...'". The
# suites therefore always run as separate pytest processes, each from its own directory
# (`make test-backend`, `make test-sdk`); never point one pytest run at both directories.

SHELL := /bin/sh
.DEFAULT_GOAL := help

PYTHON ?= python3
VENV := backend/.venv
PY := $(abspath $(VENV))/bin/python
HOST ?= 127.0.0.1
PORT ?= 8000
PYTEST_FLAGS ?= -q -p no:cacheprovider

.PHONY: help install dev-backend dev-frontend migrate test test-backend test-sdk test-frontend lint \
	lint-backend lint-frontend typecheck build serve format test-scripts smoke

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "  Backend and SDK tests run as separate pytest processes (both suites are packages named"
	@echo "  'tests' and cannot be collected together). Variables: HOST=$(HOST) PORT=$(PORT)."

install: ## Create backend/.venv (backend + SDK, dev and Postgres extras) and install frontend packages
	test -x $(PY) || $(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e "backend[dev,postgres]" -e "sdk[mcp]"
	cd frontend && npm ci

dev-backend: ## Run the API with auto-reload (frontend dev server proxies /api here)
	cd backend && $(PY) -m uvicorn app.main:app --reload --host $(HOST) --port $(PORT)

dev-frontend: ## Run the Vite dev server (proxies /api to 127.0.0.1:8000)
	cd frontend && npm run dev

migrate: ## Apply database migrations (CONTEXTOS_DATABASE_URL, default backend/data/contextos.db)
	cd backend && $(PY) -m app.cli init-db

test: test-backend test-sdk test-frontend ## Run backend, SDK and frontend tests (three separate processes)

test-backend: ## Backend tests (SQLite; set CONTEXTOS_TEST_DATABASE_URL to run them on PostgreSQL)
	cd backend && $(PY) -m pytest $(PYTEST_FLAGS) tests

test-sdk: ## SDK, CLI and integration-adapter tests
	cd sdk && $(PY) -m pytest $(PYTEST_FLAGS) tests

test-frontend: ## Frontend unit tests (Vitest)
	cd frontend && npx vitest run

lint: lint-backend lint-frontend typecheck ## Ruff, ESLint and the TypeScript type check

lint-backend: ## Ruff lint and format check (backend, SDK, scripts)
	cd backend && $(PY) -m ruff check app tests && $(PY) -m ruff format --check app tests alembic
	cd sdk && $(PY) -m ruff check . && $(PY) -m ruff format --check .
	$(PY) -m ruff check --config backend/pyproject.toml scripts && $(PY) -m ruff format --config backend/pyproject.toml --check scripts

format: ## Apply ruff format to the Python code
	cd backend && $(PY) -m ruff format app tests alembic
	cd sdk && $(PY) -m ruff format .
	$(PY) -m ruff format --config backend/pyproject.toml scripts

test-scripts: ## Tests for the smoke and audit scripts
	$(PY) -m pytest $(PYTEST_FLAGS) scripts

smoke: ## Whole-system smoke run: fresh database, real server process, real HTTP
	$(PY) scripts/smoke.py

lint-frontend: ## ESLint
	cd frontend && npx eslint src

typecheck: ## TypeScript type check
	cd frontend && npx tsc -b --noEmit

build: ## Production build of the frontend (frontend/dist, served by the API)
	cd frontend && npm run build

serve: build ## Build the frontend, apply migrations and serve API + SPA from one process
	cd backend && $(PY) -m app.cli init-db
	cd backend && CONTEXTOS_SERVE_FRONTEND=true $(PY) -m app.cli serve --host $(HOST) --port $(PORT)
