# ContextOS — instructions for Codex and other coding agents

The authoritative project instructions live in **`CLAUDE.md`** (they apply to every coding agent,
not only Claude Code). Read it first; this file only adds pointers so the two never diverge.

1. `CLAUDE.md` — what ContextOS is, layout, commands, non-negotiable security rules, conventions.
2. `CONTEXT.md` — current milestone, what works, known problems, next steps.
3. `docs/ARCHITECTURE.md` — layers, ingestion pipeline, enforcement model, cross-module contracts.
4. `docs/SECURITY_MODEL.md` and `docs/THREAT_MODEL.md` — before touching auth, redaction, audit,
   integrations or anything that handles agent data.
5. The doc for your area: `docs/DATA_MODEL.md`, `docs/API_SPECIFICATION.md`,
   `docs/INTEGRATION_SPECIFICATION.md`, `docs/TESTING_STRATEGY.md`.

Quick commands:

```bash
cd backend && .venv/bin/python -m pytest -q          # backend + SDK tests
cd frontend && npm run typecheck && npm run build    # frontend
```

If an instruction here ever conflicts with `CLAUDE.md`, `CLAUDE.md` wins — fix this file.
