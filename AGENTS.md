# ContextOS — instructions for Codex and other coding agents

**`CLAUDE.md` is the source of truth for every coding agent** (not only Claude Code): what
ContextOS is, the repository layout, commands, the ten non-negotiable rules and the conventions.
Read it first. This file only tells you where everything is, so the two never diverge — if
anything here conflicts with `CLAUDE.md`, `CLAUDE.md` wins and this file must be fixed.

## Read, in this order
1. `CLAUDE.md` — rules and conventions.
2. `CONTEXT.md` — current milestone, what works, known problems, next steps.
3. `docs/ARCHITECTURE.md` — layers and dependency rules, ingestion pipeline, enforcement model,
   stable cross-module contracts.
4. The security and area docs listed in `CLAUDE.md` before touching auth, redaction, audit,
   integrations or anything that handles agent data; `docs/integrations/*.md` for adapters.
   If a listed doc does not exist yet, the module docstrings and tests are authoritative.

## Path-scoped rules (apply them yourself)
Claude Code loads `.claude/rules/*.md` automatically by path; other agents should open the file
whose `paths:` frontmatter matches what they edit:

| Editing | Rule file |
|---|---|
| `backend/app/**` | `.claude/rules/backend-architecture.md`, `.claude/rules/security-engineering.md` |
| `backend/app/models/**`, `backend/alembic/**` | `.claude/rules/database-migrations.md` |
| `frontend/src/**` | `.claude/rules/frontend-architecture.md`, `.claude/rules/security-engineering.md` |
| `sdk/**`, `examples/**`, ingestion / event contract | `.claude/rules/integration-adapters.md` |
| any tests | `.claude/rules/testing.md` |
| `docs/**`, `*.md` | `.claude/rules/documentation.md` |

## Procedures
`.claude/skills/<name>/SKILL.md` are plain-Markdown checklists any agent can follow:
`secure-feature` (new feature/endpoint end to end), `integration-builder` (agent-framework
adapters), `test-and-verify` (which suites to run and how to read failures), `code-review`,
`architecture-review`, `threat-model`, `repo-audit`, `release-readiness` (Definition of Done).
Helper scripts (run from the repository root):

```bash
backend/.venv/bin/python .claude/skills/repo-audit/scripts/route_audit.py      # auth + org-isolation coverage of every route
backend/.venv/bin/python .claude/skills/repo-audit/scripts/doc_paths.py        # docs that reference missing files
backend/.venv/bin/python .claude/skills/release-readiness/scripts/smoke.py     # fresh DB + real server + real HTTP
```

## Quick commands
```bash
cd backend && .venv/bin/python -m pytest -q                   # backend tests
cd sdk && ../backend/.venv/bin/python -m pytest -q tests      # SDK, CLI and integration tests
cd backend && .venv/bin/ruff check app tests                  # backend lint
cd frontend && npm run typecheck && npm run lint && npm test && npm run build
```

After significant work, update `CONTEXT.md` as `CLAUDE.md` describes.
