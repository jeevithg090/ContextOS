---
paths:
  - "docs/**/*.md"
  - "*.md"
  - "sdk/README.md"
  - "examples/**/*.md"
  - ".claude/**/*.md"
---

# Documentation

- Docs describe what the code does today. Before writing a claim, find the code that implements
  it (route, service, engine, test) and use its exact names, paths, commands, field names and enum
  values. If something is planned or partial, say so under a "Limitations" heading — never as if
  it ships.
- Source-of-truth order: `CLAUDE.md` (rules for every agent) → `CONTEXT.md` (current state) →
  `docs/ARCHITECTURE.md` → area docs (`docs/integrations/*.md`, and the data/API/security docs
  listed in `CLAUDE.md`). `AGENTS.md` only points at these; never fork rules into it.
- Use the honest vocabulary: `enforced` / `advisory` / `observed`; provenance edges are "observed
  relationships"; replay counterfactuals are "simulations"; Simulation Lab output is "simulated".
- Examples use reserved names only: `example.com`/`.test`/`.invalid`, `ctxk_...` placeholders,
  canary strings — never a real-looking key or a real customer/domain.
- Every command in a doc must run as written from the stated directory (backend commands use
  `.venv/bin/...` from `backend/`). Re-run the commands you add or change.
- After significant work (a feature, an integration, a security fix, a schema change) update
  `CONTEXT.md`: what works, what changed, known problems, next steps. Update the area doc in the
  same change as the behaviour change.
- Check that referenced paths exist:
  `backend/.venv/bin/python .claude/skills/repo-audit/scripts/doc_paths.py`.
- Keep `CLAUDE.md` short (it is loaded into every session); put path-specific guidance in
  `.claude/rules/*.md` and procedures in `.claude/skills/<name>/SKILL.md`.
