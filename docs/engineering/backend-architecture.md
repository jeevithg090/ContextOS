# Backend architecture (FastAPI modular monolith)

Applies to: `backend/app/**/*.py`

Layer rules (`docs/ARCHITECTURE.md` → "Layers and dependency rules"):

- `app/engines/<name>/` and `app/workspace/` are pure: stdlib, `app.domain`, `app.core.security`
  (HMAC) and other engines only. Never import SQLAlchemy sessions, models, FastAPI or `app.services`
  there. Inputs are dataclasses/specs, outputs are dataclasses; the public API is listed in the
  engine's `__init__.py` docstring — update that docstring when you add to it.
- `app/services/` does orchestration and persistence. It takes `db: Session` and `org_id: str`,
  never a FastAPI `Request`. Split a service by responsibility (`<area>_query.py`,
  `<area>_present.py`, …) once it nears ~500 lines.
- `app/api/routes/<area>.py` stays thin: parse input, call a service, `db.commit()`, return an
  `*Out` model. No business rules, no inline queries beyond trivial lookups.
- `app/schemas/<area>.py` holds Pydantic models: `*In` for bodies, `*Out` with
  `model_config = ORM` (from `app.schemas.common`). Schemas never import `app.models`.
- Register a new route module in `app/api/router.py`; models in `app/models/__init__.py`.

Conventions:

- Auth on every non-public route: `principal: Principal = Depends(require(Permission.X.value))`
  (`app.api.deps`). Pick the narrowest `Permission` from `app.domain.enums`; GET is `read`, a state
  change is never `read`. Browser-only endpoints use `require_user`.
- Lists return `Page[T]` (`items,total,limit,offset`) via `app.services.scoping.paginate`, with a
  bounded `limit: int = Query(50, ge=1, le=200)` and `offset: int = Query(0, ge=0)`.
- Register static paths (`/stats`, `/graph`) before `/{id}` paths in the same router.
- IDs: `new_id("<kind>")` from `app.core.ids`; add a new kind to `PREFIXES` (3-letter prefix).
- Timestamps: `app.core.timeutil.utcnow()`; never `datetime.now()` / `datetime.utcnow()`.
- Errors: raise `NotFoundError`, `ConflictError`, `ValidationFailedError`, `PermissionDeniedError`
  … from `app.core.errors`. Never return an ad-hoc error dict or raise `HTTPException`. Never
  `except Exception: pass`; log with `app.core.logging.get_logger` and re-raise or record it.
- Every state change, in the same transaction:
  `append_audit(db, org_id, action="<entity>.<verb>", actor_type=principal.actor_type,
  actor_id=principal.actor_id, target_type=..., target_id=..., details={ids and short metadata})`
  and `notify(db, org_id, "<entity>.<verb>", id=...)` (ids only; published after commit).
  A new notify type must also be added to `INVALIDATIONS` in `frontend/src/hooks/useLiveEvents.ts`.
- Cross-module contracts listed in `docs/ARCHITECTURE.md` ("Cross-module contracts") are stable:
  extend them, never change an existing signature.
- Integration events enter only through `app.services.ingestion.ingest_event` /
  `decide_tool_request`. Findings, policy decisions and provenance edges are created only by the
  pipeline and the services that own them (`record_finding`, `escalate_finding`, …) — never
  inline in a route or by a new ad-hoc writer.
