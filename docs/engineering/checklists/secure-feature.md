# Secure feature, end to end

> Build a new ContextOS feature or endpoint end to end the secure way — model, migration, scoped service with redaction, audit and live notifications, permissioned route, schemas, frontend api.ts hooks and page states, and tests including org isolation and adversarial cases. Use whenever you add or extend a backend resource, an API route, a dashboard view backed by new data, or any code path that stores agent-derived content.

Work top-down through the steps; tick the checklist at the end before saying you are done.
Read first: `docs/ARCHITECTURE.md`, `docs/engineering/backend-architecture.md`,
`docs/engineering/security-engineering.md`, and the existing feature closest to yours (e.g.
`backend/app/services/findings.py` + `api/routes/findings.py` + `frontend/src/features/intelligence/`).

## 1. Threat sketch (5 minutes, write it down)
Answer: what agent-derived or secret data does it touch? Who may read / change it (which
`Permission`)? Which ids can a caller supply (each must be org-scoped)? Is anything presented as
enforced, causal or historical? For anything non-trivial follow the [threat-model](threat-model.md) checklist.

## 2. Model (`backend/app/models/<area>.py`)
```python
class Widget(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "widgets"
    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(200))
    content_redacted: Mapped[str | None] = mapped_column(Text, default=None)  # never raw content
    content_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)            # JSONType via annotation
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)       # if Simulation Lab can create it
```
Add `"widget": "wdg"` to `PREFIXES` in `backend/app/core/ids.py`; export the model from
`backend/app/models/__init__.py`.

## 3. Migration (`backend/alembic/versions/`)
Autogenerate against a scratch DB and fix the output as `docs/engineering/database-migrations.md`
describes (imports for `UTCDateTime`, `sa.Text()` in JSONB, batch ops, real `downgrade`). Verify with
the round trip in `docs/engineering/checklists/test-and-verify.md` §3. If migrations are owned by another
work package in the current wave, put the exact model diff under "requests" instead.

## 4. Pure logic (only if there are rules/decisions)
Put classification/scoring/transform logic in `backend/app/engines/<engine>/` or
`backend/app/workspace/` as functions over dataclasses — no DB, no FastAPI. Document the new public
function in that package's `__init__.py` docstring.

## 5. Service (`backend/app/services/<area>.py`)
```python
def create_widget(db: Session, org_id: str, *, actor_type: str, actor_id: str | None,
                  name: str, content: str, board_id: str | None) -> Widget:
    if board_id:
        get_scoped(db, Board, board_id, org_id, label="Board")       # foreign id → 404, never 403
    redacted = redact_text(content)                                    # before ANY persistence
    widget = Widget(id=new_id("widget"), organization_id=org_id, name=name.strip()[:200],
                    content_redacted=redacted.text, content_sha256=sha256_hex(content))
    db.add(widget)
    db.flush()
    append_audit(db, org_id, action="widget.created", actor_type=actor_type, actor_id=actor_id,
                 target_type="widget", target_id=widget.id, details={"board_id": board_id})
    notify(db, org_id, "widget.updated", id=widget.id)                 # ids only; sent after commit
    return widget
```
Rules: reads use `scoped(Widget, org_id)` / `get_scoped(...)`; errors are `app.core.errors` types
(`ConflictError` for invalid state transitions, `ValidationFailedError` for semantic validation);
check `RedactionResult` fields in `backend/app/engines/redaction/engine.py`; never log `content`.

## 6. Schemas (`backend/app/schemas/<area>.py`)
- `WidgetCreateIn(BaseModel)` with `model_config = ConfigDict(extra="forbid")`, bounded strings
  (`Field(max_length=…)`), enums from `app.domain.enums`. No trust/risk/decision/enforcement input fields.
- `WidgetOut(BaseModel)` with `model_config = ORM`; expose redacted fields only.

## 7. Route (`backend/app/api/routes/<area>.py`)
```python
router = APIRouter(prefix="/widgets", tags=["widgets"])
READ = Depends(require(Permission.READ.value))
WRITE = Depends(require(Permission.WRITE.value))

@router.get("", response_model=Page[WidgetOut])
def list_widgets(principal: Principal = READ, db: Session = Depends(get_db),
                 limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> Page[WidgetOut]:
    items, total = paginate(db, scoped(Widget, principal.org_id).order_by(Widget.created_at.desc()),
                            limit=limit, offset=offset)
    return Page[WidgetOut].model_validate({"items": items, "total": total, "limit": limit, "offset": offset})

@router.post("", response_model=WidgetOut, status_code=201)
def create(body: WidgetCreateIn, principal: Principal = WRITE, db: Session = Depends(get_db)) -> WidgetOut:
    widget = widgets.create_widget(db, principal.org_id, actor_type=principal.actor_type,
                                   actor_id=principal.actor_id, **body.model_dump())
    db.commit()
    return WidgetOut.model_validate(widget)
```
Static paths before `/{widget_id}`. Register the module in `backend/app/api/router.py`.

## 8. Live updates
Add `"widget.updated": [["widgets"], …]` to `INVALIDATIONS` in `frontend/src/hooks/useLiveEvents.ts`.

## 9. Frontend (`frontend/src/features/<feature>/`)
- `types.ts`: mirror `WidgetOut` exactly. `api.ts`: header comment listing routes; `useWidgets`,
  `useCreateWidget` with keys `["widgets", …]`; mutations invalidate affected keys; no retry on 404.
- Page: `PageHeader`; loading `LoadingRows`; `ErrorState onRetry`; `EmptyState` that says how data
  appears; badges from `@/components/ui`; `RedactedText` for redacted values; `SimulationBadge` for
  simulated rows; semantic tokens only. Wire the route in `src/app/routes.tsx` and `src/app/nav.ts`.
- Every button does something real or is not rendered; permission-gated actions are hidden or
  disabled with a reason: `useAuth().can("write")` from `features/auth/AuthProvider.tsx`. The
  server still enforces the permission; the UI check is only for clarity.

## 10. Tests
Backend `backend/tests/integration/test_<area>_api.py` (use `client`, `org`/`seeded_org`, `other_org`, `make_org`):
- happy path (+ audit row and notification: monkeypatch `bus.publish` from `app.events.bus` as
  `tests/integration/test_ingestion_redaction.py` does);
- 422 on unknown/oversized fields; 401 without credentials; 403 for `make_org("V", role="viewer")`
  on writes and for an `ingest`-only API key on reads;
- isolation: `other_org` gets 404 on every id route, sees nothing in lists/stats, and a foreign id
  in the body (e.g. `board_id`) is 404;
- adversarial: canary secret in `content` never appears in any column, audit `details`, response
  or notification; obfuscated variants; boundary sizes;
- unit tests for any engine logic in `backend/tests/unit/`.
Frontend `src/features/<feature>/__tests__/`: render loading/error/empty/data states; mutation
invalidation; no raw colour classes.

## 11. Docs
Update the API/data docs listed in `CONTRIBUTING.md` for the new routes and table, and `CONTEXT.md`
(what works, limitations). Run `backend/.venv/bin/python scripts/audit/doc_paths.py`.

## 12. Verify and report
Follow the [test-and-verify](test-and-verify.md) checklist (targeted, then full backend suite; ruff; tsc/eslint/vitest) and
`backend/.venv/bin/python scripts/audit/route_audit.py --tests tests/integration/test_<area>_api.py`
— your new routes must not appear under "never requested in an other_org test".

## Checklist
- [ ] Model org-scoped, prefixed id, `UTCDateTime`/JSON via annotations, no raw content column
- [ ] Alembic revision (or request filed) and round trip verified
- [ ] Every query `scoped`/`get_scoped`; foreign ids → 404
- [ ] Redaction before DB/log/audit/notify/export; hashes or fingerprints instead of secrets
- [ ] `require(Permission.…)` with the narrowest permission; no `read` on state changes
- [ ] `append_audit` + `notify` on every state change; INVALIDATIONS updated
- [ ] `*In` forbid extras; `*Out` ORM; lists are `Page[T]`
- [ ] Frontend api.ts hooks, loading/error/empty states, badges, tokens, no dead buttons
- [ ] Tests: happy, validation, permissions, isolation, adversarial/redaction, frontend states
- [ ] Docs + `CONTEXT.md` updated; all suites green with counts reported
