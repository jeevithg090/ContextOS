"""Tenant-scoped query helpers. Use these instead of raw ``db.get`` for org-owned rows."""

from __future__ import annotations

from typing import Any, TypeVar

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError

T = TypeVar("T")


def scoped(model: type[T], org_id: str) -> Select[tuple[T]]:
    """``select(model)`` filtered to one organisation."""
    return select(model).where(model.organization_id == org_id)  # type: ignore[attr-defined]


def get_scoped(db: Session, model: type[T], obj_id: str, org_id: str, *, label: str | None = None) -> T:
    """Fetch by id within the organisation or raise 404 (never 403 — do not leak existence)."""
    obj = db.scalar(scoped(model, org_id).where(model.id == obj_id))  # type: ignore[attr-defined]
    if obj is None:
        raise NotFoundError(f"{label or model.__name__} '{obj_id}' not found")
    return obj


def find_scoped(db: Session, model: type[T], obj_id: str | None, org_id: str) -> T | None:
    if not obj_id:
        return None
    return db.scalar(scoped(model, org_id).where(model.id == obj_id))  # type: ignore[attr-defined]


def paginate(db: Session, query: Select[Any], *, limit: int, offset: int) -> tuple[list[Any], int]:
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    items = list(db.scalars(query.limit(limit).offset(offset)))
    return items, int(total)
