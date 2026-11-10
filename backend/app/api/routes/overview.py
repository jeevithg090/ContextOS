"""Security command centre aggregates (from persisted data only)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/overview", tags=["overview"])
