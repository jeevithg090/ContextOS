"""Login, logout, current user, first-run bootstrap."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])
