"""Organisation settings, members, roles and API keys."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/org", tags=["organisation"])
