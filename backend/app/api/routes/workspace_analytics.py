"""Engineering analytics from task records."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/workspace/analytics", tags=["workspace"])
