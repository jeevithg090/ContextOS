"""Agent sessions and their timelines."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/sessions", tags=["sessions"])
