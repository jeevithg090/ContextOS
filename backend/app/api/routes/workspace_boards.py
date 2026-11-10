"""Kanban boards and columns."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/workspace/boards", tags=["workspace"])
