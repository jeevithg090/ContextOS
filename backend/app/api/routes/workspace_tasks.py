"""Tasks, comments, dependencies, links, fix attempts, verification."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/workspace/tasks", tags=["workspace"])
