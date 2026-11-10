"""Fix-context generation, context packs, prompt templates, task breakdown."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/workspace/ai", tags=["workspace"])
