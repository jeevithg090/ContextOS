"""Policy Studio: policies, validation and dry-run evaluation."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/policies", tags=["policies"])
