"""Security Intelligence: findings and detections."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/findings", tags=["findings"])
