"""Context Explorer: context items, sources and Context Receipts."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/context", tags=["context"])
