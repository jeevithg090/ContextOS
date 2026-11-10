"""Trust Centre: trust rules, source classification, destinations."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/trust", tags=["trust"])
