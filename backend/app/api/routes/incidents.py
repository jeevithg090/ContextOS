"""Incidents, investigation timeline and evidence export."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/incidents", tags=["incidents"])
