"""Event ingestion (POST /events), synchronous decisions (POST /decide), event log and live stream (GET /stream)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="", tags=["events"])
