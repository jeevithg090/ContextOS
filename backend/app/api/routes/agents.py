"""Agent registry, profiles, identity/delegation graph and security posture."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/agents", tags=["agents"])
