"""Replay Lab: recorded session replay and counterfactual policy evaluation."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/replay", tags=["replay"])
