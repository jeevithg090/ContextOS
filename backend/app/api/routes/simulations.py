"""Simulation Lab: attack scenarios and security regression suites."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/simulations", tags=["simulations"])
