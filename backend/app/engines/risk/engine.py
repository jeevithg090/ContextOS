"""Risk engine facade: stable public API re-exported by ``app.engines.risk``.

Implementation lives in focused modules:
- ``tools``     — server-side tool classification (``classify_tool``)
- ``resources`` — resources touched by a call and its outbound destination
- ``shell``     — static shell-command analysis used by both
- ``session``   — lethal-trifecta session risk (``compute_session_risk``)
- ``posture``   — explainable agent posture (``compute_agent_posture``)
"""

from __future__ import annotations

from app.engines.risk.posture import PostureAssessment, PostureDimension, PostureInputs, compute_agent_posture
from app.engines.risk.resources import extract_destination, extract_resources
from app.engines.risk.session import (
    RiskFactor,
    SessionRisk,
    SessionSignals,
    compute_session_risk,
    risk_level_for,
)
from app.engines.risk.tools import ToolClassification, classify_tool

__all__ = [
    "PostureAssessment",
    "PostureDimension",
    "PostureInputs",
    "RiskFactor",
    "SessionRisk",
    "SessionSignals",
    "ToolClassification",
    "classify_tool",
    "compute_agent_posture",
    "compute_session_risk",
    "extract_destination",
    "extract_resources",
    "risk_level_for",
]
