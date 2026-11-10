"""Risk engine (pure; no database access).

CONTRACT:

    classify_tool(name, provider, *, category_hint=None, server=None, arguments=None) -> ToolClassification
        Server-side tool classification (category + risk level + whether it is an outbound
        channel / reads sensitive data). Knows Claude Code built-in tools (Bash, Read, Write, Edit,
        WebFetch, WebSearch, Task, NotebookEdit, Glob, Grep, mcp__<server>__<tool>), common MCP
        tool naming, and generic verbs (send_email, http_request, execute_sql...).

    extract_resources(category, arguments) -> list[dict]
        Resources touched by a tool call: file paths, URLs, hosts, shell commands; flags sensitive
        ones via app.engines.redaction.is_sensitive_path.

    extract_destination(category, arguments, resources) -> dict | None
        Outbound destination ({"kind", "identifier"}) when the call can transmit data.

    compute_session_risk(signals: SessionSignals) -> SessionRisk
        Lethal-trifecta tracking with evidence: (1) sensitive data access, (2) exposure to
        untrusted content, (3) an outbound channel. Reports conditions, NOT proof of an attack.

    compute_agent_posture(inputs: PostureInputs) -> PostureAssessment
        Explainable 0-100 posture with per-dimension scores, each with evidence and a fix hint.
"""

from app.engines.risk.engine import (
    PostureAssessment,
    PostureInputs,
    SessionRisk,
    SessionSignals,
    ToolClassification,
    classify_tool,
    compute_agent_posture,
    compute_session_risk,
    extract_destination,
    extract_resources,
)

__all__ = [
    "PostureAssessment",
    "PostureInputs",
    "SessionRisk",
    "SessionSignals",
    "ToolClassification",
    "classify_tool",
    "compute_agent_posture",
    "compute_session_risk",
    "extract_destination",
    "extract_resources",
]
