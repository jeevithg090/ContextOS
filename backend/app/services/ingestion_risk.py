"""Session risk for the ingestion pipeline: assemble ``SessionSignals`` from persisted rows, run the
risk engine, persist the result and raise the lethal-trifecta finding on first activation.

The trifecta is a risk condition (sensitive access + untrusted content + an outbound channel in one
session), never proof of an attack; the finding and the stored state say so.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.domain.enums import (
    SEVERITY_RANK,
    TRUST_RANK,
    UNTRUSTED_LEVELS,
    FindingCategory,
    Severity,
    TrustLevel,
)
from app.engines.risk import SessionRisk, SessionSignals, classify_tool, compute_session_risk
from app.models import (
    AgentSession,
    ContextItem,
    ContextSource,
    Destination,
    SecurityFinding,
    Tool,
    ToolInvocation,
)
from app.services.ingestion_findings import raise_finding
from app.services.ingestion_state import PipelineState

MAX_SIGNAL_ROWS = 5000
INJECTION_CATEGORIES = frozenset({FindingCategory.PROMPT_INJECTION.value, FindingCategory.INSTRUCTION_OVERRIDE.value})
# Content that tries to steer the agent (injection proper, or instructions to reach credentials / send data).
MANIPULATION_CATEGORIES = INJECTION_CATEGORIES | {FindingCategory.CREDENTIAL_ACCESS.value, FindingCategory.EXFILTRATION.value}
_MEDIUM = SEVERITY_RANK[Severity.MEDIUM]

# (tool_id, argument_hash) -> whether that call can transmit data. Pure function of the stored,
# redacted arguments, so a bounded process-local memo avoids re-classifying old calls each event.
_OUTBOUND_MEMO: OrderedDict[tuple[str, str | None], bool] = OrderedDict()
_MEMO_SIZE = 20_000


@dataclass
class SessionView:
    signals: SessionSignals
    context: dict[str, Any]  # EvaluationInput.context


def manipulation_hits(summary: dict[str, Any] | None, *, min_rank: int = _MEDIUM) -> list[dict[str, Any]]:
    hits = (summary or {}).get("hits") or []
    return [
        h for h in hits
        if isinstance(h, dict) and h.get("category") in MANIPULATION_CATEGORIES
        and SEVERITY_RANK.get(str(h.get("severity")), 0) >= min_rank
    ]


def _effective_trust(item_level: str | None, source_level: str | None) -> str:
    levels = [lvl for lvl in (item_level, source_level) if lvl in TRUST_RANK]
    return min(levels, key=TRUST_RANK.__getitem__) if levels else TrustLevel.UNKNOWN.value


def _outbound(db: Session, rows: list[Any]) -> dict[str, bool]:
    """invocation id -> outbound, re-deriving the server-side classification from stored arguments."""
    out: dict[str, bool] = {}
    missing: list[Any] = []
    for r in rows:
        if r.destination_id:
            out[r.id] = True
            continue
        key = (r.tool_id, r.argument_hash)
        if key in _OUTBOUND_MEMO:
            out[r.id] = _OUTBOUND_MEMO[key]
        else:
            missing.append(r)
    if missing:
        args = dict(db.execute(
            select(ToolInvocation.id, ToolInvocation.arguments_redacted).where(
                ToolInvocation.id.in_([r.id for r in missing])
            )
        ).all())
        for r in missing:
            value = classify_tool(r.tool_name, r.provider, server=r.server, arguments=args.get(r.id) or {}).outbound
            out[r.id] = value
            _OUTBOUND_MEMO[(r.tool_id, r.argument_hash)] = value
            if len(_OUTBOUND_MEMO) > _MEMO_SIZE:
                _OUTBOUND_MEMO.popitem(last=False)
    return out


def session_view(st: PipelineState, *, pending: dict[str, Any] | None = None) -> SessionView:
    """Signals for the current session, optionally including a not-yet-persisted tool call."""
    assert st.session is not None and st.agent is not None
    db, org, session = st.db, st.ctx.org_id, st.session
    db.flush()
    item_rows = db.execute(
        select(
            ContextItem.id, ContextItem.trust_level, ContextItem.source_id, ContextItem.contains_secrets,
            ContextItem.sensitivity, ContextItem.detection_summary, ContextSource.source_type,
            ContextSource.trust_level.label("source_trust"),
        )
        .join(ContextSource, ContextSource.id == ContextItem.source_id)
        .where(ContextItem.organization_id == org, ContextItem.session_id == session.id)
        .order_by(ContextItem.received_at.desc())
        .limit(MAX_SIGNAL_ROWS)
    ).all()
    items: list[dict[str, Any]] = []
    for r in item_rows:
        summary = r.detection_summary or {}
        items.append({
            "id": r.id,
            "trust_level": _effective_trust(r.trust_level, r.source_trust),
            "source_type": r.source_type,
            "source_id": r.source_id,
            "contains_secrets": bool(r.contains_secrets),
            "sensitivity": r.sensitivity,
            "detection_max_severity": summary.get("max_severity"),
            "detection_categories": list(summary.get("categories") or []),
            "_manipulation": bool(manipulation_hits(summary)),
            "_source_trust": r.source_trust,
        })

    inv_rows = db.execute(
        select(
            ToolInvocation.id, ToolInvocation.status, ToolInvocation.decision, ToolInvocation.resources,
            ToolInvocation.destination_id, ToolInvocation.sensitive_data_detected,
            ToolInvocation.matched_session_fingerprints, ToolInvocation.argument_hash, ToolInvocation.tool_id,
            Tool.name.label("tool_name"), Tool.category, Tool.provider, Tool.server,
            Destination.classification.label("destination_classification"),
        )
        .join(Tool, Tool.id == ToolInvocation.tool_id)
        .outerjoin(Destination, Destination.id == ToolInvocation.destination_id)
        .where(ToolInvocation.organization_id == org, ToolInvocation.session_id == session.id)
        .order_by(ToolInvocation.requested_at.desc())
        .limit(MAX_SIGNAL_ROWS)
    ).all()
    pending_id = pending.get("id") if pending else None
    inv_rows = [r for r in inv_rows if r.id != pending_id]
    outbound = _outbound(db, inv_rows)
    invocations = [
        {
            "id": r.id, "tool_name": r.tool_name, "category": r.category, "status": r.status,
            "decision": r.decision,
            "sensitive_resources": [x.get("id") for x in (r.resources or []) if isinstance(x, dict) and x.get("sensitive")],
            "destination_classification": r.destination_classification,
            "outbound": outbound.get(r.id, False),
            "sensitive_data_detected": bool(r.sensitive_data_detected),
            "matched_session_fingerprints": list(r.matched_session_fingerprints or []),
        }
        for r in inv_rows
    ]
    if pending:
        invocations.insert(0, pending)

    findings = _session_findings(db, org, session.id)
    declared = (st.agent.declared_capabilities or {}).get("tools") or []
    signals = SessionSignals(
        context_items=[{k: v for k, v in i.items() if not k.startswith("_")} for i in items],
        tool_invocations=invocations,
        declared_tools=[t for t in declared if isinstance(t, dict)],
        findings=findings,
        inherited_risk=_inherited(db, org, session),
    )
    return SessionView(signals=signals, context=_context_summary(items))


def _session_findings(db: Session, org_id: str, session_id: str) -> list[dict[str, Any]]:
    return [
        {"id": f.id, "category": f.category, "severity": f.severity, "status": f.status}
        for f in db.execute(
            select(SecurityFinding.id, SecurityFinding.category, SecurityFinding.severity, SecurityFinding.status)
            .where(SecurityFinding.organization_id == org_id, SecurityFinding.session_id == session_id)
            .limit(MAX_SIGNAL_ROWS)
        ).all()
    ]


def _inherited(db: Session, org_id: str, session: AgentSession) -> dict[str, Any]:
    if not session.parent_session_id:
        return {}
    parent = db.scalar(
        select(AgentSession).where(AgentSession.organization_id == org_id, AgentSession.id == session.parent_session_id)
    )
    if parent is None:
        return {}
    state = parent.risk_state or {}
    return {
        "session_id": parent.id, "score": parent.risk_score or 0, "level": state.get("level"),
        "trifecta": bool(state.get("trifecta")), "relation": "delegating (parent)",
    }


def _context_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    if not items:
        return {"untrusted_item_count": 0, "suspicious_source_ids": [], "injection_detected": False}
    lowest = min((i["trust_level"] for i in items), key=TRUST_RANK.__getitem__)
    severities = [i["detection_max_severity"] for i in items if i["detection_max_severity"] in SEVERITY_RANK]
    return {
        "lowest_trust": lowest,
        "untrusted_item_count": sum(1 for i in items if i["trust_level"] in UNTRUSTED_LEVELS),
        "suspicious_source_ids": sorted({
            i["source_id"] for i in items if i["_source_trust"] in (TrustLevel.SUSPICIOUS, TrustLevel.BLOCKED)
        }),
        "injection_detected": any(i["_manipulation"] for i in items),
        "max_detection_severity": max(severities, key=SEVERITY_RANK.__getitem__) if severities else None,
    }


def session_risk_input(risk: SessionRisk) -> dict[str, Any]:
    """``EvaluationInput.session``."""
    return {
        "score": risk.score, "level": risk.level, "untrusted_exposure": risk.untrusted_exposure,
        "sensitive_access": risk.sensitive_access, "outbound_channel": risk.outbound_channel,
        "trifecta": risk.trifecta,
    }


def update_session_risk(st: PipelineState, *, view: SessionView | None = None) -> SessionRisk:
    """Recompute and persist the session's risk; raise the trifecta finding when it first activates.

    ``view``: signals already assembled for this event (a tool request whose context and calls are
    unchanged since); only the findings, which the decision may have added, are re-read.
    """
    assert st.session is not None and st.agent is not None
    if view is None:
        signals = session_view(st).signals
    else:
        st.db.flush()
        signals = replace(view.signals, findings=_session_findings(st.db, st.ctx.org_id, st.session.id))
    risk = compute_session_risk(signals)
    session = st.session
    was_active = bool((session.risk_state or {}).get("trifecta"))
    state = risk.to_dict()
    state["computed_at"] = st.now.isoformat()
    session.risk_state = state
    session.risk_score = risk.score
    if risk.trifecta and not was_active:
        _trifecta_finding(st, risk)
    _update_agent_risk(st)
    return risk


def _trifecta_finding(st: PipelineState, risk: SessionRisk) -> None:
    evidence: list[dict[str, Any]] = []
    labels = {"sensitive_access": "sensitive data access", "untrusted_exposure": "untrusted content",
              "outbound_channel": "outbound channel"}
    for leg, label in labels.items():
        for ev in (risk.trifecta_evidence.get(leg) or [])[:5]:
            evidence.append({"type": ev.get("type"), "id": ev.get("id"), "excerpt": None,
                             "detail": f"{label}: {ev.get('detail')}"})
    raise_finding(
        st,
        category=FindingCategory.LETHAL_TRIFECTA.value,
        rule_id="RISK-TRIFECTA-001",
        title=f"Lethal trifecta conditions in a session of {st.agent.name if st.agent else 'an agent'}",
        explanation=(
            f"{risk.summary} With all three present, content injected into the agent's context could cause "
            "sensitive data to leave the environment. Outbound calls in this session are now evaluated with "
            "session.trifecta = true."
        ),
        severity=Severity.HIGH.value,
        confidence=0.9,
        evidence=evidence,
    )


def _update_agent_risk(st: PipelineState) -> None:
    assert st.session is not None and st.agent is not None
    st.db.flush()
    top = st.db.scalar(
        select(func.max(AgentSession.risk_score)).where(
            AgentSession.organization_id == st.ctx.org_id,
            AgentSession.agent_id == st.agent.id,
            AgentSession.status == "active",
        )
    )
    st.agent.risk_score = int(top or 0)
