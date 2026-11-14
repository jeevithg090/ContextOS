"""Session risk: lethal-trifecta tracking with evidence and an explainable 0-100 score (pure).

The "lethal trifecta" is the co-occurrence, within one agent session, of (1) access to sensitive
data, (2) exposure to untrusted content and (3) a channel that can move data out. Together they
make exfiltration via prompt injection *possible*; they do not prove it happened. Every point of
the score comes from a named ``RiskFactor`` that carries its own explanation and evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.domain.enums import (
    OUTBOUND_CATEGORIES,
    SEVERITY_RANK,
    UNTRUSTED_LEVELS,
    FindingCategory,
    RiskLevel,
    ToolCategory,
    TrustLevel,
)
from app.engines.risk.tools import classify_tool

MAX_EVIDENCE = 25

# Fixed contributions (points out of 100). Chosen so that the full trifecta alone is "high" (>= 50)
# and the trifecta plus a high-severity injection is "critical" (>= 75).
W_SENSITIVE = 10
W_UNTRUSTED = 10
W_UNTRUSTED_SUSPICIOUS = 15
W_OUTBOUND_USED = 5
W_TRIFECTA = 30
W_INJECTION = {"critical": 25, "high": 20, "medium": 12, "low": 5, "info": 2}
W_CREDENTIAL_OUTBOUND = 25
W_CREDENTIAL_FLOW = 35
W_DENIED_EACH, W_DENIED_MAX = 5, 15
W_SUSPICIOUS_DEST_FIRST, W_SUSPICIOUS_DEST_EACH, W_SUSPICIOUS_DEST_MAX = 15, 5, 25
W_UNVERIFIED_DEST = 5
W_FINDING = {"critical": (15, 5), "high": (8, 3)}  # (first, each additional)
W_FINDINGS_MAX = 25
W_INHERITED_MAX, W_INHERITED_TRIFECTA = 20, 15

LEVEL_THRESHOLDS = ((75, RiskLevel.CRITICAL), (50, RiskLevel.HIGH), (25, RiskLevel.MEDIUM))

_MANIPULATION = {
    FindingCategory.PROMPT_INJECTION,
    FindingCategory.INSTRUCTION_OVERRIDE,
    FindingCategory.CREDENTIAL_ACCESS,
    FindingCategory.EXFILTRATION,
}
_NOT_EXECUTED = {"denied", "rejected", "pending_approval", "expired", "cancelled"}
_BLOCKED = {"denied", "rejected"}
_OPEN_FINDING = {"open", "acknowledged"}
_SENSITIVE_LEVELS = {"secret", "confidential"}
_BAD_DESTINATIONS = {TrustLevel.SUSPICIOUS, TrustLevel.BLOCKED}


@dataclass
class SessionSignals:
    """Observable facts about one session, assembled by the ingestion service from the DB."""

    # [{"id", "trust_level", "source_type", "source_id", "contains_secrets", "sensitivity",
    #   "detection_max_severity": str|None, "detection_categories": [...]}]
    context_items: list[dict[str, Any]] = field(default_factory=list)
    # [{"id", "tool_name", "category", "status", "decision", "sensitive_resources": [...],
    #   "destination_classification": str|None, "outbound": bool, "sensitive_data_detected": bool}]
    # Optional: "matched_session_fingerprints": [...] (secrets first seen in this session's context).
    tool_invocations: list[dict[str, Any]] = field(default_factory=list)
    # Agent's declared tools (capability, not usage): [{"name","category"}]
    declared_tools: list[dict[str, Any]] = field(default_factory=list)
    # [{"id","category","severity","status"}]
    findings: list[dict[str, Any]] = field(default_factory=list)
    # From a parent/child session: {"session_id", "score", "level", "trifecta": bool, "relation"}
    inherited_risk: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskFactor:
    key: str
    label: str
    weight: int  # contribution to the 0-100 score
    explanation: str
    evidence: list[dict[str, str]] = field(default_factory=list)  # [{"type","id","detail"}]


@dataclass
class SessionRisk:
    score: int
    level: str  # RiskLevel
    sensitive_access: bool
    untrusted_exposure: bool
    outbound_channel: bool
    factors: list[RiskFactor] = field(default_factory=list)
    # {"sensitive_access": [evidence], "untrusted_exposure": [...], "outbound_channel": [...]}
    trifecta_evidence: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    summary: str = ""

    @property
    def trifecta(self) -> bool:
        return self.sensitive_access and self.untrusted_exposure and self.outbound_channel

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trifecta"] = self.trifecta
        return data


def risk_level_for(score: int) -> str:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return str(level)
    return str(RiskLevel.LOW)


def _ev(kind: str, ident: Any, detail: str) -> dict[str, str]:
    return {"type": kind, "id": str(ident or ""), "detail": detail}


def _cap(items: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: dict[tuple[str, str, str], dict[str, str]] = {}
    for item in items:
        seen.setdefault((item["type"], item["id"], item["detail"]), item)
    return list(seen.values())[:MAX_EVIDENCE]


def _sev(value: Any) -> str | None:
    s = str(value).lower() if value else None
    return s if s in SEVERITY_RANK else None


def _ids(resources: Any) -> list[str]:
    out = []
    for r in resources or []:
        out.append(str(r.get("id", "")) if isinstance(r, dict) else str(r))
    return [r for r in out if r]


def _tool_label(inv: dict[str, Any]) -> str:
    return str(inv.get("tool_name") or inv.get("category") or "tool")


def _sensitive_evidence(signals: SessionSignals) -> list[dict[str, str]]:
    ev = []
    for item in signals.context_items:
        sensitivity = str(item.get("sensitivity") or "").lower()
        if item.get("contains_secrets"):
            ev.append(
                _ev(
                    "context_item", item.get("id"), "context contains a secret (stored only in redacted form)"
                )
            )
        elif sensitivity in _SENSITIVE_LEVELS:
            ev.append(_ev("context_item", item.get("id"), f"context classified as {sensitivity}"))
    for inv in signals.tool_invocations:
        if str(inv.get("status") or "").lower() in _NOT_EXECUTED:
            continue
        ids = _ids(inv.get("sensitive_resources"))
        if ids:
            more = f" (+{len(ids) - 3} more)" if len(ids) > 3 else ""
            ev.append(
                _ev(
                    "tool_invocation",
                    inv.get("id"),
                    f"{_tool_label(inv)} accessed {', '.join(ids[:3])}{more}",
                )
            )
        if inv.get("sensitive_data_detected"):
            ev.append(
                _ev(
                    "tool_invocation",
                    inv.get("id"),
                    f"{_tool_label(inv)}: sensitive data detected in its arguments or result",
                )
            )
    return _cap(ev)


def _untrusted_evidence(signals: SessionSignals) -> tuple[list[dict[str, str]], bool]:
    ev, suspicious = [], False
    for item in signals.context_items:
        level = str(item.get("trust_level") or TrustLevel.UNKNOWN).upper()
        if level not in UNTRUSTED_LEVELS:
            continue
        suspicious |= level in _BAD_DESTINATIONS
        detail = f"{item.get('source_type') or 'content'} from a source with trust {level}"
        cats = sorted(set(item.get("detection_categories") or []))
        if cats:
            sev = _sev(item.get("detection_max_severity"))
            detail += f"; detections: {', '.join(cats)}" + (f" (max {sev})" if sev else "")
        ev.append(_ev("context_item", item.get("id"), detail))
    return _cap(ev), suspicious


def _declared_outbound(tool: dict[str, Any]) -> tuple[bool, str]:
    """Can a declared tool move data out? Shell counts: it can reach the network when it chooses to."""
    name = str(tool.get("name") or "")
    hint = tool.get("category")
    if not name:
        category = str(hint or ToolCategory.OTHER)
        return category in OUTBOUND_CATEGORIES, category
    cls = classify_tool(
        name, str(tool.get("provider") or "declared"), category_hint=hint, server=tool.get("server")
    )
    return cls.outbound or cls.category == ToolCategory.SHELL, cls.category


def _outbound_evidence(signals: SessionSignals) -> tuple[list[dict[str, str]], bool]:
    ev, used = [], False
    for inv in signals.tool_invocations:
        if not inv.get("outbound") or str(inv.get("status") or "").lower() in _NOT_EXECUTED:
            continue
        used = True
        dest = inv.get("destination_classification")
        detail = f"{_tool_label(inv)} ({inv.get('category') or 'tool'}) can transmit data"
        ev.append(
            _ev("tool_invocation", inv.get("id"), detail + (f"; destination trust {dest}" if dest else ""))
        )
    for tool in signals.declared_tools:
        capable, category = _declared_outbound(tool)
        if capable:
            ev.append(
                _ev(
                    "tool",
                    tool.get("name") or category,
                    f"declared tool {tool.get('name') or category} ({category}) can transmit data "
                    "(capability, not necessarily used)",
                )
            )
    return _cap(ev), used


def _injection_factor(signals: SessionSignals) -> RiskFactor | None:
    ev, worst = [], None
    for item in signals.context_items:
        cats = set(item.get("detection_categories") or []) & {str(c) for c in _MANIPULATION}
        if not cats:
            continue
        sev = _sev(item.get("detection_max_severity")) or "medium"
        if worst is None or SEVERITY_RANK[sev] > SEVERITY_RANK[worst]:
            worst = sev
        ev.append(_ev("context_item", item.get("id"), f"{', '.join(sorted(cats))} detected (max {sev})"))
    if worst is None:
        return None
    return RiskFactor(
        "injection_observed",
        "Manipulative content detected in context",
        W_INJECTION[worst],
        f"{len(ev)} context item(s) contain prompt-injection, instruction-override or "
        f"credential/exfiltration instructions (worst severity {worst}). Such text tries to steer "
        "the agent; detections are heuristic.",
        _cap(ev),
    )


def _credential_factor(signals: SessionSignals) -> RiskFactor | None:
    ev, flow = [], False
    for inv in signals.tool_invocations:
        matched = inv.get("matched_session_fingerprints") or []
        if not inv.get("outbound") or not (inv.get("sensitive_data_detected") or matched):
            continue
        flow |= bool(matched)
        blocked = str(inv.get("status") or "").lower() in _BLOCKED
        detail = (
            f"{_tool_label(inv)} {'attempted to send' if blocked else 'sent'} data containing a credential"
        )
        if matched:
            detail += f"; {len(matched)} secret(s) match ones first seen in this session's context"
        ev.append(_ev("tool_invocation", inv.get("id"), detail))
    if not ev:
        return None
    if flow:
        return RiskFactor(
            "credential_flow",
            "Credential from context sent outbound",
            W_CREDENTIAL_FLOW,
            "A secret that entered this session through context reappeared in the arguments of an "
            "outbound call (matched by keyed fingerprint; the secret itself is never stored).",
            _cap(ev),
        )
    return RiskFactor(
        "credential_in_outbound",
        "Credential in outbound arguments",
        W_CREDENTIAL_OUTBOUND,
        "An outbound call's arguments contained a credential (redacted before storage).",
        _cap(ev),
    )


def _denied_factor(signals: SessionSignals) -> RiskFactor | None:
    ev = [
        _ev("tool_invocation", inv.get("id"), f"{_tool_label(inv)} was {str(inv.get('status') or 'denied')}")
        for inv in signals.tool_invocations
        if str(inv.get("decision") or "").upper() == "DENY"
        or str(inv.get("status") or "").lower() in _BLOCKED
    ]
    if not ev:
        return None
    return RiskFactor(
        "denied_actions",
        "Actions denied by policy",
        min(W_DENIED_MAX, W_DENIED_EACH * len(ev)),
        f"{len(ev)} action(s) were denied or rejected ({W_DENIED_EACH} points each, max "
        f"{W_DENIED_MAX}). Repeated attempts at blocked actions can indicate a manipulated agent.",
        _cap(ev),
    )


def _destination_factors(signals: SessionSignals) -> list[RiskFactor]:
    bad, unknown = [], []
    for inv in signals.tool_invocations:
        cls = str(inv.get("destination_classification") or "").upper()
        if cls in _BAD_DESTINATIONS:
            bad.append(
                _ev("tool_invocation", inv.get("id"), f"{_tool_label(inv)} targeted a {cls} destination")
            )
        elif (
            cls == TrustLevel.UNKNOWN
            and inv.get("outbound")
            and str(inv.get("status") or "").lower() not in _BLOCKED
        ):
            unknown.append(
                _ev(
                    "tool_invocation",
                    inv.get("id"),
                    f"{_tool_label(inv)} sent to an unclassified destination",
                )
            )
    out = []
    if bad:
        weight = min(W_SUSPICIOUS_DEST_MAX, W_SUSPICIOUS_DEST_FIRST + W_SUSPICIOUS_DEST_EACH * (len(bad) - 1))
        out.append(
            RiskFactor(
                "suspicious_destinations",
                "Suspicious or blocked destinations",
                weight,
                f"{len(bad)} call(s) targeted destinations classified SUSPICIOUS or BLOCKED.",
                _cap(bad),
            )
        )
    elif unknown:
        out.append(
            RiskFactor(
                "unverified_destinations",
                "Unverified destinations",
                W_UNVERIFIED_DEST,
                f"{len(unknown)} outbound call(s) went to destinations no trust rule classifies.",
                _cap(unknown),
            )
        )
    return out


def _findings_factor(signals: SessionSignals) -> RiskFactor | None:
    # Lethal-trifecta findings are produced FROM this computation; counting them would feed back.
    relevant = [
        f
        for f in signals.findings
        if str(f.get("status") or "open").lower() in _OPEN_FINDING
        and str(f.get("severity") or "").lower() in W_FINDING
        and str(f.get("category") or "") != FindingCategory.LETHAL_TRIFECTA
    ]
    if not relevant:
        return None
    weight = 0
    for sev, (first, each) in W_FINDING.items():
        n = sum(1 for f in relevant if str(f.get("severity")).lower() == sev)
        weight += first + each * (n - 1) if n else 0
    ev = [
        _ev("finding", f.get("id"), f"open {f.get('severity')} {f.get('category') or 'finding'}")
        for f in relevant
    ]
    return RiskFactor(
        "open_findings",
        "Unresolved high-severity findings",
        min(W_FINDINGS_MAX, weight),
        f"{len(relevant)} open critical/high finding(s) in this session. Resolving or marking them "
        "false positive removes this contribution.",
        _cap(ev),
    )


def _inherited_factor(signals: SessionSignals) -> RiskFactor | None:
    inh = signals.inherited_risk or {}
    score = int(inh.get("score") or 0)
    trifecta = bool(inh.get("trifecta"))
    if score <= 0 and not trifecta:
        return None
    weight = min(W_INHERITED_MAX, score // 5)
    if trifecta:
        weight = max(weight, W_INHERITED_TRIFECTA)
    relation = inh.get("relation") or "related"
    detail = f"{relation} session risk {score}" + (" with trifecta conditions" if trifecta else "")
    return RiskFactor(
        "inherited_risk",
        "Risk from a related session",
        weight,
        f"A {relation} session (delegation or messaging) has risk score {score}"
        f"{' and trifecta conditions' if trifecta else ''}; content and data can cross that boundary.",
        [_ev("session", inh.get("session_id"), detail)],
    )


def _summary(sensitive: list, untrusted: list, outbound: list, outbound_used: bool) -> str:
    caveat = "Their co-occurrence is a risk condition, not proof of an attack."
    parts = []
    if sensitive:
        parts.append(f"sensitive data access ({len(sensitive)} signal{'s' if len(sensitive) != 1 else ''})")
    if untrusted:
        parts.append(
            f"exposure to untrusted content ({len(untrusted)} item{'s' if len(untrusted) != 1 else ''})"
        )
    if outbound:
        parts.append(
            "an outbound channel" + ("" if outbound_used else " (declared capability, not yet used)")
        )
    if len(parts) == 3:
        return (
            f"All three lethal-trifecta conditions observed: {parts[0]}, {parts[1]} and {parts[2]}. {caveat}"
        )
    if not parts:
        return (
            "No lethal-trifecta conditions observed yet (no sensitive data access, untrusted content or "
            "outbound channel). If they co-occur later, that is a risk condition, not proof of an attack."
        )
    missing = [
        name
        for name, ev in (
            ("sensitive data access", sensitive),
            ("untrusted content", untrusted),
            ("an outbound channel", outbound),
        )
        if not ev
    ]
    return (
        f"Observed {' and '.join(parts)}; not observed: {', '.join(missing)}. Co-occurrence of all three "
        "would be a risk condition, not proof of an attack."
    )


def compute_session_risk(signals: SessionSignals) -> SessionRisk:
    sensitive = _sensitive_evidence(signals)
    untrusted, suspicious_source = _untrusted_evidence(signals)
    outbound, outbound_used = _outbound_evidence(signals)
    factors: list[RiskFactor] = []
    if sensitive:
        factors.append(
            RiskFactor(
                "sensitive_access",
                "Sensitive data accessed",
                W_SENSITIVE,
                "The session touched secrets, confidential context or sensitive resources.",
                sensitive,
            )
        )
    if untrusted:
        weight = W_UNTRUSTED_SUSPICIOUS if suspicious_source else W_UNTRUSTED
        factors.append(
            RiskFactor(
                "untrusted_exposure",
                "Exposure to untrusted content",
                weight,
                "Content from sources that are not trusted entered the agent's context"
                + (" (including SUSPICIOUS/BLOCKED sources)." if suspicious_source else "."),
                untrusted,
            )
        )
    if outbound_used:
        factors.append(
            RiskFactor(
                "outbound_channel",
                "Outbound channel used",
                W_OUTBOUND_USED,
                "The agent used a tool that can transmit data outside the environment.",
                [e for e in outbound if e["type"] == "tool_invocation"],
            )
        )
    if sensitive and untrusted and outbound:
        factors.append(
            RiskFactor(
                "trifecta",
                "Lethal trifecta conditions co-occur",
                W_TRIFECTA,
                "Sensitive data, untrusted content and an outbound channel are present in the same "
                "session, so injected instructions could cause data to leave. This is a condition, "
                "not evidence that it happened.",
                (sensitive[:3] + untrusted[:3] + outbound[:3]),
            )
        )
    for maybe in (
        _injection_factor(signals),
        _credential_factor(signals),
        _denied_factor(signals),
        *_destination_factors(signals),
        _findings_factor(signals),
        _inherited_factor(signals),
    ):
        if maybe is not None:
            factors.append(maybe)
    score = min(100, sum(f.weight for f in factors))
    return SessionRisk(
        score=score,
        level=risk_level_for(score),
        sensitive_access=bool(sensitive),
        untrusted_exposure=bool(untrusted),
        outbound_channel=bool(outbound),
        factors=factors,
        trifecta_evidence={
            "sensitive_access": sensitive,
            "untrusted_exposure": untrusted,
            "outbound_channel": outbound,
        },
        summary=_summary(sensitive, untrusted, outbound, outbound_used),
    )
