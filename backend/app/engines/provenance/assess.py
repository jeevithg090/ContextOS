"""Score a walk (origin -> session(s) -> tool invocation) and explain it in plain language.

Scoring is additive and explainable; every point corresponds to a reason line:

    origin trust      BLOCKED +3, SUSPICIOUS +2, UNKNOWN/EXTERNAL +1
    origin detection  critical +3, high +2, medium +1; prompt-injection/instruction-override +2
    sensitive access  +2 (on the invocation, or an earlier, unprevented sibling call in the same session)
    secrets involved  +2, or +3 when a session secret fingerprint matched the call's arguments
    destination       UNKNOWN/EXTERNAL +2, SUSPICIOUS +4, BLOCKED +5 (TRUSTED/APPROVED never count)
    sensitive + outbound in one path +2; crossing sessions (multi-agent) +1; policy-flag only +1
    outcome           prevented -3 (and at most "high"), awaiting approval -2

    severity: >= 11 critical, >= 8 high, >= 5 medium, otherwise low.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domain.enums import (
    SEVERITY_RANK,
    TRUST_RANK,
    UNTRUSTED_LEVELS,
    FindingCategory,
    ProvenanceNodeType,
    Severity,
    TrustLevel,
)
from app.engines.provenance import explain
from app.engines.provenance.graph import GraphIndex
from app.engines.provenance.search import Walk
from app.engines.provenance.signals import (
    AWAITING_APPROVAL,
    ORIGIN_TYPES,
    PREVENTED,
    Detection,
    InvocationAnalysis,
    contains_secrets,
    detection_of,
    trust_of,
)

_TRUST_POINTS: dict[str, int] = {TrustLevel.BLOCKED: 3, TrustLevel.SUSPICIOUS: 2, TrustLevel.UNKNOWN: 1, TrustLevel.EXTERNAL: 1}
_DETECTION_POINTS: dict[str, int] = {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1}
_DESTINATION_POINTS: dict[str, int] = {TrustLevel.BLOCKED: 5, TrustLevel.SUSPICIOUS: 4, TrustLevel.UNKNOWN: 2, TrustLevel.EXTERNAL: 2}
_OUTCOME_ADJUSTMENT: dict[str, int] = {PREVENTED: -3, AWAITING_APPROVAL: -2}
_MAX_SIBLINGS = 3
_EARLIEST = datetime.min.replace(tzinfo=UTC)
_UNTRUSTED = {level.value for level in UNTRUSTED_LEVELS}


@dataclass
class Assessment:
    walk: Walk
    sink: InvocationAnalysis
    siblings: list[InvocationAnalysis]
    node_ids: list[str]
    edge_ids: list[str]
    score: int
    severity: str
    category: str
    title: str
    explanation: str
    reasons: list[str]
    inferred_edge_ids: list[str]
    sessions: list[str]
    related_origin_ids: list[str] = field(default_factory=list)

    @property
    def origin(self) -> str:
        return self.walk.nodes[0]

    @property
    def explained_invocations(self) -> set[str]:
        return {self.sink.node_id, *(s.node_id for s in self.siblings)}


def severity_for(score: int, outcome: str) -> str:
    if score >= 11:
        severity = Severity.CRITICAL.value
    elif score >= 8:
        severity = Severity.HIGH.value
    elif score >= 5:
        severity = Severity.MEDIUM.value
    else:
        severity = Severity.LOW.value
    if outcome == PREVENTED and severity == Severity.CRITICAL.value:
        severity = Severity.HIGH.value
    return severity


def _sensitive_siblings(
    index: GraphIndex, session: str, sink: InvocationAnalysis, analyze: Callable[[str], InvocationAnalysis]
) -> list[tuple[InvocationAnalysis, str]]:
    """Unprevented invocations in the sink's session that touched sensitive data no later than the sink."""
    found: list[tuple[InvocationAnalysis, str]] = []
    for ref in index.out_of_type(session, ProvenanceNodeType.TOOL_INVOCATION.value):
        if ref.other == sink.node_id:
            continue
        sibling = analyze(ref.other)
        if not (sibling.sensitive or sibling.secret_items) or sibling.outcome in (PREVENTED, AWAITING_APPROVAL):
            continue  # a call that was stopped (or is still held) did not touch the data
        if sibling.time is not None and sink.time is not None and sibling.time > sink.time:
            continue
        found.append((sibling, ref.id))
    found.sort(key=lambda pair: (not pair[0].secrets, pair[0].time or _EARLIEST, pair[0].node_id))
    return found[:_MAX_SIBLINGS]


def _worst_detection(nodes: list[dict]) -> tuple[Detection, bool]:
    worst = Detection()
    injection = False
    for node in nodes:
        det = detection_of(node)
        injection = injection or det.injection
        if det.rank > worst.rank:
            worst = det
    return worst, injection


def _category(cross: bool, sensitive: bool, outbound: bool, secrets: bool) -> str:
    if cross:
        return FindingCategory.CROSS_AGENT_CONTAMINATION.value
    if outbound and (sensitive or secrets):
        return FindingCategory.EXFILTRATION.value
    if sensitive or secrets:
        return FindingCategory.CREDENTIAL_ACCESS.value
    if outbound:
        return FindingCategory.DESTINATION_RISK.value
    return FindingCategory.POLICY_VIOLATION.value


def assess(
    index: GraphIndex, walk: Walk, sink: InvocationAnalysis, analyze: Callable[[str], InvocationAnalysis]
) -> Assessment:
    origin_nodes = [index.nodes[n] for n in walk.nodes if index.type_of(n) in ORIGIN_TYPES]
    sessions = [n for n in walk.nodes[1:-1] if index.type_of(n) == ProvenanceNodeType.SESSION.value]
    cross = len(sessions) > 1

    sibling_pairs = []
    if sink.outbound and not sink.sensitive:
        sibling_pairs = _sensitive_siblings(index, walk.last_session, sink, analyze)
    siblings = [s for s, _ in sibling_pairs]

    worst_trust = min(
        (trust_of(n) for n in origin_nodes), key=lambda t: TRUST_RANK[t], default=TrustLevel.UNKNOWN.value
    )
    detection, injection = _worst_detection(origin_nodes)
    sensitive = sink.sensitive or bool(siblings)
    outbound = sink.outbound
    matched = sink.matched_fingerprints > 0
    secrets = sink.secrets or any(s.secrets for s in siblings) or any(contains_secrets(n) for n in origin_nodes)

    score = _TRUST_POINTS.get(worst_trust, 0) + _DETECTION_POINTS.get(detection.max_severity or "", 0)
    score += 2 if injection else 0
    score += 2 if sensitive else 0
    score += (3 if matched else 2) if secrets else 0
    score += _DESTINATION_POINTS.get(sink.worst_destination or "", 0) if outbound else 0
    score += 2 if sensitive and outbound else 0
    score += 1 if cross else 0
    score += 1 if not (sensitive or outbound) else 0
    score += _OUTCOME_ADJUSTMENT.get(sink.outcome, 0)
    score = max(score, 0)

    # Node/edge order follows the story: origin .. session, sensitive siblings, then the sink and its leaves.
    node_ids, edge_ids = list(walk.nodes[:-1]), list(walk.edges[:-1])
    for sibling, edge_id in sibling_pairs:
        node_ids.append(sibling.node_id)
        edge_ids.append(edge_id)
        for leaf in sibling.leaves():
            if leaf.node_id is not None and leaf.edge_id is not None and leaf.node_id not in node_ids:
                node_ids.append(leaf.node_id)
                edge_ids.append(leaf.edge_id)
    node_ids.append(sink.node_id)
    edge_ids.append(walk.edges[-1])
    for leaf in sink.leaves():
        if leaf.node_id is not None and leaf.edge_id is not None and leaf.node_id not in node_ids:
            node_ids.append(leaf.node_id)
            edge_ids.append(leaf.edge_id)

    inferred = [eid for eid in edge_ids if index.edges_by_id.get(eid, {}).get("confidence") == "inferred"]

    story = explain.Story(
        origin=index.nodes[walk.nodes[0]],
        origin_trust=trust_of(index.nodes[walk.nodes[0]]),
        origin_untrusted=trust_of(index.nodes[walk.nodes[0]]) in _UNTRUSTED,
        detection=detection,
        injection=injection,
        sessions=[index.nodes[s] for s in sessions],
        sink=sink,
        siblings=siblings,
        secrets=secrets,
        order_verified=walk.order_verified,
        inferred_count=len(inferred),
    )
    severity = severity_for(score, sink.outcome)
    return Assessment(
        walk=walk,
        sink=sink,
        siblings=siblings,
        node_ids=node_ids,
        edge_ids=edge_ids,
        score=score,
        severity=severity,
        category=_category(cross, sensitive, outbound, secrets),
        title=explain.title(story),
        explanation=explain.explanation(story),
        reasons=explain.reasons(story),
        inferred_edge_ids=inferred,
        sessions=sessions,
    )


def priority(a: Assessment) -> tuple:
    """Most severe first; unprevented before prevented; shorter (more direct) paths first."""
    return (-SEVERITY_RANK[a.severity], -a.score, a.sink.outcome == PREVENTED, len(a.node_ids), tuple(a.node_ids))


__all__ = ["Assessment", "assess", "priority", "severity_for"]
