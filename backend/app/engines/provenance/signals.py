"""Read security signals off provenance nodes (trust, detections, sensitive access, destinations, decisions).

Recognised node attributes (top level or under ``data``):

- source / context_item: ``trust_level``; ``detection_summary`` or ``detection`` ({score, max_severity,
  rule_ids, categories}) or flat ``max_severity``/``rule_ids``/``categories``; ``contains_secrets``.
- tool_invocation: ``decision``, ``enforcement``, ``status``, ``tool_name``; sensitive flags ``sensitive``
  / ``sensitive_access`` / ``sensitive_data_detected``; ``secret_fingerprints``;
  ``matched_session_fingerprints``; inline ``resources`` ([{id, sensitive}]) when no resource nodes;
  ``destination_classification`` / ``destination`` when no destination node; ``requested_at``.
- resource: ``sensitive`` (bool) or ``sensitivity == "secret"``.
- destination: ``classification`` (or ``trust_level``).
- policy_decision: ``decision``, ``enforcement`` (fallback when the invocation lacks them).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.domain.enums import (
    SEVERITY_RANK,
    TRUST_RANK,
    UNTRUSTED_LEVELS,
    Decision,
    EnforcementMode,
    FindingCategory,
    ProvenanceNodeType,
    Severity,
    TrustLevel,
)
from app.engines.provenance._util import attr, count_of, lower, parse_time, upper
from app.engines.provenance.graph import GraphIndex

ORIGIN_TYPES = (ProvenanceNodeType.SOURCE.value, ProvenanceNodeType.CONTEXT_ITEM.value)
SAFE_DESTINATIONS = {TrustLevel.TRUSTED.value, TrustLevel.APPROVED.value}
_UNTRUSTED = {level.value for level in UNTRUSTED_LEVELS}
_INJECTION_CATEGORIES = {FindingCategory.PROMPT_INJECTION.value, FindingCategory.INSTRUCTION_OVERRIDE.value}
_INJECTION_RULE_PREFIXES = ("PI-", "IO-")

# Outcomes of the tool call at the end of a path.
PREVENTED = "prevented"                  # DENY / rejected approval at an enforced boundary
AWAITING_APPROVAL = "awaiting_approval"  # held at an enforced boundary until a human decides
ADVISORY_ONLY = "advisory_only"          # blocking decision returned, but the host may ignore it
NOT_PREVENTED = "not_prevented"          # allowed, approved, or only observed after execution

_TIME_KEYS = (
    "requested_at", "observed_at", "ts", "occurred_at", "received_at", "collected_at", "started_at", "created_at",
)


def node_time(node: Mapping[str, Any]) -> datetime | None:
    return parse_time(attr(node, *_TIME_KEYS))


def edge_time(edge: Mapping[str, Any]) -> datetime | None:
    return parse_time(edge.get("observed_at") or edge.get("ts"))


def trust_of(node: Mapping[str, Any]) -> str:
    """Trust level of a node; unclassified nodes are ``UNKNOWN`` (the domain default)."""
    level = upper(attr(node, "trust_level", "trust", "classification"))
    return level if level in TRUST_RANK else TrustLevel.UNKNOWN.value


@dataclass(frozen=True)
class Detection:
    max_severity: str | None = None
    rule_ids: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.max_severity, -1) if self.max_severity else -1

    @property
    def injection(self) -> bool:
        if any(c in _INJECTION_CATEGORIES for c in self.categories):
            return True
        return any(r.upper().startswith(_INJECTION_RULE_PREFIXES) or "injection" in r.lower() for r in self.rule_ids)


def _str_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list | tuple | set | frozenset):
        return tuple(sorted({str(v) for v in value if v not in (None, "")}))
    return ()


def detection_of(node: Mapping[str, Any]) -> Detection:
    summary = attr(node, "detection_summary", "detection")
    if not isinstance(summary, Mapping):
        summary = {
            "max_severity": attr(node, "max_severity"),
            "rule_ids": attr(node, "rule_ids"),
            "categories": attr(node, "categories"),
        }
    severity = lower(summary.get("max_severity"))
    return Detection(
        max_severity=severity if severity in SEVERITY_RANK else None,
        rule_ids=_str_tuple(summary.get("rule_ids")),
        categories=_str_tuple(summary.get("categories")),
    )


def is_origin(node: Mapping[str, Any]) -> bool:
    """Untrusted origin: a source/context item with untrusted trust or a detection of medium or worse."""
    if node.get("type") not in ORIGIN_TYPES:
        return False
    if trust_of(node) in _UNTRUSTED:
        return True
    return detection_of(node).rank >= SEVERITY_RANK[Severity.MEDIUM]


def contains_secrets(node: Mapping[str, Any]) -> bool:
    return bool(attr(node, "contains_secrets")) or upper(attr(node, "sensitivity")) == "SECRET"


@dataclass(frozen=True)
class Leaf:
    """A node hanging off a tool invocation (resource / destination / decision) that explains it."""

    node_id: str | None  # None for inline attributes without a graph node
    edge_id: str | None
    label: str
    classification: str | None = None


@dataclass
class InvocationAnalysis:
    node_id: str
    tool_label: str
    time: datetime | None
    sensitive_flag: bool = False
    sensitive_resources: list[Leaf] = field(default_factory=list)
    destinations: list[Leaf] = field(default_factory=list)  # destinations NOT trusted/approved
    decision_leaf: Leaf | None = None
    secret_items: list[Leaf] = field(default_factory=list)  # returned context items carrying secrets
    secrets_in_arguments: bool = False
    matched_fingerprints: int = 0
    decision: str | None = None
    enforcement: str | None = None
    status: str | None = None
    outcome: str = NOT_PREVENTED

    @property
    def sensitive(self) -> bool:
        return self.sensitive_flag or bool(self.sensitive_resources)

    @property
    def outbound(self) -> bool:
        return bool(self.destinations)

    @property
    def secrets(self) -> bool:
        return self.secrets_in_arguments or self.matched_fingerprints > 0 or bool(self.secret_items)

    @property
    def policy_flagged(self) -> bool:
        return self.decision in (Decision.DENY.value, Decision.REQUIRE_APPROVAL.value) or self.status in (
            "denied", "rejected", "pending_approval",
        )

    @property
    def risky(self) -> bool:
        return self.sensitive or self.outbound or self.policy_flagged

    @property
    def worst_destination(self) -> str | None:
        if not self.destinations:
            return None
        return min((d.classification or TrustLevel.UNKNOWN.value for d in self.destinations),
                   key=lambda c: TRUST_RANK.get(c, TRUST_RANK[TrustLevel.UNKNOWN]))

    def leaves(self) -> list[Leaf]:
        found = [*self.sensitive_resources, *self.destinations, *self.secret_items]
        if self.decision_leaf is not None:
            found.append(self.decision_leaf)
        return [leaf for leaf in found if leaf.node_id is not None]


def _outcome(decision: str | None, enforcement: str | None, status: str | None) -> str:
    enforced = enforcement == EnforcementMode.ENFORCED.value
    advisory = enforcement == EnforcementMode.ADVISORY.value
    if decision == Decision.DENY.value or status in ("denied", "rejected"):
        return PREVENTED if enforced else ADVISORY_ONLY if advisory else NOT_PREVENTED
    if decision == Decision.REQUIRE_APPROVAL.value:
        if status in (None, "requested", "pending_approval"):
            return AWAITING_APPROVAL if enforced else ADVISORY_ONLY if advisory else NOT_PREVENTED
    return NOT_PREVENTED


def _inline_resources(node: Mapping[str, Any]) -> list[Leaf]:
    resources = attr(node, "resources")
    if not isinstance(resources, list):
        return []
    return [
        Leaf(None, None, str(r.get("id") or r.get("path") or r.get("kind") or "resource"))
        for r in resources
        if isinstance(r, Mapping) and r.get("sensitive")
    ]


def analyze_invocation(index: GraphIndex, inv_id: str) -> InvocationAnalysis:
    node = index.nodes[inv_id]
    tool_label = attr(node, "tool_name", "tool")
    if not tool_label:
        tools = index.out_of_type(inv_id, ProvenanceNodeType.TOOL.value)
        tool_label = index.nodes[tools[0].other]["label"] if tools else node["label"]
    result = InvocationAnalysis(node_id=inv_id, tool_label=str(tool_label), time=node_time(node))
    result.sensitive_flag = bool(attr(node, "sensitive", "sensitive_access", "sensitive_data_detected"))
    result.secrets_in_arguments = bool(attr(node, "sensitive_data_detected")) or count_of(
        attr(node, "secret_fingerprints")
    ) > 0
    result.matched_fingerprints = count_of(attr(node, "matched_session_fingerprints"))

    resource_refs = index.out_of_type(inv_id, ProvenanceNodeType.RESOURCE.value)
    for ref in resource_refs:
        res = index.nodes[ref.other]
        if attr(res, "sensitive") or upper(attr(res, "sensitivity")) == "SECRET":
            result.sensitive_resources.append(Leaf(ref.other, ref.id, res["label"]))
    if not resource_refs:
        result.sensitive_resources.extend(_inline_resources(node))

    dest_refs = index.out_of_type(inv_id, ProvenanceNodeType.DESTINATION.value)
    for ref in dest_refs:
        cls = trust_of(index.nodes[ref.other])
        if cls not in SAFE_DESTINATIONS:
            result.destinations.append(Leaf(ref.other, ref.id, index.nodes[ref.other]["label"], cls))
    inline_cls = upper(attr(node, "destination_classification"))
    if not dest_refs and inline_cls is not None:
        cls = inline_cls if inline_cls in TRUST_RANK else TrustLevel.UNKNOWN.value
        if cls not in SAFE_DESTINATIONS:
            label = attr(node, "destination_identifier", "destination", default="destination")
            result.destinations.append(Leaf(None, None, str(label), cls))

    for ref in index.out_of_type(inv_id, ProvenanceNodeType.CONTEXT_ITEM.value):
        if contains_secrets(index.nodes[ref.other]):
            result.secret_items.append(Leaf(ref.other, ref.id, index.nodes[ref.other]["label"]))

    decision = upper(attr(node, "decision"))
    enforcement = lower(attr(node, "enforcement"))
    for ref in index.out_of_type(inv_id, ProvenanceNodeType.POLICY_DECISION.value):
        dnode = index.nodes[ref.other]
        result.decision_leaf = Leaf(ref.other, ref.id, dnode["label"])
        decision = decision or upper(attr(dnode, "decision"))
        enforcement = enforcement or lower(attr(dnode, "enforcement"))
        break
    result.decision, result.enforcement = decision, enforcement
    result.status = lower(attr(node, "status"))
    result.outcome = _outcome(decision, enforcement, result.status)
    return result
