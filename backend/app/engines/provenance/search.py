"""Directed, time-aware walks from untrusted origins to tool invocations.

Allowed steps (by node type, any relation name):

    source -> context_item            (source produced the item)
    context_item -> session           (item entered the session)
    session -> session                (delegation: multi-agent hand-off)
    session -> context_item           (agent message emitted by the session)
    session -> tool_invocation        (the session invoked a tool)   <- candidate sink
    tool_invocation -> context_item   (the invocation returned content)

Time awareness: when both timestamps are known, a step that happened BEFORE the untrusted content
reached the current node is not followed — e.g. a tool call made before a README entered the session,
or a delegation that happened before the content arrived. When a timestamp is missing the step is
followed and the walk is marked ``order_verified=False`` so explanations can say so.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from app.domain.enums import ProvenanceNodeType
from app.engines.provenance.graph import GraphIndex
from app.engines.provenance.signals import edge_time, node_time

_STEPS = {
    (ProvenanceNodeType.SOURCE.value, ProvenanceNodeType.CONTEXT_ITEM.value),
    (ProvenanceNodeType.CONTEXT_ITEM.value, ProvenanceNodeType.SESSION.value),
    (ProvenanceNodeType.SESSION.value, ProvenanceNodeType.SESSION.value),
    (ProvenanceNodeType.SESSION.value, ProvenanceNodeType.CONTEXT_ITEM.value),
    (ProvenanceNodeType.SESSION.value, ProvenanceNodeType.TOOL_INVOCATION.value),
    (ProvenanceNodeType.TOOL_INVOCATION.value, ProvenanceNodeType.CONTEXT_ITEM.value),
}
# Steps that represent an action or hand-off which can only carry content that was already present.
_GATED = {
    (ProvenanceNodeType.SESSION.value, ProvenanceNodeType.SESSION.value),
    (ProvenanceNodeType.SESSION.value, ProvenanceNodeType.CONTEXT_ITEM.value),
    (ProvenanceNodeType.SESSION.value, ProvenanceNodeType.TOOL_INVOCATION.value),
}
_ENTERS_SESSION = (ProvenanceNodeType.CONTEXT_ITEM.value, ProvenanceNodeType.SESSION.value)
_EARLIEST = datetime.min.replace(tzinfo=UTC)


@dataclass(frozen=True)
class Walk:
    nodes: tuple[str, ...]  # origin ... session, sink invocation
    edges: tuple[str, ...]
    order_verified: bool

    @property
    def sink(self) -> str:
        return self.nodes[-1]

    @property
    def last_session(self) -> str:
        return self.nodes[-2]


def _later(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def walks_from(
    index: GraphIndex, origin: str, *, max_depth: int, limit: int, is_sink: Callable[[str], bool]
) -> list[Walk]:
    """Shortest-first walks of at most ``max_depth`` edges from ``origin`` to invocations where
    ``is_sink(invocation_id)`` holds. Non-sink invocations are still walked through (returned items)."""
    found: list[Walk] = []
    # Earliest time the content is known to be present at each node (None = unknown = permissive).
    best: dict[str, datetime | None] = {origin: None}
    queue: deque[tuple[tuple[str, ...], tuple[str, ...], datetime | None, bool]] = deque(
        [((origin,), (), None, True)]
    )
    while queue and len(found) < limit:
        nodes, edges, present_at, verified = queue.popleft()
        if len(edges) >= max_depth:
            continue
        here = nodes[-1]
        here_type = index.type_of(here)
        for ref in index.out.get(here, []):
            nxt = ref.other
            step = (here_type, index.type_of(nxt))
            if step not in _STEPS or nxt in nodes:
                continue
            # When the edge carries no timestamp, use the node whose event the edge records: the item's
            # arrival for item -> session, otherwise the next node (invocation, message, child session).
            event_node = here if step == _ENTERS_SESSION else nxt
            step_at = edge_time(ref.edge) or node_time(index.nodes[event_node])
            step_verified = verified
            if step in _GATED:
                if present_at is not None and step_at is not None and step_at < present_at:
                    continue  # this action happened before the content was present here
                step_verified = verified and present_at is not None and step_at is not None
            arrived = _later(present_at, step_at)
            if nxt in best and (arrived or _EARLIEST) >= (best[nxt] or _EARLIEST):
                continue  # already reached at least as early by a shorter walk
            best[nxt] = arrived
            walk_nodes, walk_edges = (*nodes, nxt), (*edges, ref.id)
            if step[1] == ProvenanceNodeType.TOOL_INVOCATION.value and is_sink(nxt):
                found.append(Walk(walk_nodes, walk_edges, step_verified))
                if len(found) >= limit:
                    break
            queue.append((walk_nodes, walk_edges, arrived, step_verified))
    return found
