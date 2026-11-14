"""The ``Section`` value type and the part-composition rules shared by fix-context builders.

A section is built from *parts*, each with an epistemic kind. A section with a single kind renders
its content directly; a mixed section renders each part under a fixed sub-heading ("Confirmed
facts", "Observed evidence", "Assumptions", "Hypotheses", "Recommendations", "Instructions") so the
receiving agent can always tell what is known from what is guessed. A mixed section's declared
``kind`` is its *least certain* part, so nothing is over-trusted by consumers that only read it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.workspace.modes import SECTION_KEYS

SECTION_KINDS: tuple[str, ...] = (
    "fact",
    "evidence",
    "assumption",
    "hypothesis",
    "recommendation",
    "instruction",
)

# Render order of parts inside a mixed section.
PART_ORDER: tuple[str, ...] = (
    "fact",
    "evidence",
    "assumption",
    "hypothesis",
    "recommendation",
    "instruction",
)

# Least certain wins when a section mixes kinds.
_UNCERTAINTY = {
    "fact": 0,
    "evidence": 1,
    "instruction": 2,
    "recommendation": 3,
    "assumption": 4,
    "hypothesis": 5,
}

SUBHEADINGS: dict[str, str] = {
    "fact": "Confirmed facts",
    "evidence": "Observed evidence",
    "assumption": "Assumptions",
    "hypothesis": "Hypotheses",
    "recommendation": "Recommendations",
    "instruction": "Instructions",
}

SECTION_TITLES: dict[str, str] = {
    "task_summary": "Task summary",
    "problem_description": "Problem description",
    "current_behaviour": "Current behaviour",
    "expected_behaviour": "Expected behaviour",
    "reproduction_steps": "Reproduction steps",
    "available_evidence": "Available evidence",
    "codebase_context": "Codebase context",
    "root_cause_hypotheses": "Root-cause hypotheses",
    "required_implementation": "Required implementation",
    "constraints": "Constraints",
    "acceptance_criteria": "Acceptance criteria",
    "testing_requirements": "Testing requirements",
    "verification": "Verification and reporting",
    "related_documentation": "Related documentation",
}
assert tuple(SECTION_TITLES) == SECTION_KEYS


@dataclass
class Section:
    key: str
    title: str
    content: str
    kind: str
    sources: list[str] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)
    required: bool = False
    edited: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "content": self.content,
            "kind": self.kind,
            "kinds": list(self.kinds or [self.kind]),
            "sources": list(self.sources),
            "required": self.required,
            "edited": self.edited,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Section:
        """Rehydrate a stored (possibly user-edited) section; validates the fields that rendering relies on."""
        key = data.get("key")
        if not isinstance(key, str) or not key:
            raise ValueError("Section needs a key")
        kind = data.get("kind") or "instruction"
        if kind not in SECTION_KINDS:
            raise ValueError(f"Section {key!r} has invalid kind {kind!r}")
        content = data.get("content")
        if not isinstance(content, str):
            raise ValueError(f"Section {key!r} content must be a string")
        return cls(
            key=key,
            title=str(data.get("title") or SECTION_TITLES.get(key, key.replace("_", " ").capitalize())),
            content=content,
            kind=kind,
            sources=[str(s) for s in data.get("sources") or []],
            kinds=[k for k in data.get("kinds") or [kind] if k in SECTION_KINDS],
            required=bool(data.get("required", False)),
            edited=bool(data.get("edited", False)),
        )


@dataclass
class _Part:
    kind: str
    blocks: list[str]
    title: str | None = None


class Parts:
    """Accumulates content blocks per kind and composes them into a :class:`Section`."""

    def __init__(self) -> None:
        self._parts: list[_Part] = []
        self.sources: list[str] = []

    def add(self, kind: str, block: str, *, title: str | None = None) -> None:
        if kind not in SECTION_KINDS:
            raise ValueError(f"Unknown part kind {kind!r}")
        if not block or not block.strip():
            return
        for part in self._parts:
            if part.kind == kind and part.title == title:
                part.blocks.append(block.strip())
                return
        self._parts.append(_Part(kind, [block.strip()], title))

    def source(self, *refs: str | None) -> None:
        for ref in refs:
            if ref and ref not in self.sources:
                self.sources.append(ref)

    def __bool__(self) -> bool:
        return bool(self._parts)

    def build(self, key: str, *, required: bool) -> Section:
        if not self._parts:
            raise ValueError(f"Section {key!r} has no content")
        ordered = sorted(self._parts, key=lambda p: (PART_ORDER.index(p.kind), p.title is not None))
        kinds = list(dict.fromkeys(p.kind for p in ordered))
        titled = any(p.title for p in ordered)
        if len(kinds) == 1 and not titled:
            content = "\n\n".join(b for p in ordered for b in p.blocks)
        else:
            chunks = []
            for part in ordered:
                heading = part.title or SUBHEADINGS[part.kind]
                chunks.append(f"### {heading}\n\n" + "\n\n".join(part.blocks))
            content = "\n\n".join(chunks)
        kind = max(kinds, key=lambda k: _UNCERTAINTY[k])
        return Section(
            key=key,
            title=SECTION_TITLES[key],
            content=content,
            kind=kind,
            sources=list(self.sources),
            kinds=kinds,
            required=required,
        )
