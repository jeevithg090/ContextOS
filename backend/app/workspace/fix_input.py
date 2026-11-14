"""Input model and normalisation helpers for fix-context generation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.domain.enums import SEVERITY_RANK
from app.workspace.modes import DEPTH_LIMITS, GenerationOptions, ModeSpec, PresetSpec, may_modify_files

SECURITY_TASK_TYPES = frozenset(
    {"security_vulnerability", "prompt_injection", "agent_misconfiguration", "data_exposure"}
)


@dataclass
class FixContextInput:
    """Everything the generator may use. All record-derived dicts must already be org-scoped; text is
    redacted again during generation as defence in depth.

    - ``task``: task fields (id, key, title, description, task_type, priority, severity, status,
      reproduction_steps, expected_behaviour, actual_behaviour, acceptance_criteria, related_files, labels).
    - ``findings``: ``{id, title, category, severity, explanation, evidence, remediation}`` (redacted).
    - ``events``: ``{id, type, at, summary}``; ``provenance_paths``: ``{title, explanation, severity}``.
    - ``policies``: ``{id, name, outcome, explanation}``.
    - ``previous_attempts``: fix attempts ``{id, status, agent_tool, notes, branch, pr_url}``.
    - ``verification_runs``: ``{id, kind, status, summary, command}``.
    - ``context_pack_items``: items from :func:`app.workspace.context_pack.build_context_pack`.
    - ``repo_docs``: extra documentation refs (``str`` path or ``{path|url, title, verified}``).
    """

    task: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    incident: dict[str, Any] | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    agent: dict[str, Any] | None = None
    provenance_paths: list[dict[str, Any]] = field(default_factory=list)
    policies: list[dict[str, Any]] = field(default_factory=list)
    previous_attempts: list[dict[str, Any]] = field(default_factory=list)
    verification_runs: list[dict[str, Any]] = field(default_factory=list)
    context_pack_items: list[dict[str, Any]] = field(default_factory=list)
    repo_docs: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.task, Mapping):
            raise ValueError("task must be a mapping of task fields")
        for name in (
            "findings",
            "events",
            "provenance_paths",
            "policies",
            "previous_attempts",
            "verification_runs",
            "context_pack_items",
            "repo_docs",
        ):
            value = getattr(self, name)
            if value is None:
                setattr(self, name, [])
            elif not isinstance(value, (list, tuple)):
                raise ValueError(f"{name} must be a list")
        for name in (
            "findings",
            "events",
            "provenance_paths",
            "policies",
            "previous_attempts",
            "verification_runs",
            "context_pack_items",
        ):
            if not all(isinstance(x, Mapping) for x in getattr(self, name)):
                raise ValueError(f"every entry in {name} must be a mapping")


@dataclass
class BuildContext:
    data: FixContextInput
    mode: ModeSpec
    preset: PresetSpec
    options: GenerationOptions
    section_overrides: Mapping[str, str]

    @property
    def limits(self) -> dict[str, int]:
        return DEPTH_LIMITS[self.options.technical_depth]

    @property
    def may_modify(self) -> bool:
        return may_modify_files(self.mode, self.options)

    @property
    def task(self) -> Mapping[str, Any]:
        return self.data.task

    @property
    def task_ref(self) -> str | None:
        return ref("task", self.task)

    @property
    def is_security(self) -> bool:
        return str(self.task.get("task_type")) in SECURITY_TASK_TYPES or bool(self.data.findings)

    def sorted_findings(self) -> list[Mapping[str, Any]]:
        return sorted(
            self.data.findings,
            key=lambda f: (
                -SEVERITY_RANK.get(str(f.get("severity")), 0),
                str(f.get("title") or ""),
                str(f.get("id") or ""),
            ),
        )

    def sorted_events(self) -> list[Mapping[str, Any]]:
        return sorted(self.data.events, key=lambda e: (str(e.get("at") or ""), str(e.get("id") or "")))

    def categories(self) -> list[str]:
        return list(
            dict.fromkeys(str(f.get("category")) for f in self.sorted_findings() if f.get("category"))
        )


def ref(kind: str, record: Mapping[str, Any] | None) -> str | None:
    if not record:
        return None
    rid = record.get("id")
    return f"{kind}:{rid}" if isinstance(rid, str) and rid else None


def humanize(value: Any) -> str:
    return str(value or "").replace("_", " ").strip()


def task_label(task: Mapping[str, Any]) -> str:
    key = task.get("key")
    if not key and task.get("number") is not None:
        key = f"CTX-{task['number']}"
    return str(key) if key else ""


def criteria(task: Mapping[str, Any]) -> list[tuple[str, bool]]:
    out: list[tuple[str, bool]] = []
    for item in task.get("acceptance_criteria") or []:
        if isinstance(item, str) and item.strip():
            out.append((item, False))
        elif isinstance(item, Mapping) and isinstance(item.get("text"), str) and item["text"].strip():
            out.append((item["text"], bool(item.get("done"))))
    return out
