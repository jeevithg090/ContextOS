"""Prompt modes, agent presets and generation options for fix-context prompts.

A *mode* says what the receiving coding agent is allowed to do (investigate only, plan, implement,
...). A *preset* adds notes that are specific to one agent product; notes only describe behaviour
the product actually has (instruction files it reads, permission features it offers) — nothing
aspirational. :class:`GenerationOptions` holds the user's tuning knobs and validates them.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

SECTION_KEYS: tuple[str, ...] = (
    "task_summary",
    "problem_description",
    "current_behaviour",
    "expected_behaviour",
    "reproduction_steps",
    "available_evidence",
    "codebase_context",
    "root_cause_hypotheses",
    "required_implementation",
    "constraints",
    "acceptance_criteria",
    "testing_requirements",
    "verification",
    "related_documentation",
)

_CORE = (
    "task_summary",
    "problem_description",
    "available_evidence",
    "codebase_context",
    "constraints",
    "verification",
)


class PromptMode(StrEnum):
    INVESTIGATE_ONLY = "investigate_only"
    ROOT_CAUSE_ANALYSIS = "root_cause_analysis"
    IMPLEMENTATION_PLAN = "implementation_plan"
    IMPLEMENT_FIX = "implement_fix"
    SECURITY_HARDEN = "security_harden"
    REFACTOR = "refactor"
    TEST_AND_VERIFY = "test_and_verify"
    FULL_AUTONOMOUS_REMEDIATION = "full_autonomous_remediation"


class Preset(StrEnum):
    CLAUDE_CODE = "claude_code"
    CODEX = "codex"
    CURSOR = "cursor"
    GENERIC = "generic"


class TechnicalDepth(StrEnum):
    BRIEF = "brief"
    STANDARD = "standard"
    DEEP = "deep"


class Autonomy(StrEnum):
    ASK_BEFORE_CHANGES = "ask_before_changes"
    AUTONOMOUS_WITH_CHECKPOINTS = "autonomous_with_checkpoints"
    FULLY_AUTONOMOUS = "fully_autonomous"


class RequiredTesting(StrEnum):
    NONE = "none"
    UNIT = "unit"
    UNIT_INTEGRATION = "unit_integration"
    FULL_REGRESSION = "full_regression"


class SecurityLevel(StrEnum):
    STANDARD = "standard"
    STRICT = "strict"


class OutputFormat(StrEnum):
    MARKDOWN = "markdown"
    XML_TAGGED = "xml_tagged"


NO_MODIFY = "Do not modify any files."

APPROVAL_GATES: tuple[str, ...] = (
    "destructive or irreversible actions (deleting data, deleting files unrelated to the change, force operations, history rewrites)",
    "any `git push`, merge, or pull-request creation",
    "database migrations or data changes against shared, staging or production databases",
    "changes to credentials, secrets, CI/CD pipelines, deployment or infrastructure configuration",
    "installing, upgrading or removing dependencies",
    "any other high-impact action whose effects reach beyond your local working copy",
)


@dataclass(frozen=True)
class ModeSpec:
    key: PromptMode
    label: str
    description: str
    may_modify_files: bool
    required_sections: tuple[str, ...]
    instructions: tuple[str, ...]
    deliverable: str


MODES: dict[PromptMode, ModeSpec] = {
    PromptMode.INVESTIGATE_ONLY: ModeSpec(
        PromptMode.INVESTIGATE_ONLY,
        "Investigate only",
        "Read-only investigation: gather evidence and describe what is happening. No changes.",
        False,
        _CORE + ("current_behaviour", "reproduction_steps", "root_cause_hypotheses", "related_documentation"),
        (
            NO_MODIFY + " This is a read-only investigation.",
            "Do not run commands that change state: no installs, migrations, commits, or writes to external services.",
            "Read code and run read-only commands or existing tests to gather evidence.",
            "For each hypothesis below, say whether your evidence supports it, rules it out, or is inconclusive.",
        ),
        "An investigation report: observed behaviour, evidence with file:line references you actually opened, "
        "and the status of each hypothesis.",
    ),
    PromptMode.ROOT_CAUSE_ANALYSIS: ModeSpec(
        PromptMode.ROOT_CAUSE_ANALYSIS,
        "Root cause analysis",
        "Find and prove the root cause, then propose fix options without implementing them.",
        False,
        _CORE + ("current_behaviour", "expected_behaviour", "reproduction_steps", "root_cause_hypotheses"),
        (
            NO_MODIFY + " Analyse only; do not implement the fix.",
            "Separate the confirmed root cause (with evidence) from contributing factors and remaining hypotheses.",
            "Propose one to three fix options with trade-offs; do not apply any of them.",
        ),
        "A root-cause report: the cause, the evidence chain that proves it, and fix options with trade-offs.",
    ),
    PromptMode.IMPLEMENTATION_PLAN: ModeSpec(
        PromptMode.IMPLEMENTATION_PLAN,
        "Implementation plan",
        "Produce a reviewed, step-by-step plan for the fix. No changes.",
        False,
        _CORE
        + (
            "expected_behaviour",
            "root_cause_hypotheses",
            "required_implementation",
            "acceptance_criteria",
            "testing_requirements",
        ),
        (
            NO_MODIFY + " Produce a plan for review instead.",
            "List each file to change (only files you confirmed exist, or new files clearly marked as new), the change, and why.",
            "Include the tests to add, migration or rollout concerns, risks, and how to roll back.",
        ),
        "A step-by-step implementation plan that a reviewer can approve before any code is written.",
    ),
    PromptMode.IMPLEMENT_FIX: ModeSpec(
        PromptMode.IMPLEMENT_FIX,
        "Implement fix",
        "Confirm the root cause, implement the smallest correct fix and prove it with tests.",
        True,
        _CORE
        + (
            "expected_behaviour",
            "reproduction_steps",
            "root_cause_hypotheses",
            "required_implementation",
            "acceptance_criteria",
            "testing_requirements",
        ),
        (
            "Confirm the root cause before changing code; if the evidence contradicts every hypothesis, stop and report.",
            "Make the smallest change that fixes the root cause; avoid unrelated refactors.",
            "Add a regression test that fails before the fix and passes after it.",
        ),
        "The fix, its regression test, and a report with the evidence that it works.",
    ),
    PromptMode.SECURITY_HARDEN: ModeSpec(
        PromptMode.SECURITY_HARDEN,
        "Security hardening",
        "Fix the vulnerability and harden the surrounding boundary against bypasses.",
        True,
        _CORE
        + (
            "expected_behaviour",
            "reproduction_steps",
            "root_cause_hypotheses",
            "required_implementation",
            "acceptance_criteria",
            "testing_requirements",
        ),
        (
            "Treat this as security-sensitive work: fail closed, validate input at trust boundaries, never log secrets.",
            "Add adversarial tests for plausible bypasses of this specific issue (encoding and case variants, "
            "path traversal, oversized or malformed input, alternative entry points).",
            "Do not weaken, skip or delete existing security checks or tests to make the build pass.",
        ),
        "The hardened fix, adversarial tests, and a report listing the bypasses you tested.",
    ),
    PromptMode.REFACTOR: ModeSpec(
        PromptMode.REFACTOR,
        "Refactor",
        "Restructure code without changing externally observable behaviour.",
        True,
        _CORE
        + (
            "current_behaviour",
            "expected_behaviour",
            "required_implementation",
            "acceptance_criteria",
            "testing_requirements",
        ),
        (
            "Preserve externally observable behaviour; add characterisation tests first where coverage is missing.",
            "Make no functional changes unless they are listed in the acceptance criteria.",
            "Refactor in small steps that each keep the test suite passing.",
        ),
        "The refactored code with unchanged behaviour, proven by tests that pass before and after.",
    ),
    PromptMode.TEST_AND_VERIFY: ModeSpec(
        PromptMode.TEST_AND_VERIFY,
        "Test and verify",
        "Write or run tests that prove whether the issue is fixed. Production code stays unchanged.",
        True,
        _CORE + ("expected_behaviour", "reproduction_steps", "acceptance_criteria", "testing_requirements"),
        (
            "Limit changes to tests, fixtures and test configuration. Do not change production code.",
            "If a test exposes a defect, report it with the failing test instead of fixing production code.",
            "Run the relevant suites and report the exact commands and pass/fail counts.",
        ),
        "New or updated tests and a verification report with exact commands and results.",
    ),
    PromptMode.FULL_AUTONOMOUS_REMEDIATION: ModeSpec(
        PromptMode.FULL_AUTONOMOUS_REMEDIATION,
        "Full autonomous remediation",
        "Investigate, fix, test and verify end-to-end, stopping only at human-approval gates.",
        True,
        SECTION_KEYS,
        (
            "Work end-to-end: investigate, confirm the root cause, implement, test and verify.",
            "Stop and obtain explicit human approval before: " + "; ".join(APPROVAL_GATES) + ".",
            "Never bypass permission prompts, sandboxing or security controls, even if that blocks progress.",
            "Saying the work is complete is not verification: finish with the evidence described under Verification.",
        ),
        "A verified fix with tests and an evidence report, without having crossed any approval gate unapproved.",
    ),
}


@dataclass(frozen=True)
class PresetSpec:
    key: Preset
    label: str
    instruction_file: str | None
    notes: tuple[str, ...]


PRESETS: dict[Preset, PresetSpec] = {
    Preset.CLAUDE_CODE: PresetSpec(
        Preset.CLAUDE_CODE,
        "Claude Code",
        "CLAUDE.md",
        (
            "Claude Code loads `CLAUDE.md` memory files from the repository automatically; follow the project rules there.",
            "For read-only or planning work you can use plan mode, which explores without editing files.",
            "Respect the permission rules in `.claude/settings.json` (and `.claude/settings.local.json` if present); "
            "do not try to work around denied tools or commands.",
        ),
    ),
    Preset.CODEX: PresetSpec(
        Preset.CODEX,
        "Codex",
        "AGENTS.md",
        (
            "Codex reads `AGENTS.md` files in the repository; follow the instructions there.",
            "Work within the sandbox and approval settings this session was started with; do not try to escalate them.",
        ),
    ),
    Preset.CURSOR: PresetSpec(
        Preset.CURSOR,
        "Cursor",
        ".cursor/rules",
        (
            "Cursor applies project rules from `.cursor/rules`; follow them where they apply to the files you touch.",
        ),
    ),
    Preset.GENERIC: PresetSpec(Preset.GENERIC, "Generic agent", None, ()),
}


AUTONOMY_INSTRUCTIONS: dict[Autonomy, str] = {
    Autonomy.ASK_BEFORE_CHANGES: (
        "Before modifying any file or running a state-changing command, describe the change and wait for confirmation."
    ),
    Autonomy.AUTONOMOUS_WITH_CHECKPOINTS: (
        "Make routine edits without asking, but stop for confirmation at each checkpoint: "
        "(1) root cause confirmed, (2) fix implemented, (3) tests passing."
    ),
    Autonomy.FULLY_AUTONOMOUS: (
        "Proceed without checkpoints. The human-approval gates in this prompt still apply."
    ),
}

DEPTH_INSTRUCTIONS: dict[TechnicalDepth, str] = {
    TechnicalDepth.BRIEF: "Keep your report short: conclusions, evidence references and next steps.",
    TechnicalDepth.STANDARD: "Explain your reasoning where it is not obvious from the evidence.",
    TechnicalDepth.DEEP: "Explain your reasoning in detail, including alternatives you considered and why you ruled them out.",
}

# Evidence volume per depth (findings, events, evidence items per finding, excerpt characters).
DEPTH_LIMITS: dict[TechnicalDepth, dict[str, int]] = {
    TechnicalDepth.BRIEF: {"findings": 3, "events": 5, "evidence": 2, "excerpt": 300, "paths": 3},
    TechnicalDepth.STANDARD: {"findings": 10, "events": 15, "evidence": 4, "excerpt": 800, "paths": 10},
    TechnicalDepth.DEEP: {"findings": 50, "events": 60, "evidence": 10, "excerpt": 2000, "paths": 30},
}

_MAX_CONSTRAINTS = 30
_MAX_CONSTRAINT_CHARS = 500
_MAX_EXTRA_CHARS = 4000


def _enum(cls: type[StrEnum], value: Any, name: str) -> Any:
    try:
        return cls(value)
    except ValueError:
        allowed = ", ".join(m.value for m in cls)  # type: ignore[attr-defined]
        raise ValueError(f"Invalid {name} {value!r}; expected one of: {allowed}") from None


@dataclass
class GenerationOptions:
    technical_depth: TechnicalDepth = TechnicalDepth.STANDARD
    autonomy: Autonomy = Autonomy.ASK_BEFORE_CHANGES
    testing_requirements: RequiredTesting = RequiredTesting.UNIT
    security_requirements: SecurityLevel = SecurityLevel.STANDARD
    output_format: OutputFormat = OutputFormat.MARKDOWN
    constraints: list[str] = field(default_factory=list)
    allow_code_changes: bool = True
    allow_architecture_changes: bool = False
    extra_instructions: str = ""

    def __post_init__(self) -> None:
        self.technical_depth = _enum(TechnicalDepth, self.technical_depth, "technical_depth")
        self.autonomy = _enum(Autonomy, self.autonomy, "autonomy")
        self.testing_requirements = _enum(RequiredTesting, self.testing_requirements, "testing_requirements")
        self.security_requirements = _enum(SecurityLevel, self.security_requirements, "security_requirements")
        self.output_format = _enum(OutputFormat, self.output_format, "output_format")
        if not isinstance(self.constraints, (list, tuple)) or not all(
            isinstance(c, str) for c in self.constraints
        ):
            raise ValueError("constraints must be a list of strings")
        items = [c.strip() for c in self.constraints if c.strip()]
        if len(items) > _MAX_CONSTRAINTS:
            raise ValueError(f"At most {_MAX_CONSTRAINTS} constraints are allowed")
        if any(len(c) > _MAX_CONSTRAINT_CHARS for c in items):
            raise ValueError(f"Each constraint must be at most {_MAX_CONSTRAINT_CHARS} characters")
        self.constraints = items
        for flag in ("allow_code_changes", "allow_architecture_changes"):
            if not isinstance(getattr(self, flag), bool):
                raise ValueError(f"{flag} must be a boolean")
        if not isinstance(self.extra_instructions, str):
            raise ValueError("extra_instructions must be a string")
        if len(self.extra_instructions) > _MAX_EXTRA_CHARS:
            raise ValueError(f"extra_instructions must be at most {_MAX_EXTRA_CHARS} characters")
        self.extra_instructions = self.extra_instructions.strip()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> GenerationOptions:
        data = dict(data or {})
        unknown = sorted(set(data) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError(f"Unknown generation option(s): {', '.join(unknown)}")
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technical_depth": self.technical_depth.value,
            "autonomy": self.autonomy.value,
            "testing_requirements": self.testing_requirements.value,
            "security_requirements": self.security_requirements.value,
            "output_format": self.output_format.value,
            "constraints": list(self.constraints),
            "allow_code_changes": self.allow_code_changes,
            "allow_architecture_changes": self.allow_architecture_changes,
            "extra_instructions": self.extra_instructions,
        }


def get_mode(value: PromptMode | str) -> ModeSpec:
    return MODES[_enum(PromptMode, value, "mode")]


def get_preset(value: Preset | str) -> PresetSpec:
    return PRESETS[_enum(Preset, value, "preset")]


def coerce_options(options: GenerationOptions | Mapping[str, Any] | None) -> GenerationOptions:
    if isinstance(options, GenerationOptions):
        return options
    return GenerationOptions.from_dict(options)


def may_modify_files(mode: ModeSpec, options: GenerationOptions) -> bool:
    """Effective permission: the mode must allow modification AND the requester must not have disabled it."""
    return mode.may_modify_files and options.allow_code_changes


def describe_modes() -> list[dict[str, Any]]:
    """JSON-friendly catalogue for the API/UI (mode pickers, docs)."""
    return [
        {
            "key": spec.key.value,
            "label": spec.label,
            "description": spec.description,
            "may_modify_files": spec.may_modify_files,
            "required_sections": list(spec.required_sections),
            "instructions": list(spec.instructions),
            "deliverable": spec.deliverable,
        }
        for spec in MODES.values()
    ]


def describe_presets() -> list[dict[str, Any]]:
    return [
        {"key": p.key.value, "label": p.label, "instruction_file": p.instruction_file, "notes": list(p.notes)}
        for p in PRESETS.values()
    ]
