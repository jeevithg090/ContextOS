"""AI fix-context generation: turn a task and its linked security records into a prompt for a coding agent.

Public API (pure; no DB access — the workspace services load and org-scope the records):

    generate_sections(input, mode, preset, options, *, section_overrides=None) -> list[Section]
    regenerate_section(input, key, mode, preset, options, *, section_overrides=None) -> Section
    validate_sections(sections, mode) -> list[str]           # problems, e.g. a removed required section
    render_markdown(sections, mode, preset, options, *, title=None) -> str
    render_json(sections, mode, preset, options, *, title=None) -> dict
    generate_prompt(input, mode, preset, options, ...) -> {"sections": [...], "content": str}

Guarantees: sections come in a fixed order (``SECTION_KEYS``); every section declares its kind
(fact / evidence / assumption / hypothesis / recommendation / instruction) and mixed sections use
sub-headings; only verified context-pack items are presented as verified references; hypotheses
are labelled with confidence words; read-only modes say "Do not modify any files."; all text is
redacted again before it is returned.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from app.workspace import sections_problem as sp
from app.workspace import sections_repo as sr
from app.workspace import sections_work as sw
from app.workspace.fix_input import BuildContext, FixContextInput
from app.workspace.modes import (
    SECTION_KEYS,
    GenerationOptions,
    Preset,
    PromptMode,
    coerce_options,
    get_mode,
    get_preset,
)
from app.workspace.render import render_json, render_markdown
from app.workspace.section import SECTION_TITLES, Parts, Section
from app.workspace.text import clean, quote

__all__ = [
    "SECTION_KEYS",
    "SECTION_TITLES",
    "FixContextInput",
    "GenerationOptions",
    "Preset",
    "PromptMode",
    "Section",
    "generate_prompt",
    "generate_sections",
    "regenerate_section",
    "render_json",
    "render_markdown",
    "validate_sections",
]

Builder = Callable[[BuildContext, Parts], None]

BUILDERS: dict[str, Builder] = {
    "task_summary": sp.task_summary,
    "problem_description": sp.problem_description,
    "current_behaviour": sp.current_behaviour,
    "expected_behaviour": sp.expected_behaviour,
    "reproduction_steps": sp.reproduction_steps,
    "available_evidence": sp.available_evidence,
    "codebase_context": sr.codebase_context,
    "root_cause_hypotheses": sw.root_cause_hypotheses,
    "required_implementation": sw.required_implementation,
    "constraints": sw.constraints,
    "acceptance_criteria": sw.acceptance_criteria,
    "testing_requirements": sw.testing_requirements,
    "verification": sw.verification,
    "related_documentation": sr.related_documentation,
}
assert tuple(BUILDERS) == SECTION_KEYS


def _context(
    data: FixContextInput, mode: Any, preset: Any, options: Any, section_overrides: Mapping[str, str] | None
) -> BuildContext:
    if not isinstance(data, FixContextInput):
        raise ValueError("input must be a FixContextInput")
    overrides = dict(section_overrides or {})
    unknown = sorted(set(overrides) - set(SECTION_KEYS))
    if unknown:
        raise ValueError(f"Unknown section key(s) in overrides: {', '.join(unknown)}")
    return BuildContext(
        data=data,
        mode=get_mode(mode),
        preset=get_preset(preset),
        options=coerce_options(options),
        section_overrides=overrides,
    )


def _build(ctx: BuildContext, key: str) -> Section:
    parts = Parts()
    BUILDERS[key](ctx, parts)
    extra = ctx.section_overrides.get(key)
    if isinstance(extra, str) and extra.strip():
        parts.add(
            "instruction", quote(clean(extra, limit=2000)), title="Additional instructions from the template"
        )
    section = parts.build(key, required=key in ctx.mode.required_sections)
    section.content = clean(section.content, limit=len(section.content) + 1)  # defence in depth
    return section


def generate_sections(
    data: FixContextInput,
    mode: PromptMode | str,
    preset: Preset | str = Preset.GENERIC,
    options: GenerationOptions | Mapping[str, Any] | None = None,
    *,
    section_overrides: Mapping[str, str] | None = None,
) -> list[Section]:
    """All 14 sections in canonical order. Sections a mode does not require are still produced (with
    mode-appropriate content) and marked ``required=False`` so the UI can let users drop them."""
    ctx = _context(data, mode, preset, options, section_overrides)
    return [_build(ctx, key) for key in SECTION_KEYS]


def regenerate_section(
    data: FixContextInput,
    key: str,
    mode: PromptMode | str,
    preset: Preset | str = Preset.GENERIC,
    options: GenerationOptions | Mapping[str, Any] | None = None,
    *,
    section_overrides: Mapping[str, str] | None = None,
) -> Section:
    if key not in BUILDERS:
        raise ValueError(f"Unknown section {key!r}; expected one of: {', '.join(SECTION_KEYS)}")
    return _build(_context(data, mode, preset, options, section_overrides), key)


def validate_sections(sections: Sequence[Section | Mapping[str, Any]], mode: PromptMode | str) -> list[str]:
    """Plain-language problems with an (edited) section list for ``mode``; empty when valid."""
    spec = get_mode(mode)
    problems: list[str] = []
    keys: list[str] = []
    for raw in sections:
        try:
            section = raw if isinstance(raw, Section) else Section.from_dict(raw)
        except ValueError as exc:
            problems.append(str(exc))
            continue
        if section.key not in SECTION_TITLES:
            problems.append(f"Unknown section {section.key!r}.")
        elif section.key in keys:
            problems.append(f"Section {section.key!r} appears more than once.")
        elif not section.content.strip():
            problems.append(f"Section '{section.title}' is empty.")
        keys.append(section.key)
    for key in spec.required_sections:
        if key not in keys:
            problems.append(f"The '{spec.label}' mode requires the section '{SECTION_TITLES[key]}'.")
    return problems


def generate_prompt(
    data: FixContextInput,
    mode: PromptMode | str,
    preset: Preset | str = Preset.GENERIC,
    options: GenerationOptions | Mapping[str, Any] | None = None,
    *,
    section_overrides: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Convenience: sections (as dicts) plus the rendered prompt in the requested output format."""
    opts = coerce_options(options)
    sections = generate_sections(data, mode, preset, opts, section_overrides=section_overrides)
    title = data.task.get("title") if isinstance(data.task.get("title"), str) else None
    return {
        "sections": [s.to_dict() for s in sections],
        "content": render_markdown(sections, mode, preset, opts, title=title),
    }
