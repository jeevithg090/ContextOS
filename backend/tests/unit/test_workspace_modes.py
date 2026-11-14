"""Prompt modes, presets and generation options."""

from __future__ import annotations

import json

import pytest

from app.workspace.modes import (
    MODES,
    PRESETS,
    SECTION_KEYS,
    GenerationOptions,
    Preset,
    PromptMode,
    coerce_options,
    describe_modes,
    describe_presets,
    get_mode,
    get_preset,
    may_modify_files,
)

READ_ONLY = {PromptMode.INVESTIGATE_ONLY, PromptMode.ROOT_CAUSE_ANALYSIS, PromptMode.IMPLEMENTATION_PLAN}


def test_every_mode_is_specified_with_valid_required_sections():
    assert set(MODES) == set(PromptMode)
    for spec in MODES.values():
        assert spec.label and spec.description and spec.deliverable and spec.instructions
        assert set(spec.required_sections) <= set(SECTION_KEYS)
        assert "task_summary" in spec.required_sections
    assert MODES[PromptMode.FULL_AUTONOMOUS_REMEDIATION].required_sections == SECTION_KEYS


def test_read_only_modes_forbid_modification():
    for key, spec in MODES.items():
        assert spec.may_modify_files is (key not in READ_ONLY)
        if key in READ_ONLY:
            assert any("Do not modify any files" in i for i in spec.instructions)


def test_full_autonomous_mode_requires_human_approval_for_high_impact_actions():
    text = " ".join(MODES[PromptMode.FULL_AUTONOMOUS_REMEDIATION].instructions)
    assert "human approval" in text
    for needle in ("git push", "migrations", "destructive"):
        assert needle in text


def test_preset_notes_are_product_specific_and_generic_has_none():
    claude = " ".join(PRESETS[Preset.CLAUDE_CODE].notes)
    assert "CLAUDE.md" in claude and "plan mode" in claude and ".claude/settings" in claude
    codex = " ".join(PRESETS[Preset.CODEX].notes)
    assert "AGENTS.md" in codex and "CLAUDE.md" not in codex and "plan mode" not in codex
    cursor = " ".join(PRESETS[Preset.CURSOR].notes)
    assert ".cursor/rules" in cursor and "AGENTS.md" not in cursor
    assert PRESETS[Preset.GENERIC].notes == ()
    assert PRESETS[Preset.GENERIC].instruction_file is None


def test_generation_options_defaults_roundtrip_and_validation():
    opts = GenerationOptions()
    assert GenerationOptions.from_dict(opts.to_dict()) == opts
    custom = GenerationOptions.from_dict(
        {"technical_depth": "deep", "constraints": [" keep API ", ""], "output_format": "xml_tagged"}
    )
    assert custom.constraints == ["keep API"]
    assert custom.to_dict()["output_format"] == "xml_tagged"
    with pytest.raises(ValueError, match="technical_depth"):
        GenerationOptions.from_dict({"technical_depth": "extreme"})
    with pytest.raises(ValueError, match="Unknown generation option"):
        GenerationOptions.from_dict({"temperature": 1})
    with pytest.raises(ValueError):
        GenerationOptions.from_dict({"allow_code_changes": "yes"})
    with pytest.raises(ValueError):
        GenerationOptions.from_dict({"constraints": ["x" * 501]})
    with pytest.raises(ValueError):
        GenerationOptions.from_dict({"extra_instructions": "x" * 4001})


def test_effective_modification_permission_and_lookup_helpers():
    no_changes = GenerationOptions(allow_code_changes=False)
    assert may_modify_files(get_mode("implement_fix"), GenerationOptions()) is True
    assert may_modify_files(get_mode("implement_fix"), no_changes) is False
    assert may_modify_files(get_mode("investigate_only"), GenerationOptions(allow_code_changes=True)) is False
    assert get_preset("cursor").label == "Cursor"
    assert coerce_options(None) == GenerationOptions()
    with pytest.raises(ValueError, match="mode"):
        get_mode("yolo")
    with pytest.raises(ValueError, match="preset"):
        get_preset("copilot")
    json.dumps(describe_modes())
    json.dumps(describe_presets())
