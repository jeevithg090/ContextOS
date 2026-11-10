"""Deterministic task breakdown into subtask drafts."""

from __future__ import annotations

import pytest

from app.workspace.breakdown import PLAN_KEYS, SubtaskDraft, choose_plan, decompose


def _acyclic(drafts: list[SubtaskDraft]) -> bool:
    return all(all(0 <= d < i for d in draft.depends_on) for i, draft in enumerate(drafts))


@pytest.mark.parametrize("plan", PLAN_KEYS)
def test_every_plan_has_acyclic_dependencies_and_parent_title(plan):
    drafts = decompose({"title": "Fix the thing", "task_type": "task"}, plan=plan)
    assert len(drafts) >= 4
    assert _acyclic(drafts)
    for d in drafts:
        assert "Fix the thing" in d.title
        assert d.description and d.acceptance_criteria
        assert set(d.to_dict()) == {"title", "description", "task_type", "acceptance_criteria",
                                    "testing_requirements", "depends_on"}


def test_security_vulnerability_follows_reproduce_rootcause_fix_tests_docs_order():
    drafts = decompose({"title": "Token leak in logs", "task_type": "security_vulnerability",
                        "related_finding_id": "fnd_123"})
    titles = [d.title for d in drafts]
    assert titles[0].startswith("Reproduce with a failing test")
    assert titles[1].startswith("Identify root cause")
    assert titles[2].startswith("Implement fix")
    assert titles[3].startswith("Add regression tests")
    assert titles[4].startswith("Add adversarial security tests")
    assert titles[5].startswith("Document and verify")
    assert drafts[5].depends_on == [3, 4]
    assert any("fnd_123" in c for c in drafts[0].acceptance_criteria)
    assert drafts[0].task_type == "security_vulnerability"


@pytest.mark.parametrize(
    ("task", "plan"),
    [
        ({"title": "MCP gateway does not intercept tools/call", "task_type": "security_vulnerability"}, "mcp_interception"),
        ({"title": "Bypass", "description": "Requests skip the MCP proxy", "task_type": "integration_bug"},
         "mcp_interception"),
        ({"title": "README injection", "task_type": "prompt_injection"}, "prompt_injection"),
        ({"title": "Vuln", "task_type": "security_vulnerability", "category": "secret_exposure"}, "data_exposure"),
        ({"title": "Vuln", "task_type": "security_vulnerability"}, "security_vulnerability"),
        ({"title": "Slow list", "task_type": "performance"}, "performance"),
        ({"title": "Dark mode", "task_type": "feature"}, "feature"),
        ({"title": "Old code", "task_type": "tech_debt"}, "tech_debt"),
        ({"title": "Hook payload rejected", "task_type": "integration_bug"}, "integration_bug"),
        ({"title": "Tidy", "task_type": "task"}, "generic"),
        ({"title": "Tidy", "task_type": "something_new"}, "generic"),
    ],
)
def test_plan_selection(task, plan):
    assert choose_plan(task) == plan


def test_mcp_plan_covers_fail_closed_and_honest_enforcement_docs():
    drafts = decompose({"title": "MCP gateway bypass", "task_type": "security_vulnerability"})
    text = " ".join(d.title + " " + d.description + " ".join(d.acceptance_criteria) for d in drafts)
    assert "Fail closed" in text and "fail_closed" in text
    assert "'enforced'" in text
    assert _acyclic(drafts)


def test_breakdown_is_deterministic_truncates_titles_and_redacts():
    task = {"title": "Leak of ghp_R8xk2LmQ9vTz4WcY7pJn3HbFd6SaEu1Go0Ki " + "x" * 300, "task_type": "data_exposure"}
    first = [d.to_dict() for d in decompose(task)]
    assert first == [d.to_dict() for d in decompose(task)]
    assert all("ghp_R8xk2" not in d["title"] for d in first)
    assert all(len(d["title"]) < 200 for d in first)


def test_breakdown_rejects_unknown_plan_and_non_mapping():
    with pytest.raises(ValueError):
        decompose({"title": "x"}, plan="moonshot")
    with pytest.raises(ValueError):
        decompose(["not", "a", "task"])  # type: ignore[arg-type]
