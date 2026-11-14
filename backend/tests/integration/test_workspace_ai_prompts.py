"""Engineering Workspace AI: saved prompts (edit, regenerate, export), templates and task breakdown."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.models import AuditEvent, GeneratedPrompt, Task, TaskDependency
from app.workspace.modes import SECTION_KEYS
from tests.integration.ingestion_support import GITHUB_TOKEN
from tests.integration.workspace_ai_support import AI, fix_context, injection_task
from tests.integration.workspace_support import API, activity_kinds, create_task, get_task, ok


@pytest.fixture(autouse=True)
def no_root(monkeypatch):
    monkeypatch.setattr(get_settings(), "workspace_repo_root", None)


def _section(prompt: dict, key: str) -> dict:
    return next(s for s in prompt["sections"] if s["key"] == key)


def _patch(client, headers, prompt_id: str, body: dict, status: int = 200):
    return ok(client.patch(f"{AI}/prompts/{prompt_id}", json=body, headers=headers), status)


def test_saved_prompt_can_be_edited_regenerated_and_exported(client, seeded_org, db):
    task, finding = injection_task(client, seeded_org, db)
    h = seeded_org.user_headers
    saved = fix_context(client, h, task["id"], 201, mode="implement_fix", save=True)
    pid = saved["prompt_id"]
    assert saved["saved"] and saved["version"] == 1 and saved["context_pack"]["task_id"] == task["id"]
    listed = ok(client.get(f"{AI}/prompts", params={"task_id": task["id"]}, headers=h))
    assert listed["total"] == 1 and listed["items"][0]["edited_sections"] == []

    # Edit one section: content is redacted, the section is marked edited, the version increases.
    edited = _patch(
        client,
        h,
        pid,
        {
            "sections": [
                {"key": "task_summary", "content": f"My own summary of the job. Leaked {GITHUB_TOKEN} here."}
            ]
        },
    )
    summary = _section(edited, "task_summary")
    assert edited["version"] == 2 and summary["edited"] is True and "My own summary" in summary["content"]
    assert "My own summary" in edited["content"] and GITHUB_TOKEN not in str(edited)
    db.rollback()
    assert GITHUB_TOKEN not in db.get(GeneratedPrompt, pid).content

    # Invalid edits are refused with plain-language reasons and change nothing.
    for body in (
        {"sections": [{"key": "constraints", "removed": True}]},
        {"sections": [{"key": "verification", "content": "   "}]},
        {"sections": [{"key": "not_a_section", "content": "x"}]},
    ):
        response = client.patch(f"{AI}/prompts/{pid}", json=body, headers=h)
        assert response.status_code == 422, body
        assert response.json()["error"]["details"]["errors"]
    assert ok(client.get(f"{AI}/prompts/{pid}", headers=h))["version"] == 2

    # Optional sections can be removed and brought back by regenerating them.
    removed = _patch(client, h, pid, {"sections": [{"key": "related_documentation", "removed": True}]})
    assert removed["version"] == 3 and "related_documentation" not in [s["key"] for s in removed["sections"]]
    assert "## Related documentation" not in removed["content"]
    back = ok(
        client.post(
            f"{AI}/prompts/{pid}/regenerate-section", json={"section_key": "related_documentation"}, headers=h
        )
    )
    assert back["version"] == 4 and [s["key"] for s in back["sections"]] == list(SECTION_KEYS)

    # Regenerating an edited section rebuilds it from records and clears the edited flag.
    fresh = ok(
        client.post(f"{AI}/prompts/{pid}/regenerate-section", json={"section_key": "task_summary"}, headers=h)
    )
    assert fresh["version"] == 5 and _section(fresh, "task_summary")["edited"] is False
    assert (
        "My own summary" not in fresh["content"] and finding.id in _section(fresh, "task_summary")["content"]
    )
    assert (
        client.post(
            f"{AI}/prompts/{pid}/regenerate-section", json={"section_key": "bogus"}, headers=h
        ).status_code
        == 422
    )

    # Option changes rebuild sections the user has not edited; edited ones are kept as written.
    _patch(
        client,
        h,
        pid,
        {"sections": [{"key": "verification", "content": "Run `make verify` and paste output."}]},
    )
    changed = _patch(
        client,
        h,
        pid,
        {
            "extra_instructions": "Keep the public API stable.",
            "options": {"testing_requirements": "full_regression"},
        },
    )
    assert changed["version"] == 7 and changed["options"]["testing_requirements"] == "full_regression"
    assert "Keep the public API stable." in _section(changed, "constraints")["content"]
    assert _section(changed, "verification")["content"] == "Run `make verify` and paste output."
    assert any("Options changed" in n for n in changed["notes"])
    assert changed["edited_sections"] == ["verification"]
    assert (
        client.patch(f"{AI}/prompts/{pid}", json={"options": {"autonomy": "reckless"}}, headers=h).status_code
        == 422
    )

    # Exports: Markdown attachment identical to the stored prompt, and a structured JSON document.
    md = client.get(f"{AI}/prompts/{pid}/export", params={"format": "markdown"}, headers=h)
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert md.headers["content-disposition"] == f'attachment; filename="{task["key"]}-implement_fix-v7.md"'
    assert md.text == changed["content"]
    js = client.get(f"{AI}/prompts/{pid}/export", params={"format": "json"}, headers=h)
    assert js.status_code == 200 and js.headers["content-type"].startswith("application/json")
    doc = json.loads(js.text)
    assert doc["format"] == "contextos.fix_context" and doc["external_transfer"] is False
    assert doc["prompt"]["version"] == 7 and doc["task"]["key"] == task["key"]
    assert [s["key"] for s in doc["sections"]] == list(SECTION_KEYS) and doc["content"] == changed["content"]
    assert doc["context_pack"]["id"] == saved["context_pack"]["id"] and doc["context_pack"]["items"]
    assert client.get(f"{AI}/prompts/{pid}/export", params={"format": "pdf"}, headers=h).status_code == 422
    db.rollback()
    exports = db.scalars(
        select(AuditEvent).where(
            AuditEvent.organization_id == seeded_org.org_id, AuditEvent.action == "prompt.exported"
        )
    ).all()
    assert len(exports) == 2

    kinds = activity_kinds(get_task(client, h, task["id"]))
    assert {"prompt_generated", "prompt_edited", "prompt_section_regenerated"} <= set(kinds)


def test_templates_crud_and_use(client, seeded_org, db):
    h = seeded_org.user_headers
    builtins = ok(client.get(f"{AI}/templates", headers=h))
    assert len(builtins) == 8 and all(t["is_builtin"] and t["id"].startswith("builtin:") for t in builtins)
    harden = next(t for t in builtins if t["id"] == "builtin:security_harden")
    assert harden["options"]["security_requirements"] == "strict"

    body = {
        "name": "Billing hardening",
        "mode": "security_harden",
        "preset": "claude_code",
        "options": {"technical_depth": "deep", "constraints": ["Do not touch billing/legacy"]},
        "section_overrides": {"constraints": f"Coordinate with the billing team. {GITHUB_TOKEN}"},
    }
    created = ok(client.post(f"{AI}/templates", json=body, headers=h), 201)
    assert created["is_builtin"] is False and created["options"]["technical_depth"] == "deep"
    assert (
        GITHUB_TOKEN not in str(created)
        and "Coordinate with the billing team" in created["section_overrides"]["constraints"]
    )
    for bad, status in [
        ({**body, "name": "billing HARDENING"}, 409),
        ({**body, "name": "Implement fix"}, 409),
        ({**body, "name": "B", "options": {"technical_depth": "extreme"}}, 422),
        ({**body, "name": "C", "options": {"temperature": 0.2}}, 422),
        ({**body, "name": "D", "section_overrides": {"nope": "x"}}, 422),
    ]:
        assert client.post(f"{AI}/templates", json=bad, headers=h).status_code == status, bad

    task, _ = injection_task(client, seeded_org, db)
    out = fix_context(client, h, task["id"], template_id=created["id"])
    assert (
        out["mode"] == "security_harden"
        and out["preset"] == "claude_code"
        and out["template_id"] == created["id"]
    )
    assert out["options"]["technical_depth"] == "deep"
    constraints = _section(out, "constraints")["content"]
    assert "Coordinate with the billing team" in constraints and "Do not touch billing/legacy" in constraints
    assert "Notes for Claude Code" in out["content"]
    override = fix_context(
        client,
        h,
        task["id"],
        template_id=created["id"],
        mode="investigate_only",
        options={"technical_depth": "brief"},
    )
    assert override["mode"] == "investigate_only" and override["options"]["technical_depth"] == "brief"
    assert override["options"]["constraints"] == ["Do not touch billing/legacy"]
    builtin_use = fix_context(client, h, task["id"], template_id="builtin:full_autonomous_remediation")
    assert builtin_use["options"]["testing_requirements"] == "full_regression"

    renamed = ok(
        client.patch(f"{AI}/templates/{created['id']}", json={"name": "Billing hardening v2"}, headers=h)
    )
    assert renamed["name"] == "Billing hardening v2"
    assert client.patch(f"{AI}/templates/builtin:refactor", json={"name": "x"}, headers=h).status_code == 409
    assert client.delete(f"{AI}/templates/builtin:refactor", headers=h).status_code == 409
    assert client.delete(f"{AI}/templates/builtin:nonsense", headers=h).status_code == 404

    saved = fix_context(client, h, task["id"], 201, template_id=created["id"], save=True)
    assert client.delete(f"{AI}/templates/{created['id']}", headers=h).status_code == 204
    assert client.get(f"{AI}/templates/{created['id']}", headers=h).status_code == 404
    assert (
        client.post(
            f"{AI}/fix-context", json={"task_id": task["id"], "template_id": created["id"]}, headers=h
        ).status_code
        == 404
    )
    regenerated = ok(
        client.post(
            f"{AI}/prompts/{saved['prompt_id']}/regenerate-section",
            json={"section_key": "constraints"},
            headers=h,
        )
    )
    assert any("template this prompt used has been deleted" in n for n in regenerated["notes"])
    assert "Coordinate with the billing team" not in _section(regenerated, "constraints")["content"]
    db.rollback()
    actions = set(
        db.scalars(select(AuditEvent.action).where(AuditEvent.organization_id == seeded_org.org_id))
    )
    assert {"prompt_template.created", "prompt_template.updated", "prompt_template.deleted"} <= actions


def _assert_acyclic(edges: list[tuple[str, str]]) -> None:
    graph: dict[str, list[str]] = {}
    for a, b in edges:
        graph.setdefault(a, []).append(b)
    state: dict[str, int] = {}

    def visit(node: str) -> None:
        state[node] = 1
        for nxt in graph.get(node, []):
            assert state.get(nxt) != 1, f"cycle through {nxt}"
            if nxt not in state:
                visit(nxt)
        state[node] = 2

    for node in list(graph):
        if node not in state:
            visit(node)


def test_breakdown_drafts_and_apply_creates_acyclic_subtasks(client, seeded_org, db):
    task, finding = injection_task(client, seeded_org, db)
    h = seeded_org.user_headers
    drafts = ok(client.post(f"{AI}/breakdown", json={"task_id": task["id"]}, headers=h))
    assert drafts["plan"] == "prompt_injection" and drafts["existing_subtasks"] == 0
    assert drafts["external_transfer"] is False and len(drafts["drafts"]) == 5
    assert all(d < i for i, draft in enumerate(drafts["drafts"]) for d in draft["depends_on"])
    assert finding.id in drafts["drafts"][0]["acceptance_criteria"][-1]
    assert (
        ok(client.post(f"{AI}/breakdown", json={"task_id": task["id"], "plan": "bug"}, headers=h))["plan"]
        == "bug"
    )
    assert (
        client.post(f"{AI}/breakdown", json={"task_id": task["id"], "plan": "bogus"}, headers=h).status_code
        == 422
    )

    edited = drafts["drafts"]
    edited[0]["title"] = "Reproduce the README injection in a test"
    applied = ok(
        client.post(f"{AI}/breakdown/apply", json={"task_id": task["id"], "drafts": edited}, headers=h), 201
    )
    created = applied["created"]
    assert len(created) == 5 and applied["parent_task_id"] == task["id"]
    assert all(c["parent_task_id"] == task["id"] for c in created)
    assert created[0]["title"] == "Reproduce the README injection in a test"
    expected = {
        (created[i]["id"], created[d]["id"]) for i, draft in enumerate(edited) for d in draft["depends_on"]
    }
    assert {(d["task_id"], d["depends_on_task_id"]) for d in applied["dependencies"]} == expected
    assert created[1]["blocked_by_open"] >= 1 and created[0]["blocked_by_open"] == 0
    db.rollback()
    ids = [c["id"] for c in created]
    edges = list(
        db.execute(
            select(TaskDependency.task_id, TaskDependency.depends_on_task_id).where(
                TaskDependency.organization_id == seeded_org.org_id, TaskDependency.task_id.in_(ids)
            )
        )
    )
    assert {tuple(e) for e in edges} == expected
    _assert_acyclic([tuple(e) for e in edges])
    first = db.get(Task, created[0]["id"])
    assert "Testing requirements:" in first.description and first.acceptance_criteria[0]["done"] is False

    parent = get_task(client, h, task["id"])
    assert "breakdown_applied" in activity_kinds(parent)
    assert (
        ok(client.post(f"{AI}/breakdown", json={"task_id": task["id"]}, headers=h))["existing_subtasks"] == 5
    )

    # A subtask's prompt includes the records linked to its parent.
    sub_prompt = fix_context(client, h, created[0]["id"], mode="investigate_only")
    assert finding.id in sub_prompt["content"]
    assert any(task["key"] in n and "parent task" in n for n in sub_prompt["notes"])


def test_breakdown_apply_rejects_invalid_dependency_graphs(client, org, db):
    h = org.user_headers
    task = create_task(client, h, "Ship the exporter", task_type="feature")
    for drafts in (
        [{"title": "A", "depends_on": [1]}, {"title": "B", "depends_on": [0]}],
        [{"title": "A", "depends_on": [0]}],
        [{"title": "A", "depends_on": [3]}],
    ):
        response = client.post(
            f"{AI}/breakdown/apply", json={"task_id": task["id"], "drafts": drafts}, headers=h
        )
        assert response.status_code == 422, drafts
        assert response.json()["error"]["details"]["errors"]
    cycle = client.post(
        f"{AI}/breakdown/apply",
        json={
            "task_id": task["id"],
            "drafts": [
                {"title": "A", "depends_on": [2]},
                {"title": "B", "depends_on": [0]},
                {"title": "C", "depends_on": [1]},
            ],
        },
        headers=h,
    )
    assert cycle.json()["error"]["details"]["reason"] == "dependency_cycle"
    db.rollback()
    assert db.scalars(select(Task).where(Task.parent_task_id == task["id"])).first() is None

    # Later drafts may be prerequisites of earlier ones as long as the graph stays acyclic.
    applied = ok(
        client.post(
            f"{AI}/breakdown/apply",
            json={
                "task_id": task["id"],
                "priority": "high",
                "drafts": [
                    {"title": "Release", "depends_on": [1]},
                    {"title": "Build", "task_type": "backend"},
                ],
            },
            headers=h,
        ),
        201,
    )
    assert [c["priority"] for c in applied["created"]] == ["high", "high"]
    assert applied["dependencies"] == [
        {"task_id": applied["created"][0]["id"], "depends_on_task_id": applied["created"][1]["id"]}
    ]
    ok(client.delete(f"{API}/tasks/{task['id']}", headers=h), 204)
    archived = client.post(
        f"{AI}/breakdown/apply", json={"task_id": task["id"], "drafts": [{"title": "x"}]}, headers=h
    )
    assert archived.status_code == 409
