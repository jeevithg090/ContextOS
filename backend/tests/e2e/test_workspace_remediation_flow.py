"""Engineering Workspace, end to end: a security finding becomes a verified fix.

Part XIX's final requirement, driven through the HTTP API in one flow: a real prompt injection is
detected by the pipeline, the finding becomes a remediation task that references (not copies) the
evidence, a fix-context prompt is generated, edited and exported, a coding agent's fix attempt is
tracked, a claim of completion alone verifies nothing, and only a passing verification run lets the
task close, after which analytics and the remediation pipeline report it from the stored records.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.models import AuditEvent, GeneratedPrompt, SecurityFinding, Task
from app.workspace.modes import NO_MODIFY, SECTION_KEYS
from tests.integration.ingestion_support import GITHUB_TOKEN, run_tool
from tests.integration.workspace_ai_support import AI, MALICIOUS_README, fix_context
from tests.integration.workspace_support import API, activity_kinds, board_by_name, column, get_task, move, ok


@pytest.fixture(autouse=True)
def no_repo_root(monkeypatch):
    monkeypatch.setattr(get_settings(), "workspace_repo_root", None)


def _remediation_row(client, headers, finding_id: str) -> dict:
    page = ok(client.get(f"{API}/analytics/remediation", params={"limit": 200}, headers=headers))
    return next(i for i in page["items"] if i["finding_id"] == finding_id)


def test_finding_to_verified_fix(client, seeded_org, db):
    h = seeded_org.user_headers

    # 1. Discover: the pipeline detects an injected instruction in a README a coding agent read.
    run_tool(
        client, seeded_org.api_headers, "Read", {"file_path": "/work/billing/README.md"}, MALICIOUS_README
    )
    db.rollback()
    finding = db.scalars(
        select(SecurityFinding).where(
            SecurityFinding.organization_id == seeded_org.org_id,
            SecurityFinding.category == "instruction_override",
        )
    ).one()
    assert _remediation_row(client, h, finding.id)["state"] == "no_task"

    # 2. Create the task from the finding: it links to the original records instead of copying them.
    task = ok(client.post(f"{API}/tasks/from-finding", json={"finding_id": finding.id}, headers=h), 201)[
        "task"
    ]
    refs = {r["ref_type"] for r in task["refs"]}
    assert {"finding", "session", "agent", "source", "tool_invocation"} <= refs
    assert all(r["exists"] for r in task["refs"]) and task["related_finding_id"] == finding.id
    assert _remediation_row(client, h, finding.id)["state"] == "task_open"

    # 3. Understand and plan: an investigate-only prompt forbids changes; the implement prompt is saved.
    investigate = fix_context(client, h, task["id"], mode="investigate_only")
    assert investigate["may_modify_files"] is False and NO_MODIFY in investigate["content"]
    assert investigate["external_transfer"] is False and investigate["prompt_id"] is None
    implement = fix_context(client, h, task["id"], 201, mode="implement_fix", preset="claude_code", save=True)
    assert implement["may_modify_files"] is True and implement["saved"] is True
    assert [s["key"] for s in implement["sections"]] == list(SECTION_KEYS)  # all 14 sections
    assert finding.id in implement["content"] and implement["context_pack"]["task_id"] == task["id"]
    assert GITHUB_TOKEN not in str(investigate) + str(implement)

    # 4. Review before handing it to a coding agent: edit, then export exactly what was reviewed.
    pid = implement["prompt_id"]
    edited = ok(
        client.patch(
            f"{AI}/prompts/{pid}", json={"extra_instructions": "Keep the loader's public API."}, headers=h
        )
    )
    assert edited["version"] == 2 and "Keep the loader's public API." in edited["content"]
    exported = client.get(f"{AI}/prompts/{pid}/export", params={"format": "markdown"}, headers=h)
    assert exported.status_code == 200 and exported.text == edited["content"]

    # 5. Track the implementation: the coding agent's branch and PR are linked to the task.
    board = board_by_name(client, h, "Security Remediation")
    ok(move(client, h, task["id"], column(board, "In Progress")["id"]))
    attempt = ok(
        client.post(
            f"{API}/tasks/{task['id']}/fix-attempts",
            json={
                "agent_tool": "claude_code",
                "status": "in_progress",
                "branch": "fix/readme-injection",
                "pr_url": "https://git.example.test/acme/billing/pull/42",
                "generated_prompt_id": pid,
            },
            headers=h,
        ),
        201,
    )
    assert attempt["generated_prompt_id"] == pid  # the attempt records which reviewed prompt was used

    # 6. The agent says it is done. A claim verifies nothing and the task cannot be closed yet.
    claimed = ok(
        client.patch(
            f"{API}/tasks/fix-attempts/{attempt['id']}", json={"status": "claimed_complete"}, headers=h
        )
    )
    assert claimed["is_claim_only"] is True
    detail = get_task(client, h, task["id"])
    assert detail["verification_status"] == "unverified" and detail["is_done"] is False
    assert move(client, h, task["id"], column(board, "Verified")["id"]).status_code == 409
    assert _remediation_row(client, h, finding.id)["state"] == "task_open"

    # 7. Verify with evidence, then close the task.
    run = ok(
        client.post(
            f"{API}/tasks/{task['id']}/verifications",
            json={
                "kind": "test_run",
                "status": "passed",
                "summary": "Regression test for the README injection passes",
                "fix_attempt_id": attempt["id"],
                "command": "pytest -q tests/test_loader.py",
                "evidence": {"tests_passed": 12, "tests_failed": 0},
            },
            headers=h,
        ),
        201,
    )
    assert run["task_verification_status"] == "passed"
    ok(move(client, h, task["id"], column(board, "Verified")["id"]))
    ok(move(client, h, task["id"], column(board, "Done")["id"]))
    done = get_task(client, h, task["id"])
    assert done["is_done"] is True and done["verification_status"] == "passed"
    assert done["fix_attempts"][0]["status"] == "verified"
    assert [p["url"] for p in done["links"]["pull_request"]] == [
        "https://git.example.test/acme/billing/pull/42"
    ]

    # 8. Report from stored records: the finding reads as verified and counts towards completion.
    row = _remediation_row(client, h, finding.id)
    assert row["state"] == "verified" and row["task"]["id"] == task["id"]
    analytics = ok(client.get(f"{API}/analytics", headers=h))
    assert analytics["remediation_completion_rate"]["numerator"] >= 1
    assert analytics["outstanding_critical"]["tasks"] == 0 or all(
        i.get("task", {}).get("id") != task["id"] for i in analytics["outstanding_critical"]["items"]
    )

    # The whole chain is in the task's history and the audit log; the raw credential is nowhere.
    kinds = set(activity_kinds(done))
    assert {
        "created_from_finding",
        "prompt_generated",
        "prompt_edited",
        "moved",
        "fix_attempt_created",
        "fix_attempt_updated",
        "verification",
    } <= kinds, kinds
    db.rollback()
    actions = set(
        db.scalars(select(AuditEvent.action).where(AuditEvent.organization_id == seeded_org.org_id))
    )
    assert {"task.created", "prompt.exported"} <= actions, actions
    assert GITHUB_TOKEN not in db.get(Task, task["id"]).description
    assert GITHUB_TOKEN not in db.get(GeneratedPrompt, pid).content
