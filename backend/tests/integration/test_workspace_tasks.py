"""Engineering Workspace tasks: create/update/move, workflow gates, automation, dependencies, subtasks,
labels, assignees, comments, filters, isolation and permissions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.domain.enums import Role
from app.models import AuditEvent, Task, TaskComment
from app.services.notify import _KEY as PENDING_NOTIFICATIONS
from app.services.workspace_tasks import create_task as create_task_service
from app.services.workspace_tasks_common import Actor
from tests.integration.ingestion_support import GITHUB_TOKEN
from tests.integration.workspace_support import (
    API,
    activity_kinds,
    add_member,
    board_by_name,
    column,
    create_task,
    get_task,
    move,
    ok,
    verify,
)


def test_create_task_numbers_defaults_and_redaction(client, org, db):
    first = create_task(client, org.user_headers, "Rotate credentials",
                        description=f"Leaked token {GITHUB_TOKEN} in CI logs", related_files=["ci/deploy.sh"])
    second = create_task(client, org.user_headers, "Second")
    assert (first["key"], second["key"]) == ("CTX-1", "CTX-2")
    assert first["board_name"] == "Engineering" and first["column_name"] == "Backlog"
    assert (first["position"], second["position"]) == (0.0, 1.0)
    assert first["priority"] == "medium" and first["task_type"] == "task" and first["verification_status"] == "unverified"
    assert GITHUB_TOKEN not in first["description"] and "[REDACTED:" in first["description"]
    assert first["reporter"]["id"] == org.user_id and first["related_files"] == ["ci/deploy.sh"]
    db.rollback()
    stored = db.get(Task, first["id"])
    assert GITHUB_TOKEN not in stored.description
    assert db.scalar(select(AuditEvent).where(AuditEvent.organization_id == org.org_id,
                                              AuditEvent.action == "task.created", AuditEvent.target_id == first["id"]))
    unknown_board = client.post(f"{API}/tasks", json={"title": "x", "board_id": "brd_nope"}, headers=org.user_headers)
    assert unknown_board.status_code == 404


def test_service_mutations_queue_task_notifications(db, org):
    actor = Actor(org_id=org.org_id, type="user", id=org.user_id, user_id=org.user_id)
    task = create_task_service(db, actor, title="Via service")
    pending = db.info.get(PENDING_NOTIFICATIONS, [])
    assert (org.org_id, {"type": "task.updated", "id": task.id, "board_id": task.board_id}) in pending
    db.commit()


def test_update_records_one_activity_per_changed_field(client, org):
    task = create_task(client, org.user_headers)
    due = (datetime.now(UTC) + timedelta(days=3)).isoformat()
    updated = ok(client.patch(f"{API}/tasks/{task['id']}", json={
        "title": "Fix the thing properly", "priority": "urgent", "due_date": due, "severity": "high",
        "acceptance_criteria": [{"text": "Tests pass"}], "description": task["description"],
    }, headers=org.user_headers))
    changes = {a["details"]["field"]: a for a in updated["activity"] if a["kind"] == "updated"}
    assert set(changes) == {"title", "priority", "due_date", "severity", "acceptance_criteria"}
    assert changes["priority"]["from_value"] == "medium" and changes["priority"]["to_value"] == "urgent"
    assert changes["title"]["from_value"] == "Fix the thing"
    assert changes["acceptance_criteria"]["to_value"] == "1 criteria (0 done)"
    assert all(a["actor"]["id"] == org.user_id for a in changes.values())
    unknown = client.patch(f"{API}/tasks/{task['id']}", json={"status": "done"}, headers=org.user_headers)
    assert unknown.status_code == 422


def test_move_respects_wip_limits_with_explicit_override(client, org):
    board = board_by_name(client, org.user_headers, "Engineering")
    progress = column(board, "In Progress")
    ok(client.patch(f"{API}/boards/{board['id']}/columns/{progress['id']}", json={"wip_limit": 1},
                    headers=org.user_headers))
    a, b = create_task(client, org.user_headers, "A"), create_task(client, org.user_headers, "B")
    ok(move(client, org.user_headers, a["id"], progress["id"]))
    refused = move(client, org.user_headers, b["id"], progress["id"])
    assert refused.status_code == 409
    error = refused.json()["error"]
    assert error["details"]["reason"] == "wip_limit_exceeded" and "WIP limit of 1" in error["message"]
    card = ok(move(client, org.user_headers, b["id"], progress["id"], override_wip=True))
    assert card["column_id"] == progress["id"]
    moved = next(x for x in get_task(client, org.user_headers, b["id"])["activity"] if x["kind"] == "moved")
    assert moved["details"]["wip_override"] is True and moved["to_value"] == "In Progress"
    after = column(ok(client.get(f"{API}/boards/{board['id']}", headers=org.user_headers)), "In Progress")
    assert after["task_count"] == 2 and after["wip_exceeded"] is True
    # Reordering inside the same column is never blocked by its own WIP limit.
    reordered = ok(move(client, org.user_headers, b["id"], progress["id"], position=0))
    assert reordered["position"] == 0.0


def test_verification_gate_done_transitions_and_reopen(client, org):
    board = board_by_name(client, org.user_headers, "Security Remediation")
    verified, done, testing = column(board, "Verified"), column(board, "Done"), column(board, "Testing")
    task = create_task(client, org.user_headers, "Patch injection", board_id=board["id"])
    assert task["column_name"] == "Triage"

    gated = move(client, org.user_headers, task["id"], verified["id"])
    assert gated.status_code == 409
    assert "needs passed verification evidence" in gated.json()["error"]["message"]
    assert gated.json()["error"]["details"]["reason"] == "verification_required"
    downstream = move(client, org.user_headers, task["id"], done["id"])
    assert downstream.status_code == 409 and "comes after the verification gate" in downstream.json()["error"]["message"]
    direct = client.post(f"{API}/tasks", json={"title": "x", "column_id": verified["id"]}, headers=org.user_headers)
    assert direct.status_code == 409

    run = verify(client, org.user_headers, task["id"], "passed")
    assert run["task_verification_status"] == "passed"
    ok(move(client, org.user_headers, task["id"], verified["id"]))
    finished = ok(move(client, org.user_headers, task["id"], done["id"]))
    assert finished["is_done"] is True and finished["completed_at"] is not None
    reopened = ok(move(client, org.user_headers, task["id"], testing["id"]))
    assert reopened["completed_at"] is None
    assert get_task(client, org.user_headers, task["id"])["reopened_count"] == 1


def test_done_column_that_requires_verification(client, org):
    board = board_by_name(client, org.user_headers, "Engineering")
    done = column(board, "Done")
    ok(client.patch(f"{API}/boards/{board['id']}/columns/{done['id']}", json={"requires_verification": True},
                    headers=org.user_headers))
    task = create_task(client, org.user_headers)
    blocked = move(client, org.user_headers, task["id"], done["id"])
    assert blocked.status_code == 409 and "'Done' requires it" in blocked.json()["error"]["message"]
    verify(client, org.user_headers, task["id"], "failed")
    assert move(client, org.user_headers, task["id"], done["id"]).status_code == 409
    verify(client, org.user_headers, task["id"], "passed")
    assert ok(move(client, org.user_headers, task["id"], done["id"]))["is_done"] is True


def test_automation_rules_fire_and_never_bypass_gates(client, org):
    board = board_by_name(client, org.user_headers, "Security Remediation")
    progress, review, testing, verified = (column(board, n) for n in ("In Progress", "Review", "Testing", "Verified"))
    cols = f"{API}/boards/{board['id']}/columns"
    ok(client.patch(f"{cols}/{progress['id']}", json={
        "automation": [{"trigger": "pr_linked", "move_to_column_id": review["id"]}]}, headers=org.user_headers))
    ok(client.patch(f"{cols}/{testing['id']}", json={"automation": [
        {"trigger": "fix_attempt_started", "move_to_column_id": verified["id"]},
        {"trigger": "verification_passed", "move_to_column_id": verified["id"]},
    ]}, headers=org.user_headers))
    task = create_task(client, org.user_headers, board_id=board["id"], column_id=progress["id"])

    ok(client.post(f"{API}/tasks/{task['id']}/links", json={"kind": "pull_request",
                                                           "url": "https://github.com/acme/app/pull/7"},
                   headers=org.user_headers), 201)
    detail = get_task(client, org.user_headers, task["id"])
    assert detail["column_name"] == "Review"
    auto = next(a for a in detail["activity"] if a["kind"] == "automation")
    assert auto["actor"] is None and auto["details"]["trigger"] == "pr_linked"
    assert (auto["from_value"], auto["to_value"]) == ("In Progress", "Review")

    ok(move(client, org.user_headers, task["id"], testing["id"]))
    ok(client.post(f"{API}/tasks/{task['id']}/fix-attempts", json={"status": "in_progress"},
                   headers=org.user_headers), 201)
    detail = get_task(client, org.user_headers, task["id"])
    assert detail["column_name"] == "Testing"  # the gate held: started work is not verification
    skipped = next(a for a in detail["activity"] if a["kind"] == "automation_skipped")
    assert skipped["actor"] is None and "verification evidence" in skipped["details"]["reason"]

    verify(client, org.user_headers, task["id"], "passed")
    assert get_task(client, org.user_headers, task["id"])["column_name"] == "Verified"


def test_dependencies_reject_cycles(client, org):
    a, b, c = (create_task(client, org.user_headers, n) for n in ("A", "B", "C"))

    def depend(x, y, kind="blocks"):
        return client.post(f"{API}/tasks/{x['id']}/dependencies", json={"depends_on_task_id": y["id"], "kind": kind},
                           headers=org.user_headers)

    dep_ab = ok(depend(a, b), 201)
    assert dep_ab["task"]["id"] == b["id"]
    ok(depend(b, c), 201)
    cycle = depend(c, a)
    assert cycle.status_code == 409
    assert cycle.json()["error"]["details"]["reason"] == "dependency_cycle"
    assert "CTX-3 → CTX-1 → CTX-2 → CTX-3" in cycle.json()["error"]["message"]
    assert depend(a, a).status_code == 422
    assert depend(a, b).status_code == 409  # already linked
    ok(depend(c, a, "relates_to"), 201)  # non-blocking relations may point "backwards"
    assert depend(a, c, "relates_to").status_code == 409  # symmetric duplicate

    detail = get_task(client, org.user_headers, a["id"])
    assert detail["blocked_by_open"] == 1
    assert [d["task"]["key"] for d in detail["blocked_by"]] == ["CTX-2"]
    assert {d["task"]["key"] for d in detail["blocking"]} == {"CTX-3"}
    ok(client.delete(f"{API}/tasks/dependencies/{dep_ab['id']}", headers=org.user_headers), 204)
    assert get_task(client, org.user_headers, a["id"])["blocked_by_open"] == 0


def test_subtasks_and_parent_cycles(client, org):
    parent = create_task(client, org.user_headers, "Parent")
    child = create_task(client, org.user_headers, "Child", parent_task_id=parent["id"])
    grandchild = create_task(client, org.user_headers, "Grandchild", parent_task_id=child["id"])
    detail = get_task(client, org.user_headers, parent["id"])
    assert detail["subtasks_total"] == 1 and [s["id"] for s in detail["subtasks"]] == [child["id"]]
    assert get_task(client, org.user_headers, child["id"])["parent"]["id"] == parent["id"]
    cycle = client.patch(f"{API}/tasks/{parent['id']}", json={"parent_task_id": grandchild["id"]},
                         headers=org.user_headers)
    assert cycle.status_code == 409 and cycle.json()["error"]["details"]["reason"] == "parent_cycle"
    itself = client.patch(f"{API}/tasks/{parent['id']}", json={"parent_task_id": parent["id"]}, headers=org.user_headers)
    assert itself.status_code == 422
    listed = ok(client.get(f"{API}/tasks?parent_task_id={child['id']}", headers=org.user_headers))
    assert [t["id"] for t in listed["items"]] == [grandchild["id"]]
    detached = ok(client.patch(f"{API}/tasks/{child['id']}", json={"parent_task_id": None}, headers=org.user_headers))
    assert detached["parent"] is None


def test_labels_and_assignees(client, org, other_org, db):
    label = ok(client.post(f"{API}/tasks/labels", json={"name": "security", "color": "high"},
                           headers=org.user_headers), 201)
    duplicate = client.post(f"{API}/tasks/labels", json={"name": "Security"}, headers=org.user_headers)
    assert duplicate.status_code == 409
    assert client.post(f"{API}/tasks/labels", json={"name": "x", "color": "neon"}, headers=org.user_headers).status_code == 422
    task = create_task(client, org.user_headers, label_ids=[label["id"]])
    other = create_task(client, org.user_headers, "Unlabelled")
    assert [lb["name"] for lb in task["labels"]] == ["security"]
    by_name = ok(client.get(f"{API}/tasks?label=SECURITY", headers=org.user_headers))["items"]
    assert [t["id"] for t in by_name] == [task["id"]]
    usage = ok(client.get(f"{API}/tasks/labels", headers=org.user_headers))
    assert usage == [{**label, "task_count": 1, "created_at": usage[0]["created_at"]}]

    dev_id, _ = add_member(db, org.org_id, Role.DEVELOPER.value, "Dev")
    assignees = ok(client.put(f"{API}/tasks/{task['id']}/assignees", json={"assignees": [
        {"user_id": org.user_id}, {"user_id": dev_id, "role": "reviewer"}]}, headers=org.user_headers))
    assert {(a["user_id"], a["role"]) for a in assignees} == {(org.user_id, "assignee"), (dev_id, "reviewer")}
    outsider = client.put(f"{API}/tasks/{task['id']}/assignees", json={"assignees": [{"user_id": other_org.user_id}]},
                          headers=org.user_headers)
    assert outsider.status_code == 422 and "not a member" in outsider.json()["error"]["message"]
    mine = ok(client.get(f"{API}/tasks?assignee=me", headers=org.user_headers))["items"]
    assert [t["id"] for t in mine] == [task["id"]] and other["id"] not in [t["id"] for t in mine]
    assert "assignees_changed" in activity_kinds(get_task(client, org.user_headers, task["id"]))
    cleared = ok(client.patch(f"{API}/tasks/{task['id']}", json={"label_ids": []}, headers=org.user_headers))
    assert cleared["labels"] == [] and "labels_changed" in activity_kinds(cleared)


def test_comments_author_edit_and_delete(client, org, db):
    task = create_task(client, org.user_headers)
    _, dev = add_member(db, org.org_id, Role.DEVELOPER.value, "Dev")
    mine = ok(client.post(f"{API}/tasks/{task['id']}/comments", json={"body": f"token {GITHUB_TOKEN}"},
                          headers=org.user_headers), 201)
    assert GITHUB_TOKEN not in mine["body"] and mine["author"]["id"] == org.user_id
    theirs = ok(client.post(f"{API}/tasks/{task['id']}/comments", json={"body": "LGTM"}, headers=dev), 201)

    assert client.patch(f"{API}/tasks/comments/{mine['id']}", json={"body": "edited"}, headers=dev).status_code == 403
    edited = ok(client.patch(f"{API}/tasks/comments/{mine['id']}", json={"body": "edited"}, headers=org.user_headers))
    assert edited["body"] == "edited" and edited["edited_at"] is not None
    assert client.delete(f"{API}/tasks/comments/{mine['id']}", headers=dev).status_code == 403
    ok(client.delete(f"{API}/tasks/comments/{theirs['id']}", headers=org.user_headers), 204)  # admin moderation
    detail = get_task(client, org.user_headers, task["id"])
    assert [c["id"] for c in detail["comments"]] == [mine["id"]]
    assert {"commented", "comment_edited", "comment_deleted"} <= set(activity_kinds(detail))
    db.rollback()
    assert all(GITHUB_TOKEN not in c.body for c in db.scalars(select(TaskComment)))


def test_list_filters_search_and_sorting(client, org):
    board = board_by_name(client, org.user_headers, "Engineering")
    done = column(board, "Done")
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    late = create_task(client, org.user_headers, "Overdue migration", due_date=past, priority="low")
    urgent = create_task(client, org.user_headers, "Hotfix login", priority="urgent", task_type="backend")
    shipped = create_task(client, org.user_headers, "Shipped already")
    ok(move(client, org.user_headers, shipped["id"], done["id"]))

    def ids(query):
        return [t["id"] for t in ok(client.get(f"{API}/tasks{query}", headers=org.user_headers))["items"]]

    assert shipped["id"] not in ids("")
    assert shipped["id"] in ids("?include_done=true")
    assert ids("?overdue=true") == [late["id"]]
    assert ids("?q=hotfix") == [urgent["id"]]
    assert ids(f"?q={late['key'].lower()}") == [late["id"]]
    assert ids("?task_type=backend") == [urgent["id"]]
    assert ids("?status_key=done&include_done=true") == [shipped["id"]]
    assert ids("?sort=priority")[0] == urgent["id"]
    page = ok(client.get(f"{API}/tasks?limit=1&offset=1", headers=org.user_headers))
    assert page["total"] == 2 and page["limit"] == 1 and len(page["items"]) == 1
    assert client.get(f"{API}/tasks?sort=bogus", headers=org.user_headers).status_code == 422


def test_archive_and_restore(client, org):
    task = create_task(client, org.user_headers)
    ok(client.delete(f"{API}/tasks/{task['id']}", headers=org.user_headers), 204)
    assert task["id"] not in [t["id"] for t in ok(client.get(f"{API}/tasks", headers=org.user_headers))["items"]]
    board = board_by_name(client, org.user_headers, "Engineering")
    assert all(task["id"] not in [t["id"] for t in c["tasks"]] for c in board["columns"])
    assert move(client, org.user_headers, task["id"], column(board, "To Do")["id"]).status_code == 409
    assert client.patch(f"{API}/tasks/{task['id']}", json={"title": "x"}, headers=org.user_headers).status_code == 409
    restored = ok(client.patch(f"{API}/tasks/{task['id']}", json={"archived": False}, headers=org.user_headers))
    assert restored["archived_at"] is None and {"archived", "restored"} <= set(activity_kinds(restored))


def test_tasks_are_isolated_between_organisations(client, org, other_org):
    task = create_task(client, org.user_headers)
    theirs = create_task(client, other_org.user_headers, "Theirs")
    their_board = board_by_name(client, other_org.user_headers, "Engineering")
    h = other_org.user_headers
    assert client.get(f"{API}/tasks/{task['id']}", headers=h).status_code == 404
    assert client.patch(f"{API}/tasks/{task['id']}", json={"title": "x"}, headers=h).status_code == 404
    assert client.delete(f"{API}/tasks/{task['id']}", headers=h).status_code == 404
    assert move(client, h, task["id"], their_board["columns"][1]["id"]).status_code == 404
    assert client.post(f"{API}/tasks/{task['id']}/comments", json={"body": "x"}, headers=h).status_code == 404
    assert task["id"] not in [t["id"] for t in ok(client.get(f"{API}/tasks", headers=h))["items"]]
    # Cross-org references are rejected as if the record did not exist.
    assert move(client, org.user_headers, task["id"], their_board["columns"][1]["id"]).status_code == 404
    cross_dep = client.post(f"{API}/tasks/{task['id']}/dependencies", json={"depends_on_task_id": theirs["id"]},
                            headers=org.user_headers)
    assert cross_dep.status_code == 404
    cross_parent = client.post(f"{API}/tasks", json={"title": "x", "parent_task_id": theirs["id"]},
                               headers=org.user_headers)
    assert cross_parent.status_code == 404
    cross_column = client.post(f"{API}/tasks", json={"title": "x", "column_id": their_board["columns"][0]["id"]},
                               headers=org.user_headers)
    assert cross_column.status_code == 404
    assert theirs["key"] == "CTX-1"  # numbering is per organisation


def test_viewer_cannot_mutate_tasks(client, org, db):
    task = create_task(client, org.user_headers)
    _, viewer = add_member(db, org.org_id, Role.VIEWER.value, "Viewer")
    assert client.get(f"{API}/tasks/{task['id']}", headers=viewer).status_code == 200
    assert client.get(f"{API}/tasks", headers=viewer).status_code == 200
    board = board_by_name(client, org.user_headers, "Engineering")
    for response in (
        client.post(f"{API}/tasks", json={"title": "v"}, headers=viewer),
        client.patch(f"{API}/tasks/{task['id']}", json={"title": "v"}, headers=viewer),
        move(client, viewer, task["id"], column(board, "To Do")["id"]),
        client.post(f"{API}/tasks/{task['id']}/comments", json={"body": "v"}, headers=viewer),
        client.post(f"{API}/tasks/labels", json={"name": "v"}, headers=viewer),
        client.post(f"{API}/tasks/from-finding", json={"finding_id": "fnd_x"}, headers=viewer),
        client.delete(f"{API}/tasks/{task['id']}", headers=viewer),
    ):
        assert response.status_code == 403, response.text
    assert client.get(f"{API}/tasks", headers=org.api_headers).status_code == 200  # read-scoped API key
    assert client.post(f"{API}/tasks", json={"title": "k"}, headers=org.api_headers).status_code == 403
