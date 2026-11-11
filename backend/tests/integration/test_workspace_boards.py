"""Engineering Workspace boards and columns: templates, seeding, customisation, isolation, permissions."""

from __future__ import annotations

from sqlalchemy import select

from app.domain.enums import Role
from app.models import AuditEvent, Board, BoardColumn
from app.services.bootstrap import create_organization
from app.services.workspace_boards import seed_default_board
from app.workspace.templates import BOARD_TEMPLATES
from tests.integration.workspace_support import (
    API,
    activity_kinds,
    add_member,
    board_by_name,
    boards,
    column,
    create_task,
    get_task,
    ok,
)


def test_seed_default_board_creates_engineering_and_remediation_once(db, org, client):
    created = seed_default_board(db, org.org_id, org.user_id)
    db.commit()
    assert [b.name for b in created] == ["Engineering", "Security Remediation"]
    assert seed_default_board(db, org.org_id, org.user_id) == []  # idempotent

    items = boards(client, org.user_headers)
    assert [(b["name"], b["template"], b["is_default"]) for b in items] == [
        ("Engineering", "software_development", True),
        ("Security Remediation", "security_remediation", False),
    ]
    remediation = board_by_name(client, org.user_headers, "Security Remediation")
    names = [c["name"] for c in remediation["columns"]]
    assert names == [c["name"] for c in BOARD_TEMPLATES["security_remediation"]["columns"]]
    assert column(remediation, "Verified")["requires_verification"] is True
    assert column(remediation, "Done")["is_done_column"] is True


def test_organisation_bootstrap_seeds_default_boards(db):
    org, _user = create_organization(db, name="Initech", owner_email="owner@initech.test", owner_name="Owner",
                                     password="correct-horse-battery-staple")
    db.commit()
    names = set(db.scalars(select(Board.name).where(Board.organization_id == org.id)))
    assert names == {"Engineering", "Security Remediation"}


def test_first_listing_seeds_boards_and_templates_are_listed(client, org, db):
    items = boards(client, org.user_headers)
    assert {b["name"] for b in items} == {"Engineering", "Security Remediation"}
    assert all(b["column_count"] == 8 and b["task_count"] == 0 for b in items)
    db.rollback()
    assert db.scalar(select(AuditEvent).where(AuditEvent.organization_id == org.org_id,
                                              AuditEvent.action == "board.defaults_seeded"))
    templates = ok(client.get(f"{API}/boards/templates", headers=org.user_headers))
    assert {t["key"] for t in templates} == set(BOARD_TEMPLATES)
    assert next(t for t in templates if t["key"] == "security_remediation")["requires_verification"] is True


def test_create_board_from_template(client, org):
    board = ok(client.post(f"{API}/boards", json={"name": "IR", "template": "incident_response"},
                           headers=org.user_headers), 201)
    assert board["template"] == "incident_response"
    assert [c["name"] for c in board["columns"]] == [c["name"] for c in BOARD_TEMPLATES["incident_response"]["columns"]]
    assert [c["position"] for c in board["columns"]] == list(range(len(board["columns"])))
    assert board["is_default"] is True  # the organisation's first board becomes the default
    bad = client.post(f"{API}/boards", json={"name": "X", "template": "nope"}, headers=org.user_headers)
    assert bad.status_code == 422


def test_column_customisation_and_validation(client, org):
    board = board_by_name(client, org.user_headers, "Engineering")
    path = f"{API}/boards/{board['id']}/columns"
    col = ok(client.post(path, json={"name": "Blocked", "color": "blocked", "wip_limit": 3, "status_key": "in_progress",
                                     "position": 2}, headers=org.user_headers), 201)
    assert col["wip_limit"] == 3 and col["position"] == 2 and col["status_key"] == "in_progress"

    bad_color = client.post(path, json={"name": "Odd", "color": "rainbow"}, headers=org.user_headers)
    assert bad_color.status_code == 422 and "colour" in bad_color.json()["error"]["details"]["errors"][0]
    duplicate = client.post(path, json={"name": "backlog"}, headers=org.user_headers)
    assert duplicate.status_code == 422 and "more than once" in str(duplicate.json()["error"]["details"])
    bad_done = client.post(path, json={"name": "Shipped", "is_done_column": True, "status_key": "review"},
                           headers=org.user_headers)
    assert bad_done.status_code == 422

    done = column(board, "Done")
    patched = ok(client.patch(f"{path}/{col['id']}", json={
        "name": "Blocked by others", "description": "Waiting on another team", "wip_limit": None,
        "requires_verification": True, "automation": [{"trigger": "pr_linked", "move_to_column_id": done["id"]}],
    }, headers=org.user_headers))
    assert patched["name"] == "Blocked by others" and patched["wip_limit"] is None
    assert patched["requires_verification"] is True
    assert patched["automation"] == [{"trigger": "pr_linked", "move_to_column_id": done["id"]}]

    other = ok(client.post(f"{API}/boards", json={"name": "Other", "template": "bug_tracking"},
                           headers=org.user_headers), 201)
    foreign = client.patch(f"{path}/{col['id']}", json={
        "automation": [{"trigger": "pr_linked", "move_to_column_id": other["columns"][0]["id"]}]}, headers=org.user_headers)
    assert foreign.status_code == 422 and "not a column of this board" in str(foreign.json()["error"]["details"])
    to_self = client.patch(f"{path}/{col['id']}", json={
        "automation": [{"trigger": "pr_linked", "move_to_column_id": col["id"]}]}, headers=org.user_headers)
    assert to_self.status_code == 422
    no_done = client.patch(f"{path}/{done['id']}", json={"is_done_column": False}, headers=org.user_headers)
    assert no_done.status_code == 422 and "done column" in str(no_done.json()["error"]["details"])


def test_column_delete_is_safe(client, org, db):
    board = board_by_name(client, org.user_headers, "Engineering")
    todo, backlog = column(board, "To Do"), column(board, "Backlog")
    task = create_task(client, org.user_headers, column_id=todo["id"])
    path = f"{API}/boards/{board['id']}/columns/{todo['id']}"

    refused = client.delete(path, headers=org.user_headers)
    assert refused.status_code == 409 and refused.json()["error"]["details"]["reason"] == "column_not_empty"

    result = ok(client.delete(f"{path}?move_to={backlog['id']}", headers=org.user_headers))
    assert result == {"deleted_column_id": todo["id"], "moved_task_count": 1, "moved_to_column_id": backlog["id"],
                      "removed_automation_rules": 0}
    detail = get_task(client, org.user_headers, task["id"])
    assert detail["column_id"] == backlog["id"]
    moved = next(a for a in detail["activity"] if a["kind"] == "moved")
    assert moved["details"]["reason"] == "column_deleted"
    after = ok(client.get(f"{API}/boards/{board['id']}", headers=org.user_headers))
    assert "To Do" not in [c["name"] for c in after["columns"]]
    assert [c["position"] for c in after["columns"]] == list(range(len(after["columns"])))

    done = column(after, "Done")
    last_done = client.delete(f"{API}/boards/{board['id']}/columns/{done['id']}", headers=org.user_headers)
    assert last_done.status_code == 422 and "done column" in str(last_done.json()["error"]["details"])


def test_column_delete_removes_automation_targeting_it_and_respects_gates(client, org):
    board = board_by_name(client, org.user_headers, "Security Remediation")
    testing, verified, review = column(board, "Testing"), column(board, "Verified"), column(board, "Review")
    base = f"{API}/boards/{board['id']}/columns"
    ok(client.patch(f"{base}/{review['id']}", json={
        "automation": [{"trigger": "verification_passed", "move_to_column_id": testing["id"]}]}, headers=org.user_headers))
    task = create_task(client, org.user_headers, board_id=board["id"], column_id=testing["id"])
    gated = client.delete(f"{base}/{testing['id']}?move_to={verified['id']}", headers=org.user_headers)
    assert gated.status_code == 409 and "needs passed verification evidence" in gated.json()["error"]["message"]
    result = ok(client.delete(f"{base}/{testing['id']}?move_to={review['id']}", headers=org.user_headers))
    assert result["removed_automation_rules"] == 1
    after = ok(client.get(f"{API}/boards/{board['id']}", headers=org.user_headers))
    assert column(after, "Review")["automation"] == []
    assert get_task(client, org.user_headers, task["id"])["column_name"] == "Review"


def test_column_reorder(client, org):
    board = board_by_name(client, org.user_headers, "Engineering")
    ids = [c["id"] for c in board["columns"]]
    reordered = ok(client.post(f"{API}/boards/{board['id']}/columns/reorder", json={"column_ids": ids[::-1]},
                               headers=org.user_headers))
    assert [c["id"] for c in reordered] == ids[::-1]
    assert [c["position"] for c in reordered] == list(range(len(ids)))
    partial = client.post(f"{API}/boards/{board['id']}/columns/reorder", json={"column_ids": ids[:3]},
                          headers=org.user_headers)
    assert partial.status_code == 422


def test_default_board_archive_restore_and_duplicate(client, org, db):
    eng = board_by_name(client, org.user_headers, "Engineering")
    sec = board_by_name(client, org.user_headers, "Security Remediation")
    refused = client.delete(f"{API}/boards/{eng['id']}", headers=org.user_headers)
    assert refused.status_code == 409
    ok(client.patch(f"{API}/boards/{sec['id']}", json={"is_default": True, "config": {"swimlanes": "priority"}},
                    headers=org.user_headers))
    listed = boards(client, org.user_headers)
    assert [b["name"] for b in listed if b["is_default"]] == ["Security Remediation"]
    assert next(b for b in listed if b["name"] == "Security Remediation")["config"] == {"swimlanes": "priority"}
    bad_config = client.patch(f"{API}/boards/{sec['id']}", json={"config": {"card_fields": ["nope"]}},
                              headers=org.user_headers)
    assert bad_config.status_code == 422

    ok(client.delete(f"{API}/boards/{eng['id']}", headers=org.user_headers), 204)
    assert "Engineering" not in [b["name"] for b in boards(client, org.user_headers)]
    archived = ok(client.get(f"{API}/boards?include_archived=true", headers=org.user_headers))["items"]
    assert next(b for b in archived if b["name"] == "Engineering")["archived_at"] is not None
    blocked = client.post(f"{API}/tasks", json={"title": "x", "board_id": eng["id"]}, headers=org.user_headers)
    assert blocked.status_code == 409
    restored = ok(client.patch(f"{API}/boards/{eng['id']}", json={"archived": False}, headers=org.user_headers))
    assert restored["archived_at"] is None

    # Duplicate copies columns and remaps automation to the copy's own columns.
    review, testing = column(sec, "Review"), column(sec, "Testing")
    ok(client.patch(f"{API}/boards/{sec['id']}/columns/{review['id']}", json={
        "automation": [{"trigger": "verification_passed", "move_to_column_id": testing["id"]}]}, headers=org.user_headers))
    copy = ok(client.post(f"{API}/boards/{sec['id']}/duplicate", json={"name": "Sec copy"}, headers=org.user_headers), 201)
    assert copy["name"] == "Sec copy" and copy["is_default"] is False and copy["task_count"] == 0
    copy_ids = {c["id"] for c in copy["columns"]}
    rule = column(copy, "Review")["automation"][0]
    assert rule["move_to_column_id"] == column(copy, "Testing")["id"] and rule["move_to_column_id"] in copy_ids
    db.rollback()
    actions = set(db.scalars(select(AuditEvent.action).where(AuditEvent.organization_id == org.org_id)))
    assert {"board.updated", "board.archived", "board.duplicated", "board.column_updated"} <= actions


def test_boards_are_isolated_between_organisations(client, org, other_org, db):
    board = board_by_name(client, org.user_headers, "Engineering")
    col = board["columns"][0]
    h = other_org.user_headers
    assert client.get(f"{API}/boards/{board['id']}", headers=h).status_code == 404
    assert client.patch(f"{API}/boards/{board['id']}", json={"name": "pwned"}, headers=h).status_code == 404
    assert client.delete(f"{API}/boards/{board['id']}", headers=h).status_code == 404
    assert client.post(f"{API}/boards/{board['id']}/duplicate", json={}, headers=h).status_code == 404
    assert client.post(f"{API}/boards/{board['id']}/columns", json={"name": "x"}, headers=h).status_code == 404
    assert client.patch(f"{API}/boards/{board['id']}/columns/{col['id']}", json={"name": "x"}, headers=h).status_code == 404
    # Another org's own board cannot address this org's column either.
    theirs = board_by_name(client, h, "Engineering")
    assert client.patch(f"{API}/boards/{theirs['id']}/columns/{col['id']}", json={"name": "x"},
                        headers=h).status_code == 404
    assert {b["id"] for b in boards(client, h)}.isdisjoint({b["id"] for b in boards(client, org.user_headers)})
    db.rollback()
    assert db.get(BoardColumn, col["id"]).name == col["name"]


def test_viewer_can_read_but_not_change_boards(client, org, db):
    board = board_by_name(client, org.user_headers, "Engineering")
    _, viewer = add_member(db, org.org_id, Role.VIEWER.value, "Viewer")
    assert client.get(f"{API}/boards/{board['id']}", headers=viewer).status_code == 200
    for response in (
        client.post(f"{API}/boards", json={"name": "V"}, headers=viewer),
        client.patch(f"{API}/boards/{board['id']}", json={"name": "V"}, headers=viewer),
        client.delete(f"{API}/boards/{board['id']}", headers=viewer),
        client.post(f"{API}/boards/{board['id']}/columns", json={"name": "V"}, headers=viewer),
        client.post(f"{API}/boards/{board['id']}/columns/reorder", json={"column_ids": ["x"]}, headers=viewer),
    ):
        assert response.status_code == 403, response.text
    api_key_write = client.post(f"{API}/boards", json={"name": "K"}, headers=org.api_headers)
    assert api_key_write.status_code == 403


def test_board_detail_groups_cards_by_column(client, org):
    board = board_by_name(client, org.user_headers, "Engineering")
    first = create_task(client, org.user_headers, "First")
    second = create_task(client, org.user_headers, "Second")
    detail = ok(client.get(f"{API}/boards/{board['id']}", headers=org.user_headers))
    backlog = column(detail, "Backlog")
    assert [t["id"] for t in backlog["tasks"]] == [first["id"], second["id"]]
    assert backlog["task_count"] == 2 and detail["task_count"] == 2 and detail["open_task_count"] == 2
    card = backlog["tasks"][0]
    assert card["key"].startswith("CTX-") and card["column_name"] == "Backlog" and card["is_done"] is False
    assert "created" in activity_kinds(get_task(client, org.user_headers, first["id"]))
