"""Engineering Workspace tasks: CRUD, moves, the finding/incident remediation link, comments,
dependencies, labels, assignees, context references, attachments, code links, fix attempts and
verification runs.

Authorisation: ``read`` for GET, ``write`` for every mutation. Every id is resolved inside the caller's
organisation (404 otherwise). Every mutation writes task activity, an audit entry (``task.*``) and a
``task.updated`` live notification. Workflow gates (WIP limits, verification) answer 409 with a
plain-language message and ``details.reason``.

Static paths (``/labels``, ``/from-finding``, ``/comments/...``) are registered before ``/{task_id}``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import Principal, require, require_org_wide
from app.database.session import get_db
from app.domain.enums import Permission
from app.schemas.common import Page
from app.schemas.workspace import (
    AssigneeOut,
    LabelCreate,
    LabelOut,
    LabelWithUsageOut,
    PriorityName,
    TaskTypeName,
)
from app.schemas.workspace_boards import TaskCardOut
from app.schemas.workspace_evidence import (
    AttachmentCreate,
    AttachmentOut,
    FixAttemptCreate,
    FixAttemptOut,
    FixAttemptPatch,
    LinkCreate,
    LinkItemOut,
    VerificationCreate,
    VerificationOut,
    VerifyWithSimulationIn,
)
from app.schemas.workspace_tasks import (
    AssigneesPut,
    CommentCreate,
    CommentOut,
    CommentPatch,
    DependencyCreate,
    DependencyOut,
    FromFindingIn,
    FromFindingOut,
    FromIncidentIn,
    FromIncidentOut,
    IncidentTaskOut,
    RefCreate,
    RefOut,
    TaskCreate,
    TaskDetailOut,
    TaskMove,
    TaskPatch,
)
from app.services import workspace_tasks as tasks
from app.services import workspace_tasks_evidence as evidence
from app.services import workspace_tasks_refs as refs
from app.services import workspace_tasks_relations as relations
from app.services.scoping import paginate
from app.services.workspace_tasks_common import as_actor, get_task
from app.services.workspace_tasks_findings import create_task_from_finding, create_tasks_from_incident
from app.services.workspace_views import (
    attachment_out,
    brief,
    comment_out,
    dependency_out,
    fix_attempt_out,
    links_out,
    task_card,
    task_cards,
    task_detail,
    users_by_id,
    verification_out,
)

router = APIRouter(prefix="/workspace/tasks", tags=["workspace"])

READ = Depends(require_org_wide(Permission.READ.value))  # bound API keys: 403
WRITE = Depends(require(Permission.WRITE.value))
SORT_PATTERN = "^(updated|created|key|due_date|priority|position)$"


# ----------------------------------------------------------------------------- collection


@router.get("", response_model=Page[TaskCardOut])
def list_tasks(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    board_id: str | None = None,
    column_id: str | None = None,
    assignee: str | None = Query(None, description="User id, or 'me'"),
    task_type: TaskTypeName | None = None,
    priority: PriorityName | None = None,
    label: str | None = Query(None, description="Label id or name"),
    q: str | None = Query(None, max_length=200, description="Title/description text, or a key such as CTX-12"),
    status_key: str | None = None,
    related_finding_id: str | None = None,
    related_incident_id: str | None = None,
    parent_task_id: str | None = None,
    overdue: bool | None = None,
    include_done: bool = False,
    include_archived: bool = False,
    sort: str = Query("updated", pattern=SORT_PATTERN),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[TaskCardOut]:
    query = tasks.task_query(
        principal.org_id, user_id=principal.user_id, board_id=board_id, column_id=column_id, assignee=assignee,
        task_type=task_type, priority=priority, label=label, q=q, status_key=status_key,
        related_finding_id=related_finding_id, related_incident_id=related_incident_id,
        parent_task_id=parent_task_id, overdue=overdue, include_done=include_done,
        include_archived=include_archived, sort=sort,
    )
    rows, total = paginate(db, query, limit=limit, offset=offset)
    return Page(items=task_cards(db, principal.org_id, rows), total=total, limit=limit, offset=offset)


@router.post("", response_model=TaskDetailOut, status_code=201)
def create_task(body: TaskCreate, principal: Principal = WRITE, db: Session = Depends(get_db)) -> TaskDetailOut:
    data = body.model_dump(exclude_unset=True)
    title = data.pop("title")
    task = tasks.create_task(db, principal, title=title, **data)
    return task_detail(db, task)


# ----------------------------------------------------------------------------- static paths


@router.get("/labels", response_model=list[LabelWithUsageOut])
def list_labels(principal: Principal = READ, db: Session = Depends(get_db)) -> list[LabelWithUsageOut]:
    return [LabelWithUsageOut(id=label.id, name=label.name, color=label.color, task_count=count,
                              created_at=label.created_at)
            for label, count in relations.list_labels(db, principal.org_id)]


@router.post("/labels", response_model=LabelOut, status_code=201)
def create_label(body: LabelCreate, principal: Principal = WRITE, db: Session = Depends(get_db)) -> LabelOut:
    label = relations.create_label(db, as_actor(principal), name=body.name, color=body.color)
    return LabelOut(id=label.id, name=label.name, color=label.color)


@router.post("/from-finding", response_model=FromFindingOut)
def from_finding(body: FromFindingIn, response: Response, principal: Principal = WRITE,
                 db: Session = Depends(get_db)) -> FromFindingOut:
    """Create (or return the existing open) remediation task for a finding. 201 when created, 200 otherwise."""
    result = create_task_from_finding(db, principal, body.finding_id, body.board_id)
    response.status_code = 201 if result.created else 200
    return FromFindingOut(created=result.created, task=task_detail(db, result.task))


@router.post("/from-incident", response_model=FromIncidentOut)
def from_incident(body: FromIncidentIn, principal: Principal = WRITE, db: Session = Depends(get_db)) -> FromIncidentOut:
    result = create_tasks_from_incident(db, principal, body.incident_id, body.board_id, body.mode)
    cards = {c.id: c for c in task_cards(db, principal.org_id, [t for _, _, t in result.items])}
    return FromIncidentOut(
        incident_id=result.incident_id, mode=result.mode, parent_task_id=result.parent.id if result.parent else None,
        created_count=result.created_count, existing_count=result.existing_count,
        tasks=[IncidentTaskOut(finding_id=fid, created=created, task=cards[t.id]) for fid, created, t in result.items],
    )


@router.patch("/comments/{comment_id}", response_model=CommentOut)
def edit_comment(comment_id: str, body: CommentPatch, principal: Principal = WRITE,
                 db: Session = Depends(get_db)) -> CommentOut:
    comment = relations.edit_comment(db, as_actor(principal), comment_id, body.body)
    return comment_out(comment, users_by_id(db, {comment.author_user_id}))


@router.delete("/comments/{comment_id}", status_code=204)
def delete_comment(comment_id: str, principal: Principal = WRITE, db: Session = Depends(get_db)) -> Response:
    relations.delete_comment(db, as_actor(principal), comment_id)
    return Response(status_code=204)


@router.delete("/dependencies/{dependency_id}", status_code=204)
def delete_dependency(dependency_id: str, principal: Principal = WRITE, db: Session = Depends(get_db)) -> Response:
    relations.remove_dependency(db, as_actor(principal), dependency_id)
    return Response(status_code=204)


@router.delete("/refs/{ref_id}", status_code=204)
def delete_ref(ref_id: str, principal: Principal = WRITE, db: Session = Depends(get_db)) -> Response:
    refs.remove_ref(db, as_actor(principal), ref_id)
    return Response(status_code=204)


@router.delete("/attachments/{attachment_id}", status_code=204)
def delete_attachment(attachment_id: str, principal: Principal = WRITE, db: Session = Depends(get_db)) -> Response:
    evidence.delete_attachment(db, principal, attachment_id)
    return Response(status_code=204)


@router.patch("/fix-attempts/{attempt_id}", response_model=FixAttemptOut)
def update_fix_attempt(attempt_id: str, body: FixAttemptPatch, principal: Principal = WRITE,
                       db: Session = Depends(get_db)) -> FixAttemptOut:
    attempt = evidence.update_fix_attempt(db, principal, attempt_id, body.model_dump(exclude_unset=True))
    return fix_attempt_out(attempt, users_by_id(db, {attempt.created_by}))


# ----------------------------------------------------------------------------- item


@router.get("/{task_id}", response_model=TaskDetailOut)
def get_task_detail(task_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> TaskDetailOut:
    return task_detail(db, get_task(db, principal.org_id, task_id))


@router.patch("/{task_id}", response_model=TaskDetailOut)
def update_task(task_id: str, body: TaskPatch, principal: Principal = WRITE,
                db: Session = Depends(get_db)) -> TaskDetailOut:
    task = get_task(db, principal.org_id, task_id)
    tasks.update_task(db, principal, task, body.model_dump(exclude_unset=True))
    return task_detail(db, task)


@router.delete("/{task_id}", status_code=204)
def archive_task(task_id: str, principal: Principal = WRITE, db: Session = Depends(get_db)) -> Response:
    """Archive (soft-delete). Restore with ``PATCH {"archived": false}``."""
    tasks.archive_task(db, principal, get_task(db, principal.org_id, task_id))
    return Response(status_code=204)


@router.post("/{task_id}/move", response_model=TaskCardOut)
def move_task(task_id: str, body: TaskMove, principal: Principal = WRITE, db: Session = Depends(get_db)) -> TaskCardOut:
    task = get_task(db, principal.org_id, task_id)
    tasks.move_task(db, principal, task, body.column_id, body.position, body.override_wip)
    return task_card(db, task)


@router.put("/{task_id}/assignees", response_model=list[AssigneeOut])
def put_assignees(task_id: str, body: AssigneesPut, principal: Principal = WRITE,
                  db: Session = Depends(get_db)) -> list[AssigneeOut]:
    task = get_task(db, principal.org_id, task_id)
    relations.set_assignees(db, as_actor(principal), task, [(a.user_id, a.role) for a in body.assignees])
    return task_card(db, task).assignees


@router.post("/{task_id}/comments", response_model=CommentOut, status_code=201)
def add_comment(task_id: str, body: CommentCreate, principal: Principal = WRITE,
                db: Session = Depends(get_db)) -> CommentOut:
    task = get_task(db, principal.org_id, task_id)
    comment = relations.add_comment(db, as_actor(principal), task, body.body)
    return comment_out(comment, users_by_id(db, {comment.author_user_id}))


@router.post("/{task_id}/dependencies", response_model=DependencyOut, status_code=201)
def add_dependency(task_id: str, body: DependencyCreate, principal: Principal = WRITE,
                   db: Session = Depends(get_db)) -> DependencyOut:
    task = get_task(db, principal.org_id, task_id)
    dep = relations.add_dependency(db, as_actor(principal), task, body.depends_on_task_id, body.kind)
    return dependency_out(dep, brief(db, get_task(db, principal.org_id, dep.depends_on_task_id)))


@router.post("/{task_id}/refs", response_model=RefOut, status_code=201)
def add_ref(task_id: str, body: RefCreate, principal: Principal = WRITE, db: Session = Depends(get_db)) -> RefOut:
    task = get_task(db, principal.org_id, task_id)
    ref = refs.add_ref(db, as_actor(principal), task, body.ref_type, body.ref_id, body.note)
    return RefOut.model_validate(refs.resolve_refs(db, principal.org_id, [ref])[0])


@router.post("/{task_id}/attachments", response_model=AttachmentOut, status_code=201)
def add_attachment(task_id: str, body: AttachmentCreate, principal: Principal = WRITE,
                   db: Session = Depends(get_db)) -> AttachmentOut:
    task = get_task(db, principal.org_id, task_id)
    row = evidence.add_attachment(db, principal, task, name=body.name, kind=body.kind, url=body.url,
                                  content=body.content)
    return attachment_out(row, users_by_id(db, {row.created_by}))


@router.post("/{task_id}/links", response_model=dict[str, list[LinkItemOut]], status_code=201)
def add_link(task_id: str, body: LinkCreate, principal: Principal = WRITE,
             db: Session = Depends(get_db)) -> dict[str, list[LinkItemOut]]:
    """Link a branch, commit, pull request or deployment. Returns every link of the task, grouped by kind."""
    task = get_task(db, principal.org_id, task_id)
    evidence.add_link(db, principal, task, kind=body.kind, url=body.url, title=body.title, ref=body.ref,
                      state=body.state)
    return links_out(task)


@router.delete("/{task_id}/links/{kind}/{index}", response_model=dict[str, list[LinkItemOut]])
def remove_link(task_id: str, kind: str, index: int, principal: Principal = WRITE,
                db: Session = Depends(get_db)) -> dict[str, list[LinkItemOut]]:
    task = get_task(db, principal.org_id, task_id)
    evidence.remove_link(db, principal, task, kind, index)
    return links_out(task)


@router.post("/{task_id}/fix-attempts", response_model=FixAttemptOut, status_code=201)
def add_fix_attempt(task_id: str, body: FixAttemptCreate, principal: Principal = WRITE,
                    db: Session = Depends(get_db)) -> FixAttemptOut:
    task = get_task(db, principal.org_id, task_id)
    attempt = evidence.create_fix_attempt(db, principal, task, body.model_dump())
    return fix_attempt_out(attempt, users_by_id(db, {attempt.created_by}))


@router.post("/{task_id}/verifications", response_model=VerificationOut, status_code=201)
def add_verification(task_id: str, body: VerificationCreate, principal: Principal = WRITE,
                     db: Session = Depends(get_db)) -> VerificationOut:
    task = get_task(db, principal.org_id, task_id)
    run = evidence.record_verification(db, principal, task, body.model_dump())
    return verification_out(run, users_by_id(db, {run.created_by}), task.verification_status)


@router.post("/{task_id}/verify-with-simulation", response_model=VerificationOut, status_code=201)
def verify_with_simulation(task_id: str, body: VerifyWithSimulationIn, principal: Principal = WRITE,
                           db: Session = Depends(get_db)) -> VerificationOut:
    """Run a Simulation Lab scenario through the real pipeline and record it as verification evidence."""
    task = get_task(db, principal.org_id, task_id)
    run = evidence.verify_with_simulation(db, principal, task, body.scenario_id, body.fix_attempt_id)
    return verification_out(run, users_by_id(db, {run.created_by}), task.verification_status)
