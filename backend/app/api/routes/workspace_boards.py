"""Engineering Workspace: Kanban boards and their columns.

Authorisation: ``read`` for GET, ``write`` for every mutation. Every lookup is scoped to the caller's
organisation (404 for other organisations' ids). Mutations are audited (``board.*``) and publish a
``task.updated`` live notification carrying the board id.

Static paths (``/templates``) are registered before ``/{board_id}``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import Principal, require, require_org_wide
from app.database.session import get_db
from app.domain.enums import Permission
from app.schemas.common import Page
from app.schemas.workspace_boards import (
    BoardCreate,
    BoardDetailOut,
    BoardDuplicate,
    BoardPatch,
    BoardSummaryOut,
    BoardTemplateOut,
    ColumnCreate,
    ColumnDeleteOut,
    ColumnOut,
    ColumnPatch,
    ColumnReorder,
)
from app.services import workspace_boards as boards
from app.services.workspace_tasks_common import as_actor, audit_board
from app.services.workspace_views import board_detail, board_summaries, column_counts, column_out, columns_out
from app.workspace.templates import list_templates

router = APIRouter(prefix="/workspace/boards", tags=["workspace"])

READ = Depends(require_org_wide(Permission.READ.value))  # bound API keys: 403
WRITE = Depends(require(Permission.WRITE.value))


@router.get("/templates", response_model=list[BoardTemplateOut])
def templates(principal: Principal = READ) -> list[BoardTemplateOut]:
    """Column layouts a new board can start from."""
    return [BoardTemplateOut.model_validate(t) for t in list_templates()]


@router.get("", response_model=Page[BoardSummaryOut])
def list_boards(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    include_archived: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[BoardSummaryOut]:
    """Boards (default first) with column and task counts.

    An organisation that has never had a board (e.g. created before the workspace existed) gets the
    default Engineering and Security Remediation boards on first visit.
    """
    seeded = boards.seed_default_board(db, principal.org_id, principal.user_id)
    if seeded:
        audit_board(db, as_actor(principal), seeded[0].id, "defaults_seeded",
                    {"board_ids": [b.id for b in seeded]})
    rows = boards.list_boards(db, principal.org_id, include_archived=include_archived)
    page = rows[offset: offset + limit]
    return Page(items=board_summaries(db, principal.org_id, page), total=len(rows), limit=limit, offset=offset)


@router.post("", response_model=BoardDetailOut, status_code=201)
def create_board(body: BoardCreate, principal: Principal = WRITE, db: Session = Depends(get_db)) -> BoardDetailOut:
    board = boards.create_board(db, as_actor(principal), name=body.name, template=body.template,
                                description=body.description)
    return board_detail(db, board)


@router.get("/{board_id}", response_model=BoardDetailOut)
def get_board(board_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> BoardDetailOut:
    """The board with its ordered columns and the (non-archived) task cards in each column."""
    return board_detail(db, boards.get_board(db, principal.org_id, board_id))


@router.patch("/{board_id}", response_model=BoardDetailOut)
def update_board(
    board_id: str, body: BoardPatch, principal: Principal = WRITE, db: Session = Depends(get_db)
) -> BoardDetailOut:
    board = boards.get_board(db, principal.org_id, board_id)
    changes = body.model_dump(exclude_unset=True)
    if body.config is not None:
        changes["config"] = body.config.model_dump(exclude_unset=True)
    boards.update_board(db, as_actor(principal), board, changes)
    return board_detail(db, board)


@router.delete("/{board_id}", status_code=204)
def archive_board(board_id: str, principal: Principal = WRITE, db: Session = Depends(get_db)) -> Response:
    """Archive (soft-delete) a board. Restore with ``PATCH {"archived": false}``."""
    boards.archive_board(db, as_actor(principal), boards.get_board(db, principal.org_id, board_id))
    return Response(status_code=204)


@router.post("/{board_id}/duplicate", response_model=BoardDetailOut, status_code=201)
def duplicate_board(
    board_id: str, body: BoardDuplicate, principal: Principal = WRITE, db: Session = Depends(get_db)
) -> BoardDetailOut:
    """Copy settings and columns (automation remapped). Tasks are not copied."""
    source = boards.get_board(db, principal.org_id, board_id)
    return board_detail(db, boards.duplicate_board(db, as_actor(principal), source, body.name))


# ----------------------------------------------------------------------------- columns


@router.post("/{board_id}/columns", response_model=ColumnOut, status_code=201)
def add_column(
    board_id: str, body: ColumnCreate, principal: Principal = WRITE, db: Session = Depends(get_db)
) -> ColumnOut:
    board = boards.get_active_board(db, principal.org_id, board_id)
    column = boards.add_column(db, as_actor(principal), board, body.model_dump())
    return column_out(column, 0)


@router.post("/{board_id}/columns/reorder", response_model=list[ColumnOut])
def reorder_columns(
    board_id: str, body: ColumnReorder, principal: Principal = WRITE, db: Session = Depends(get_db)
) -> list[ColumnOut]:
    board = boards.get_active_board(db, principal.org_id, board_id)
    columns = boards.reorder_columns(db, as_actor(principal), board, body.column_ids)
    return columns_out(db, principal.org_id, columns)


@router.patch("/{board_id}/columns/{column_id}", response_model=ColumnOut)
def update_column(
    board_id: str, column_id: str, body: ColumnPatch, principal: Principal = WRITE, db: Session = Depends(get_db)
) -> ColumnOut:
    board = boards.get_active_board(db, principal.org_id, board_id)
    column = boards.get_board_column(db, board, column_id)
    changes = body.model_dump(exclude_unset=True)
    if body.automation is not None:
        changes["automation"] = [r.model_dump() for r in body.automation]
    boards.update_column(db, as_actor(principal), board, column, changes)
    return column_out(column, column_counts(db, principal.org_id, [column.id]).get(column.id, 0))


@router.delete("/{board_id}/columns/{column_id}", response_model=ColumnDeleteOut)
def delete_column(
    board_id: str,
    column_id: str,
    principal: Principal = WRITE,
    db: Session = Depends(get_db),
    move_to: str | None = Query(None, description="Column to move the column's tasks into"),
    override_wip: bool = Query(False, description="Allow the move even if it exceeds the target's WIP limit"),
) -> ColumnDeleteOut:
    """Delete a column. Refused while it holds tasks unless ``move_to`` names another column of the board."""
    board = boards.get_active_board(db, principal.org_id, board_id)
    column = boards.get_board_column(db, board, column_id)
    result = boards.delete_column(db, as_actor(principal), board, column, move_to=move_to, override_wip=override_wip)
    return ColumnDeleteOut.model_validate(result)
