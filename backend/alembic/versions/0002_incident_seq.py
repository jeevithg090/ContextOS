"""Per-organisation incident counter: ``organizations.incident_seq``.

Revision ID: 0002_incident_seq
Revises: 0001_initial
Create Date: 2026-11-11

Incident numbers (``INC-<n>``) were computed as ``max(incidents.number) + 1`` before the insert, so two
transactions creating an incident at the same time could both read the same maximum and store the same
number. They now come from ``organizations.incident_seq``, incremented atomically like the audit, event
and task counters (``app.services.org_counters.reserve``).

The column is added with ``server_default '0'`` (required for a NOT NULL column on a populated table)
and backfilled with each organisation's highest existing incident number, so numbering continues where
it left off. The server default is left in place: dropping it would rebuild ``organizations`` on SQLite
for no benefit, and every insert goes through SQLAlchemy, which applies the model default anyway.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002_incident_seq"
down_revision: str | Sequence[str] | None = "0001_initial"


def upgrade() -> None:
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.add_column(sa.Column("incident_seq", sa.Integer(), nullable=False, server_default="0"))
    op.execute(
        "UPDATE organizations SET incident_seq = COALESCE("
        "(SELECT MAX(incidents.number) FROM incidents WHERE incidents.organization_id = organizations.id), 0)"
    )


def downgrade() -> None:
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.drop_column("incident_seq")
