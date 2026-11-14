"""Initial schema: every ContextOS table, index, unique constraint and foreign key.

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-11

Generated with ``alembic revision --autogenerate`` from ``app.models`` and reviewed by hand:

- Column types are portable: ``app.database.base.UTCDateTime`` is stored as ``DateTime(timezone=True)``
  (TIMESTAMP WITH TIME ZONE on PostgreSQL; SQLite keeps ISO text and the type decorator restores UTC),
  JSON columns are ``JSON`` on SQLite and ``JSONB`` on PostgreSQL. No application code is imported.
- Names follow ``Base.metadata``'s naming convention (pk_/uq_/fk_/ix_), so later migrations can
  address every constraint by name, including in SQLite batch mode.
- Every tenant table has ``organization_id`` -> ``organizations.id`` ON DELETE CASCADE; the other
  foreign keys keep the ``ondelete`` behaviour declared on the models.
- No server defaults: every insert goes through SQLAlchemy, which applies the model defaults. A later
  migration that adds a NOT NULL column to a populated table must supply a ``server_default``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_initial"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TIMESTAMP = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("settings", JSON_TYPE, nullable=False),
        sa.Column("audit_seq", sa.Integer(), nullable=False),
        sa.Column("event_seq", sa.Integer(), nullable=False),
        sa.Column("task_seq", sa.Integer(), nullable=False),
        sa.Column("audit_head_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organizations")),
        sa.UniqueConstraint("slug", name=op.f("uq_organizations_slug")),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("last_login_at", TIMESTAMP, nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    op.create_table(
        "approvals",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("policy_decision_id", sa.String(length=40), nullable=False),
        sa.Column("tool_invocation_id", sa.String(length=40), nullable=True),
        sa.Column("agent_id", sa.String(length=40), nullable=False),
        sa.Column("session_id", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("risk_summary", JSON_TYPE, nullable=False),
        sa.Column("requested_at", TIMESTAMP, nullable=False),
        sa.Column("expires_at", TIMESTAMP, nullable=True),
        sa.Column("decided_at", TIMESTAMP, nullable=True),
        sa.Column("decided_by_user_id", sa.String(length=40), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_approvals_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approvals")),
    )
    op.create_index(op.f("ix_approvals_agent_id"), "approvals", ["agent_id"], unique=False)
    op.create_index(op.f("ix_approvals_organization_id"), "approvals", ["organization_id"], unique=False)
    op.create_index(
        op.f("ix_approvals_policy_decision_id"), "approvals", ["policy_decision_id"], unique=False
    )
    op.create_index(op.f("ix_approvals_status"), "approvals", ["status"], unique=False)
    op.create_index(
        op.f("ix_approvals_tool_invocation_id"), "approvals", ["tool_invocation_id"], unique=False
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("occurred_at", TIMESTAMP, nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_id", sa.String(length=40), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=48), nullable=True),
        sa.Column("target_id", sa.String(length=40), nullable=True),
        sa.Column("details", JSON_TYPE, nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=True),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_audit_events_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
        sa.UniqueConstraint("organization_id", "seq", name=op.f("uq_audit_events_organization_id_seq")),
    )
    op.create_index(op.f("ix_audit_events_action"), "audit_events", ["action"], unique=False)
    op.create_index(
        op.f("ix_audit_events_organization_id"), "audit_events", ["organization_id"], unique=False
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("user_id", sa.String(length=40), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("expires_at", TIMESTAMP, nullable=False),
        sa.Column("revoked_at", TIMESTAMP, nullable=True),
        sa.Column("user_agent", sa.String(length=400), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_auth_sessions_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_sessions")),
    )
    op.create_index(op.f("ix_auth_sessions_token_hash"), "auth_sessions", ["token_hash"], unique=True)
    op.create_index(op.f("ix_auth_sessions_user_id"), "auth_sessions", ["user_id"], unique=False)

    op.create_table(
        "boards",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("template", sa.String(length=48), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column("config", JSON_TYPE, nullable=False),
        sa.Column("created_by", sa.String(length=40), nullable=True),
        sa.Column("archived_at", TIMESTAMP, nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_boards_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_boards")),
    )
    op.create_index(op.f("ix_boards_organization_id"), "boards", ["organization_id"], unique=False)

    op.create_table(
        "context_packs",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=True),
        sa.Column("profile", sa.String(length=32), nullable=False),
        sa.Column("items", JSON_TYPE, nullable=False),
        sa.Column("token_estimate", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=40), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_context_packs_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_context_packs")),
    )
    op.create_index(
        op.f("ix_context_packs_organization_id"), "context_packs", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_context_packs_task_id"), "context_packs", ["task_id"], unique=False)

    op.create_table(
        "context_sources",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("identifier", sa.String(length=2048), nullable=False),
        sa.Column("display_name", sa.String(length=400), nullable=True),
        sa.Column("domain", sa.String(length=255), nullable=True),
        sa.Column("owner", sa.String(length=200), nullable=True),
        sa.Column("trust_level", sa.String(length=16), nullable=False),
        sa.Column("trust_capabilities", JSON_TYPE, nullable=False),
        sa.Column("trust_reasons", JSON_TYPE, nullable=False),
        sa.Column("trust_rule_id", sa.String(length=40), nullable=True),
        sa.Column("manually_classified", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", TIMESTAMP, nullable=False),
        sa.Column("last_seen_at", TIMESTAMP, nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("max_finding_severity", sa.String(length=16), nullable=True),
        sa.Column("source_metadata", JSON_TYPE, nullable=False),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_context_sources_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_context_sources")),
        sa.UniqueConstraint(
            "organization_id",
            "source_type",
            "identifier",
            name=op.f("uq_context_sources_organization_id_source_type_identifier"),
        ),
    )
    op.create_index(op.f("ix_context_sources_domain"), "context_sources", ["domain"], unique=False)
    op.create_index(
        op.f("ix_context_sources_is_simulation"), "context_sources", ["is_simulation"], unique=False
    )
    op.create_index(
        op.f("ix_context_sources_organization_id"), "context_sources", ["organization_id"], unique=False
    )

    op.create_table(
        "destinations",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("identifier", sa.String(length=1024), nullable=False),
        sa.Column("display_name", sa.String(length=400), nullable=True),
        sa.Column("classification", sa.String(length=16), nullable=False),
        sa.Column("trust_rule_id", sa.String(length=40), nullable=True),
        sa.Column("verification", JSON_TYPE, nullable=False),
        sa.Column("first_seen_at", TIMESTAMP, nullable=False),
        sa.Column("last_seen_at", TIMESTAMP, nullable=False),
        sa.Column("transfer_count", sa.Integer(), nullable=False),
        sa.Column("blocked_count", sa.Integer(), nullable=False),
        sa.Column("sensitive_transfer_count", sa.Integer(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_destinations_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_destinations")),
        sa.UniqueConstraint(
            "organization_id",
            "kind",
            "identifier",
            name=op.f("uq_destinations_organization_id_kind_identifier"),
        ),
    )
    op.create_index(
        op.f("ix_destinations_organization_id"), "destinations", ["organization_id"], unique=False
    )

    op.create_table(
        "generated_prompts",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=True),
        sa.Column("mode", sa.String(length=48), nullable=False),
        sa.Column("preset", sa.String(length=32), nullable=False),
        sa.Column("options", JSON_TYPE, nullable=False),
        sa.Column("sections", JSON_TYPE, nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("context_pack_id", sa.String(length=40), nullable=True),
        sa.Column("template_id", sa.String(length=40), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=40), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_generated_prompts_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_generated_prompts")),
    )
    op.create_index(
        op.f("ix_generated_prompts_organization_id"), "generated_prompts", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_generated_prompts_task_id"), "generated_prompts", ["task_id"], unique=False)

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=400), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("assignee_user_id", sa.String(length=40), nullable=True),
        sa.Column("primary_agent_id", sa.String(length=40), nullable=True),
        sa.Column("primary_session_id", sa.String(length=40), nullable=True),
        sa.Column("opened_at", TIMESTAMP, nullable=False),
        sa.Column("resolved_at", TIMESTAMP, nullable=True),
        sa.Column("created_by", sa.String(length=40), nullable=False),
        sa.Column("resolution", sa.Text(), nullable=True),
        sa.Column("tags", JSON_TYPE, nullable=False),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_incidents_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
    )
    op.create_index(op.f("ix_incidents_organization_id"), "incidents", ["organization_id"], unique=False)
    op.create_index(op.f("ix_incidents_status"), "incidents", ["status"], unique=False)

    op.create_table(
        "ingested_events",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("client_event_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("schema_version", sa.String(length=8), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("agent_id", sa.String(length=40), nullable=True),
        sa.Column("session_id", sa.String(length=40), nullable=True),
        sa.Column("correlation_id", sa.String(length=200), nullable=True),
        sa.Column("integration", sa.String(length=64), nullable=True),
        sa.Column("occurred_at", TIMESTAMP, nullable=False),
        sa.Column("received_at", TIMESTAMP, nullable=False),
        sa.Column("payload_redacted", JSON_TYPE, nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("refs", JSON_TYPE, nullable=False),
        sa.Column("processing_status", sa.String(length=16), nullable=False),
        sa.Column("processing_error", sa.Text(), nullable=True),
        sa.Column("api_key_id", sa.String(length=40), nullable=True),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ingested_events_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingested_events")),
        sa.UniqueConstraint(
            "organization_id",
            "client_event_id",
            name=op.f("uq_ingested_events_organization_id_client_event_id"),
        ),
    )
    op.create_index(
        "ix_events_org_received", "ingested_events", ["organization_id", "received_at"], unique=False
    )
    op.create_index(
        "ix_events_org_session_seq",
        "ingested_events",
        ["organization_id", "session_id", "sequence"],
        unique=False,
    )
    op.create_index(op.f("ix_ingested_events_agent_id"), "ingested_events", ["agent_id"], unique=False)
    op.create_index(op.f("ix_ingested_events_event_type"), "ingested_events", ["event_type"], unique=False)
    op.create_index(
        op.f("ix_ingested_events_organization_id"), "ingested_events", ["organization_id"], unique=False
    )

    op.create_table(
        "integrations",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("kind", sa.String(length=48), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("config", JSON_TYPE, nullable=False),
        sa.Column("last_event_at", TIMESTAMP, nullable=True),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("decision_count", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_integrations_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integrations")),
        sa.UniqueConstraint(
            "organization_id", "kind", "name", name=op.f("uq_integrations_organization_id_kind_name")
        ),
    )
    op.create_index(
        op.f("ix_integrations_organization_id"), "integrations", ["organization_id"], unique=False
    )

    op.create_table(
        "memberships",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("user_id", sa.String(length=40), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_memberships_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_memberships_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_memberships")),
        sa.UniqueConstraint(
            "organization_id", "user_id", name=op.f("uq_memberships_organization_id_user_id")
        ),
    )
    op.create_index(op.f("ix_memberships_organization_id"), "memberships", ["organization_id"], unique=False)
    op.create_index(op.f("ix_memberships_user_id"), "memberships", ["user_id"], unique=False)

    op.create_table(
        "policy_decisions",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("agent_id", sa.String(length=40), nullable=False),
        sa.Column("session_id", sa.String(length=40), nullable=False),
        sa.Column("tool_invocation_id", sa.String(length=40), nullable=True),
        sa.Column("event_id", sa.String(length=40), nullable=True),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("enforcement", sa.String(length=16), nullable=False),
        sa.Column("matched_policies", JSON_TYPE, nullable=False),
        sa.Column("monitor_matches", JSON_TYPE, nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("input_snapshot", JSON_TYPE, nullable=False),
        sa.Column("evaluated_at", TIMESTAMP, nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_policy_decisions_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policy_decisions")),
    )
    op.create_index(op.f("ix_policy_decisions_agent_id"), "policy_decisions", ["agent_id"], unique=False)
    op.create_index(
        "ix_policy_decisions_org_evaluated",
        "policy_decisions",
        ["organization_id", "evaluated_at"],
        unique=False,
    )
    op.create_index(
        "ix_policy_decisions_org_session", "policy_decisions", ["organization_id", "session_id"], unique=False
    )
    op.create_index(
        op.f("ix_policy_decisions_organization_id"), "policy_decisions", ["organization_id"], unique=False
    )
    op.create_index(
        op.f("ix_policy_decisions_tool_invocation_id"),
        "policy_decisions",
        ["tool_invocation_id"],
        unique=False,
    )

    op.create_table(
        "prompt_templates",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("mode", sa.String(length=48), nullable=False),
        sa.Column("preset", sa.String(length=32), nullable=False),
        sa.Column("options", JSON_TYPE, nullable=False),
        sa.Column("section_overrides", JSON_TYPE, nullable=False),
        sa.Column("is_builtin", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=40), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_prompt_templates_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_prompt_templates")),
    )
    op.create_index(
        op.f("ix_prompt_templates_organization_id"), "prompt_templates", ["organization_id"], unique=False
    )

    op.create_table(
        "provenance_edges",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("src_type", sa.String(length=32), nullable=False),
        sa.Column("src_id", sa.String(length=2048), nullable=False),
        sa.Column("dst_type", sa.String(length=32), nullable=False),
        sa.Column("dst_id", sa.String(length=2048), nullable=False),
        sa.Column("relation", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=40), nullable=True),
        sa.Column("event_id", sa.String(length=40), nullable=True),
        sa.Column("observed_at", TIMESTAMP, nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("edge_metadata", JSON_TYPE, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_provenance_edges_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_provenance_edges")),
    )
    op.create_index(
        "ix_prov_dst", "provenance_edges", ["organization_id", "dst_type", "dst_id"], unique=False
    )
    op.create_index(
        "ix_prov_org_observed", "provenance_edges", ["organization_id", "observed_at"], unique=False
    )
    op.create_index(
        "ix_prov_src", "provenance_edges", ["organization_id", "src_type", "src_id"], unique=False
    )
    op.create_index(
        op.f("ix_provenance_edges_organization_id"), "provenance_edges", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_provenance_edges_session_id"), "provenance_edges", ["session_id"], unique=False)

    op.create_table(
        "security_findings",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("agent_id", sa.String(length=40), nullable=True),
        sa.Column("session_id", sa.String(length=40), nullable=True),
        sa.Column("category", sa.String(length=48), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=400), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("evidence", JSON_TYPE, nullable=False),
        sa.Column("source_id", sa.String(length=40), nullable=True),
        sa.Column("context_item_id", sa.String(length=40), nullable=True),
        sa.Column("tool_invocation_id", sa.String(length=40), nullable=True),
        sa.Column("policy_decision_id", sa.String(length=40), nullable=True),
        sa.Column("destination_id", sa.String(length=40), nullable=True),
        sa.Column("incident_id", sa.String(length=40), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", TIMESTAMP, nullable=False),
        sa.Column("last_seen_at", TIMESTAMP, nullable=False),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("resolved_by_user_id", sa.String(length=40), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_security_findings_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_findings")),
    )
    op.create_index(
        "ix_findings_org_fingerprint", "security_findings", ["organization_id", "fingerprint"], unique=False
    )
    op.create_index(op.f("ix_security_findings_agent_id"), "security_findings", ["agent_id"], unique=False)
    op.create_index(
        op.f("ix_security_findings_incident_id"), "security_findings", ["incident_id"], unique=False
    )
    op.create_index(
        op.f("ix_security_findings_organization_id"), "security_findings", ["organization_id"], unique=False
    )
    op.create_index(
        op.f("ix_security_findings_session_id"), "security_findings", ["session_id"], unique=False
    )
    op.create_index(op.f("ix_security_findings_source_id"), "security_findings", ["source_id"], unique=False)
    op.create_index(op.f("ix_security_findings_status"), "security_findings", ["status"], unique=False)

    op.create_table(
        "security_policies",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("conditions", JSON_TYPE, nullable=False),
        sa.Column("restrictions", JSON_TYPE, nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("tags", JSON_TYPE, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("is_builtin", sa.Boolean(), nullable=False),
        sa.Column("builtin_key", sa.String(length=100), nullable=True),
        sa.Column("created_by", sa.String(length=40), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_security_policies_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_policies")),
    )
    op.create_index(
        op.f("ix_security_policies_organization_id"), "security_policies", ["organization_id"], unique=False
    )

    op.create_table(
        "simulation_runs",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("scenario_id", sa.String(length=100), nullable=False),
        sa.Column("scenario_name", sa.String(length=200), nullable=False),
        sa.Column("suite_run_id", sa.String(length=40), nullable=True),
        sa.Column("agent_id", sa.String(length=40), nullable=True),
        sa.Column("session_id", sa.String(length=40), nullable=True),
        sa.Column("agent_version", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=True),
        sa.Column("policy_snapshot", JSON_TYPE, nullable=False),
        sa.Column("results", JSON_TYPE, nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("started_at", TIMESTAMP, nullable=False),
        sa.Column("completed_at", TIMESTAMP, nullable=True),
        sa.Column("triggered_by_user_id", sa.String(length=40), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_simulation_runs_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_simulation_runs")),
    )
    op.create_index(
        op.f("ix_simulation_runs_organization_id"), "simulation_runs", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_simulation_runs_scenario_id"), "simulation_runs", ["scenario_id"], unique=False)
    op.create_index(
        op.f("ix_simulation_runs_suite_run_id"), "simulation_runs", ["suite_run_id"], unique=False
    )

    op.create_table(
        "task_labels",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("color", sa.String(length=16), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_task_labels_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_labels")),
        sa.UniqueConstraint("organization_id", "name", name=op.f("uq_task_labels_organization_id_name")),
    )
    op.create_index(op.f("ix_task_labels_organization_id"), "task_labels", ["organization_id"], unique=False)

    op.create_table(
        "tools",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("provider", sa.String(length=200), nullable=False),
        sa.Column("server", sa.String(length=200), nullable=True),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("tool_metadata", JSON_TYPE, nullable=False),
        sa.Column("first_seen_at", TIMESTAMP, nullable=False),
        sa.Column("last_seen_at", TIMESTAMP, nullable=False),
        sa.Column("invocation_count", sa.Integer(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_tools_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tools")),
        sa.UniqueConstraint(
            "organization_id", "provider", "name", name=op.f("uq_tools_organization_id_provider_name")
        ),
    )
    op.create_index(op.f("ix_tools_organization_id"), "tools", ["organization_id"], unique=False)

    op.create_table(
        "trust_rules",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("applies_to", sa.String(length=16), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=True),
        sa.Column("match_field", sa.String(length=16), nullable=False),
        sa.Column("pattern", sa.String(length=1024), nullable=False),
        sa.Column("trust_level", sa.String(length=16), nullable=False),
        sa.Column("capabilities", JSON_TYPE, nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=40), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_trust_rules_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_trust_rules")),
    )
    op.create_index(op.f("ix_trust_rules_organization_id"), "trust_rules", ["organization_id"], unique=False)

    op.create_table(
        "agents",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("framework", sa.String(length=64), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=True),
        sa.Column("environment", sa.String(length=32), nullable=False),
        sa.Column("labels", JSON_TYPE, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("declared_capabilities", JSON_TYPE, nullable=False),
        sa.Column("integration_id", sa.String(length=40), nullable=True),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("last_seen_at", TIMESTAMP, nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["integration_id"],
            ["integrations.id"],
            name=op.f("fk_agents_integration_id_integrations"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_agents_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agents")),
        sa.UniqueConstraint("organization_id", "name", name=op.f("uq_agents_organization_id_name")),
    )
    op.create_index(op.f("ix_agents_organization_id"), "agents", ["organization_id"], unique=False)

    op.create_table(
        "board_columns",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("board_id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("color", sa.String(length=16), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("wip_limit", sa.Integer(), nullable=True),
        sa.Column("status_key", sa.String(length=32), nullable=False),
        sa.Column("is_done_column", sa.Boolean(), nullable=False),
        sa.Column("requires_verification", sa.Boolean(), nullable=False),
        sa.Column("automation", JSON_TYPE, nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["board_id"], ["boards.id"], name=op.f("fk_board_columns_board_id_boards"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_board_columns_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_board_columns")),
    )
    op.create_index(op.f("ix_board_columns_board_id"), "board_columns", ["board_id"], unique=False)
    op.create_index(
        op.f("ix_board_columns_organization_id"), "board_columns", ["organization_id"], unique=False
    )

    op.create_table(
        "incident_activities",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("incident_id", sa.String(length=40), nullable=False),
        sa.Column("actor", sa.String(length=40), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("details", JSON_TYPE, nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_activities_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_incident_activities_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_activities")),
    )
    op.create_index(
        op.f("ix_incident_activities_incident_id"), "incident_activities", ["incident_id"], unique=False
    )
    op.create_index(
        op.f("ix_incident_activities_organization_id"),
        "incident_activities",
        ["organization_id"],
        unique=False,
    )

    op.create_table(
        "agent_relationships",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("parent_agent_id", sa.String(length=40), nullable=False),
        sa.Column("child_agent_id", sa.String(length=40), nullable=False),
        sa.Column("relationship_type", sa.String(length=32), nullable=False),
        sa.Column("first_seen_at", TIMESTAMP, nullable=False),
        sa.Column("last_seen_at", TIMESTAMP, nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("last_parent_session_id", sa.String(length=40), nullable=True),
        sa.Column("last_child_session_id", sa.String(length=40), nullable=True),
        sa.Column("crosses_trust_boundary", sa.Boolean(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["child_agent_id"],
            ["agents.id"],
            name=op.f("fk_agent_relationships_child_agent_id_agents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_agent_relationships_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["parent_agent_id"],
            ["agents.id"],
            name=op.f("fk_agent_relationships_parent_agent_id_agents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_relationships")),
        sa.UniqueConstraint(
            "organization_id",
            "parent_agent_id",
            "child_agent_id",
            "relationship_type",
            name=op.f(
                "uq_agent_relationships_organization_id_parent_agent_id_child_agent_id_relationship_type"
            ),
        ),
    )
    op.create_index(
        op.f("ix_agent_relationships_child_agent_id"), "agent_relationships", ["child_agent_id"], unique=False
    )
    op.create_index(
        op.f("ix_agent_relationships_organization_id"),
        "agent_relationships",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_agent_relationships_parent_agent_id"),
        "agent_relationships",
        ["parent_agent_id"],
        unique=False,
    )

    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("agent_id", sa.String(length=40), nullable=False),
        sa.Column("external_session_id", sa.String(length=200), nullable=False),
        sa.Column("parent_session_id", sa.String(length=40), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", TIMESTAMP, nullable=False),
        sa.Column("ended_at", TIMESTAMP, nullable=True),
        sa.Column("last_event_at", TIMESTAMP, nullable=True),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("session_metadata", JSON_TYPE, nullable=False),
        sa.Column("risk_state", JSON_TYPE, nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("simulation_run_id", sa.String(length=40), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name=op.f("fk_agent_sessions_agent_id_agents"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_agent_sessions_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["parent_session_id"],
            ["agent_sessions.id"],
            name=op.f("fk_agent_sessions_parent_session_id_agent_sessions"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_sessions")),
        sa.UniqueConstraint(
            "organization_id",
            "agent_id",
            "external_session_id",
            name=op.f("uq_agent_sessions_organization_id_agent_id_external_session_id"),
        ),
    )
    op.create_index(op.f("ix_agent_sessions_agent_id"), "agent_sessions", ["agent_id"], unique=False)
    op.create_index(
        op.f("ix_agent_sessions_organization_id"), "agent_sessions", ["organization_id"], unique=False
    )
    op.create_index(
        op.f("ix_agent_sessions_parent_session_id"), "agent_sessions", ["parent_session_id"], unique=False
    )
    op.create_index(
        op.f("ix_agent_sessions_simulation_run_id"), "agent_sessions", ["simulation_run_id"], unique=False
    )

    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("prefix", sa.String(length=32), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("scopes", JSON_TYPE, nullable=False),
        sa.Column("agent_id", sa.String(length=40), nullable=True),
        sa.Column("created_by_user_id", sa.String(length=40), nullable=True),
        sa.Column("last_used_at", TIMESTAMP, nullable=True),
        sa.Column("expires_at", TIMESTAMP, nullable=True),
        sa.Column("revoked_at", TIMESTAMP, nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name=op.f("fk_api_keys_agent_id_agents"), ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_api_keys_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_keys")),
    )
    op.create_index(op.f("ix_api_keys_key_hash"), "api_keys", ["key_hash"], unique=True)
    op.create_index(op.f("ix_api_keys_organization_id"), "api_keys", ["organization_id"], unique=False)

    op.create_table(
        "tasks",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("board_id", sa.String(length=40), nullable=False),
        sa.Column("column_id", sa.String(length=40), nullable=False),
        sa.Column("position", sa.Float(), nullable=False),
        sa.Column("title", sa.String(length=400), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("task_type", sa.String(length=48), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("reporter_user_id", sa.String(length=40), nullable=True),
        sa.Column("due_date", TIMESTAMP, nullable=True),
        sa.Column("parent_task_id", sa.String(length=40), nullable=True),
        sa.Column("related_agent_id", sa.String(length=40), nullable=True),
        sa.Column("related_incident_id", sa.String(length=40), nullable=True),
        sa.Column("related_finding_id", sa.String(length=40), nullable=True),
        sa.Column("related_files", JSON_TYPE, nullable=False),
        sa.Column("links", JSON_TYPE, nullable=False),
        sa.Column("reproduction_steps", sa.Text(), nullable=False),
        sa.Column("expected_behaviour", sa.Text(), nullable=False),
        sa.Column("actual_behaviour", sa.Text(), nullable=False),
        sa.Column("acceptance_criteria", JSON_TYPE, nullable=False),
        sa.Column("resolution", sa.Text(), nullable=True),
        sa.Column("verification_status", sa.String(length=16), nullable=False),
        sa.Column("verified_at", TIMESTAMP, nullable=True),
        sa.Column("completed_at", TIMESTAMP, nullable=True),
        sa.Column("reopened_count", sa.Integer(), nullable=False),
        sa.Column("archived_at", TIMESTAMP, nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["board_id"], ["boards.id"], name=op.f("fk_tasks_board_id_boards"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["column_id"],
            ["board_columns.id"],
            name=op.f("fk_tasks_column_id_board_columns"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_tasks_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["parent_task_id"], ["tasks.id"], name=op.f("fk_tasks_parent_task_id_tasks"), ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tasks")),
        sa.UniqueConstraint("organization_id", "number", name=op.f("uq_tasks_organization_id_number")),
    )
    op.create_index("ix_tasks_board_column", "tasks", ["board_id", "column_id"], unique=False)
    op.create_index(op.f("ix_tasks_organization_id"), "tasks", ["organization_id"], unique=False)
    op.create_index(op.f("ix_tasks_parent_task_id"), "tasks", ["parent_task_id"], unique=False)
    op.create_index(op.f("ix_tasks_related_finding_id"), "tasks", ["related_finding_id"], unique=False)
    op.create_index(op.f("ix_tasks_related_incident_id"), "tasks", ["related_incident_id"], unique=False)

    op.create_table(
        "context_items",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("source_id", sa.String(length=40), nullable=False),
        sa.Column("agent_id", sa.String(length=40), nullable=False),
        sa.Column("session_id", sa.String(length=40), nullable=False),
        sa.Column("event_id", sa.String(length=40), nullable=False),
        sa.Column("collected_via", sa.String(length=200), nullable=False),
        sa.Column("collected_at", TIMESTAMP, nullable=False),
        sa.Column("received_at", TIMESTAMP, nullable=False),
        sa.Column("content_type", sa.String(length=64), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("content_length", sa.Integer(), nullable=False),
        sa.Column("redacted_preview", sa.Text(), nullable=True),
        sa.Column("sensitivity", sa.String(length=16), nullable=False),
        sa.Column("contains_secrets", sa.Boolean(), nullable=False),
        sa.Column("secret_fingerprints", JSON_TYPE, nullable=False),
        sa.Column("trust_level", sa.String(length=16), nullable=False),
        sa.Column("trust_capabilities", JSON_TYPE, nullable=False),
        sa.Column("detection_summary", JSON_TYPE, nullable=False),
        sa.Column("tool_invocation_id", sa.String(length=40), nullable=True),
        sa.Column("origin_agent_id", sa.String(length=40), nullable=True),
        sa.Column("origin_session_id", sa.String(length=40), nullable=True),
        sa.Column("receipt_signature", sa.String(length=64), nullable=True),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("item_metadata", JSON_TYPE, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name=op.f("fk_context_items_agent_id_agents"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_context_items_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["agent_sessions.id"],
            name=op.f("fk_context_items_session_id_agent_sessions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["context_sources.id"],
            name=op.f("fk_context_items_source_id_context_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_context_items")),
    )
    op.create_index(op.f("ix_context_items_agent_id"), "context_items", ["agent_id"], unique=False)
    op.create_index(op.f("ix_context_items_content_hash"), "context_items", ["content_hash"], unique=False)
    op.create_index(op.f("ix_context_items_event_id"), "context_items", ["event_id"], unique=False)
    op.create_index(
        "ix_context_items_org_received", "context_items", ["organization_id", "received_at"], unique=False
    )
    op.create_index(
        "ix_context_items_org_session", "context_items", ["organization_id", "session_id"], unique=False
    )
    op.create_index(
        op.f("ix_context_items_organization_id"), "context_items", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_context_items_source_id"), "context_items", ["source_id"], unique=False)
    op.create_index(
        op.f("ix_context_items_tool_invocation_id"), "context_items", ["tool_invocation_id"], unique=False
    )

    op.create_table(
        "fix_attempts",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("generated_prompt_id", sa.String(length=40), nullable=True),
        sa.Column("agent_tool", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("branch", sa.String(length=300), nullable=True),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("pr_url", sa.String(length=2048), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("started_at", TIMESTAMP, nullable=True),
        sa.Column("completed_at", TIMESTAMP, nullable=True),
        sa.Column("created_by", sa.String(length=40), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_fix_attempts_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_fix_attempts_task_id_tasks"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fix_attempts")),
    )
    op.create_index(
        op.f("ix_fix_attempts_organization_id"), "fix_attempts", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_fix_attempts_task_id"), "fix_attempts", ["task_id"], unique=False)

    op.create_table(
        "task_activities",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("actor_user_id", sa.String(length=40), nullable=True),
        sa.Column("kind", sa.String(length=48), nullable=False),
        sa.Column("from_value", sa.Text(), nullable=True),
        sa.Column("to_value", sa.Text(), nullable=True),
        sa.Column("details", JSON_TYPE, nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_task_activities_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_task_activities_task_id_tasks"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_activities")),
    )
    op.create_index(
        op.f("ix_task_activities_organization_id"), "task_activities", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_task_activities_task_id"), "task_activities", ["task_id"], unique=False)

    op.create_table(
        "task_assignments",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("user_id", sa.String(length=40), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_task_assignments_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_task_assignments_task_id_tasks"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_task_assignments_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_assignments")),
        sa.UniqueConstraint("task_id", "user_id", name=op.f("uq_task_assignments_task_id_user_id")),
    )
    op.create_index(
        op.f("ix_task_assignments_organization_id"), "task_assignments", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_task_assignments_task_id"), "task_assignments", ["task_id"], unique=False)
    op.create_index(op.f("ix_task_assignments_user_id"), "task_assignments", ["user_id"], unique=False)

    op.create_table(
        "task_attachments",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=400), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=40), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_task_attachments_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_task_attachments_task_id_tasks"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_attachments")),
    )
    op.create_index(
        op.f("ix_task_attachments_organization_id"), "task_attachments", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_task_attachments_task_id"), "task_attachments", ["task_id"], unique=False)

    op.create_table(
        "task_comments",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("author_user_id", sa.String(length=40), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("edited_at", TIMESTAMP, nullable=True),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_task_comments_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_task_comments_task_id_tasks"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_comments")),
    )
    op.create_index(
        op.f("ix_task_comments_organization_id"), "task_comments", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_task_comments_task_id"), "task_comments", ["task_id"], unique=False)

    op.create_table(
        "task_context_refs",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("ref_type", sa.String(length=32), nullable=False),
        sa.Column("ref_id", sa.String(length=40), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_task_context_refs_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_task_context_refs_task_id_tasks"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_context_refs")),
        sa.UniqueConstraint(
            "task_id", "ref_type", "ref_id", name=op.f("uq_task_context_refs_task_id_ref_type_ref_id")
        ),
    )
    op.create_index(
        op.f("ix_task_context_refs_organization_id"), "task_context_refs", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_task_context_refs_task_id"), "task_context_refs", ["task_id"], unique=False)

    op.create_table(
        "task_dependencies",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("depends_on_task_id", sa.String(length=40), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["depends_on_task_id"],
            ["tasks.id"],
            name=op.f("fk_task_dependencies_depends_on_task_id_tasks"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_task_dependencies_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_task_dependencies_task_id_tasks"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_dependencies")),
        sa.UniqueConstraint(
            "task_id", "depends_on_task_id", name=op.f("uq_task_dependencies_task_id_depends_on_task_id")
        ),
    )
    op.create_index(
        op.f("ix_task_dependencies_depends_on_task_id"),
        "task_dependencies",
        ["depends_on_task_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_task_dependencies_organization_id"), "task_dependencies", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_task_dependencies_task_id"), "task_dependencies", ["task_id"], unique=False)

    op.create_table(
        "task_label_links",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("label_id", sa.String(length=40), nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["label_id"],
            ["task_labels.id"],
            name=op.f("fk_task_label_links_label_id_task_labels"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_task_label_links_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_task_label_links_task_id_tasks"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_label_links")),
        sa.UniqueConstraint("task_id", "label_id", name=op.f("uq_task_label_links_task_id_label_id")),
    )
    op.create_index(
        op.f("ix_task_label_links_organization_id"), "task_label_links", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_task_label_links_task_id"), "task_label_links", ["task_id"], unique=False)

    op.create_table(
        "tool_invocations",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("agent_id", sa.String(length=40), nullable=False),
        sa.Column("session_id", sa.String(length=40), nullable=False),
        sa.Column("tool_id", sa.String(length=40), nullable=False),
        sa.Column("request_event_id", sa.String(length=40), nullable=True),
        sa.Column("result_event_id", sa.String(length=40), nullable=True),
        sa.Column("correlation_id", sa.String(length=200), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=True),
        sa.Column("enforcement", sa.String(length=16), nullable=False),
        sa.Column("policy_decision_id", sa.String(length=40), nullable=True),
        sa.Column("approval_id", sa.String(length=40), nullable=True),
        sa.Column("arguments_redacted", JSON_TYPE, nullable=False),
        sa.Column("argument_hash", sa.String(length=64), nullable=True),
        sa.Column("resources", JSON_TYPE, nullable=False),
        sa.Column("destination_id", sa.String(length=40), nullable=True),
        sa.Column("sensitive_data_detected", sa.Boolean(), nullable=False),
        sa.Column("secret_fingerprints", JSON_TYPE, nullable=False),
        sa.Column("matched_session_fingerprints", JSON_TYPE, nullable=False),
        sa.Column("requested_at", TIMESTAMP, nullable=False),
        sa.Column("completed_at", TIMESTAMP, nullable=True),
        sa.Column("result_summary", sa.Text(), nullable=True),
        sa.Column("result_context_item_id", sa.String(length=40), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("updated_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name=op.f("fk_tool_invocations_agent_id_agents"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_tool_invocations_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["agent_sessions.id"],
            name=op.f("fk_tool_invocations_session_id_agent_sessions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tool_id"], ["tools.id"], name=op.f("fk_tool_invocations_tool_id_tools"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tool_invocations")),
    )
    op.create_index(
        "ix_tool_inv_correlation",
        "tool_invocations",
        ["organization_id", "session_id", "correlation_id"],
        unique=False,
    )
    op.create_index(
        "ix_tool_inv_org_requested", "tool_invocations", ["organization_id", "requested_at"], unique=False
    )
    op.create_index(
        "ix_tool_inv_org_session", "tool_invocations", ["organization_id", "session_id"], unique=False
    )
    op.create_index(op.f("ix_tool_invocations_agent_id"), "tool_invocations", ["agent_id"], unique=False)
    op.create_index(
        op.f("ix_tool_invocations_destination_id"), "tool_invocations", ["destination_id"], unique=False
    )
    op.create_index(
        op.f("ix_tool_invocations_organization_id"), "tool_invocations", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_tool_invocations_tool_id"), "tool_invocations", ["tool_id"], unique=False)

    op.create_table(
        "verification_runs",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("fix_attempt_id", sa.String(length=40), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("evidence_url", sa.String(length=2048), nullable=True),
        sa.Column("evidence", JSON_TYPE, nullable=False),
        sa.Column("simulation_run_id", sa.String(length=40), nullable=True),
        sa.Column("created_by", sa.String(length=40), nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("organization_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_verification_runs_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_verification_runs_task_id_tasks"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_verification_runs")),
    )
    op.create_index(
        op.f("ix_verification_runs_organization_id"), "verification_runs", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_verification_runs_task_id"), "verification_runs", ["task_id"], unique=False)


def downgrade() -> None:
    # Dropping a table drops its indexes; tables go in reverse dependency order.
    op.drop_table("verification_runs")
    op.drop_table("tool_invocations")
    op.drop_table("task_label_links")
    op.drop_table("task_dependencies")
    op.drop_table("task_context_refs")
    op.drop_table("task_comments")
    op.drop_table("task_attachments")
    op.drop_table("task_assignments")
    op.drop_table("task_activities")
    op.drop_table("fix_attempts")
    op.drop_table("context_items")
    op.drop_table("tasks")
    op.drop_table("api_keys")
    op.drop_table("agent_sessions")
    op.drop_table("agent_relationships")
    op.drop_table("incident_activities")
    op.drop_table("board_columns")
    op.drop_table("agents")
    op.drop_table("trust_rules")
    op.drop_table("tools")
    op.drop_table("task_labels")
    op.drop_table("simulation_runs")
    op.drop_table("security_policies")
    op.drop_table("security_findings")
    op.drop_table("provenance_edges")
    op.drop_table("prompt_templates")
    op.drop_table("policy_decisions")
    op.drop_table("memberships")
    op.drop_table("integrations")
    op.drop_table("ingested_events")
    op.drop_table("incidents")
    op.drop_table("generated_prompts")
    op.drop_table("destinations")
    op.drop_table("context_sources")
    op.drop_table("context_packs")
    op.drop_table("boards")
    op.drop_table("auth_sessions")
    op.drop_table("audit_events")
    op.drop_table("approvals")
    op.drop_table("users")
    op.drop_table("organizations")
