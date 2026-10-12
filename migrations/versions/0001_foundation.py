"""M02 foundation: append-only audit log and system flags

Revision ID: 0001
Revises:
Create Date: 2026-10-12

Sensitive-Review: approved by Claude (developer) 2026-10-12, pending independent review.
Touches audit records (SEC-AUD-001) and privileges (SEC-005).
"""

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    app_role = context.config.attributes["app_role"]

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("category", sa.String(16), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("actor_user_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("entity_type", sa.String(64), nullable=True),
        sa.Column("entity_id", sa.String(64), nullable=True),
        sa.Column("shop_id", sa.BigInteger(), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("details", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.CheckConstraint("category IN ('SECURITY','FINANCIAL','GENERAL')", name="ck_audit_logs_category_valid"),
        sa.PrimaryKeyConstraint("id", name="pk_audit_logs"),
        schema="bm",
    )
    op.create_index("ix_audit_logs_entity", "audit_logs", ["entity_type", "entity_id"], schema="bm")
    op.create_index("ix_audit_logs_occurred_at", "audit_logs", ["occurred_at"], schema="bm")
    op.create_index("ix_audit_logs_actor_user_id", "audit_logs", ["actor_user_id"], schema="bm")

    op.create_table(
        "system_flags",
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_by", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("key", name="pk_system_flags"),
        schema="bm",
    )

    # SEC-AUD-001: append-only from the application's perspective.
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.audit_logs FROM "{app_role}"')
    # Defence in depth: reject UPDATE/DELETE for every role, including the owner.
    # Retention purges (SEC-AUD-004, M05) run through a controlled, separately audited procedure.
    op.execute(
        """
        CREATE FUNCTION bm.reject_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit records are append-only (%)', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON bm.audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION bm.reject_audit_mutation()"
    )
    op.execute(
        "CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON bm.audit_logs "
        "FOR EACH STATEMENT EXECUTE FUNCTION bm.reject_audit_mutation()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON bm.audit_logs")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only ON bm.audit_logs")
    op.execute("DROP FUNCTION IF EXISTS bm.reject_audit_mutation()")
    op.drop_table("system_flags", schema="bm")
    op.drop_table("audit_logs", schema="bm")
