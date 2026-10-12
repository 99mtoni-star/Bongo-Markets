"""M04: TOTP MFA, recovery codes, login challenges, step-up grants, platform roles, replay guard

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-12

Sensitive-Review: approved by Claude (developer) 2026-10-12, pending independent review.
Adds authentication factors (encrypted TOTP secrets, hashed recovery codes), privileged role
grants and step-up grants; tightens column privileges for the application role.
"""

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

ROLES = [
    ("SUPER_ADMIN", "Super Admin", True),
    ("PLATFORM_ADMIN", "Platform Admin", True),
    ("FINANCE", "Finance", True),
    ("SUPPORT", "Support", True),
    ("MODERATOR", "Moderator", True),
]


def upgrade() -> None:
    app_role = context.config.attributes["app_role"]

    op.add_column("users", sa.Column("totp_secret_enc", sa.Text(), nullable=True), schema="bm")
    op.add_column("users", sa.Column("totp_enabled_at", sa.DateTime(timezone=True), nullable=True), schema="bm")
    op.add_column("users", sa.Column("totp_last_step", sa.BigInteger(), nullable=True), schema="bm")
    op.add_column("user_sessions", sa.Column("aal", sa.Integer(), server_default="1", nullable=False), schema="bm")

    op.drop_constraint("ck_auth_codes_purpose_valid", "auth_codes", schema="bm", type_="check")
    op.create_check_constraint("ck_auth_codes_purpose_valid", "auth_codes",
                               "purpose IN ('VERIFY_PHONE','VERIFY_EMAIL','RESET_PASSWORD','CHANGE_PHONE')",
                               schema="bm")

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_mfa_recovery_codes_user_id_users",
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_mfa_recovery_codes"),
        sa.UniqueConstraint("code_hash", name="uq_mfa_recovery_codes_code_hash"),
        schema="bm",
    )
    op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"], schema="bm")

    op.create_table(
        "login_challenges",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_login_challenges_user_id_users",
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_login_challenges"),
        sa.UniqueConstraint("public_id", name="uq_login_challenges_public_id"),
        schema="bm",
    )

    op.create_table(
        "step_up_grants",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("session_id", sa.BigInteger(), nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("aal", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("expires_at <= created_at + interval '300 seconds'", name="ck_step_up_grants_max_300s"),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_step_up_grants_user_id_users",
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["session_id"], ["bm.user_sessions.id"],
                                name="fk_step_up_grants_session_id_user_sessions", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_step_up_grants"),
        sa.UniqueConstraint("token_hash", name="uq_step_up_grants_token_hash"),
        schema="bm",
    )

    roles = op.create_table(
        "platform_roles",
        sa.Column("code", sa.String(32), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("privileged", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("code", name="pk_platform_roles"),
        schema="bm",
    )
    op.bulk_insert(roles, [{"code": c, "name": n, "privileged": p} for c, n, p in ROLES])

    op.create_table(
        "user_platform_roles",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("role_code", sa.String(32), nullable=False),
        sa.Column("granted_by", sa.BigInteger(), nullable=True),
        sa.Column("granted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_user_platform_roles_user_id_users",
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_code"], ["bm.platform_roles.code"],
                                name="fk_user_platform_roles_role_code_platform_roles"),
        sa.ForeignKeyConstraint(["granted_by"], ["bm.users.id"], name="fk_user_platform_roles_granted_by_users"),
        sa.ForeignKeyConstraint(["revoked_by"], ["bm.users.id"], name="fk_user_platform_roles_revoked_by_users"),
        sa.PrimaryKeyConstraint("id", name="pk_user_platform_roles"),
        schema="bm",
    )
    op.create_index("uq_user_platform_roles_active", "user_platform_roles", ["user_id", "role_code"], unique=True,
                    schema="bm", postgresql_where=sa.text("revoked_at IS NULL"))

    op.create_table(
        "processed_events",
        sa.Column("source", sa.String(48), nullable=False),
        sa.Column("event_id", sa.String(128), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("source", "event_id", name="pk_processed_events"),
        schema="bm",
    )

    # Column-level privileges for the application role.
    op.execute(f'GRANT UPDATE (totp_secret_enc, totp_enabled_at, totp_last_step) ON bm.users TO "{app_role}"')
    op.execute(f'GRANT UPDATE (aal) ON bm.user_sessions TO "{app_role}"')
    for table, cols in (("mfa_recovery_codes", "used_at"), ("login_challenges", "attempts, consumed_at"),
                        ("step_up_grants", "used_at"), ("user_platform_roles", "revoked_at, revoked_by")):
        op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.{table} FROM "{app_role}"')
        op.execute(f'GRANT UPDATE ({cols}) ON bm.{table} TO "{app_role}"')
    # Roles catalogue and replay log are read/insert-only for the app.
    op.execute(f'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bm.platform_roles FROM "{app_role}"')
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.processed_events FROM "{app_role}"')


def downgrade() -> None:
    for table in ("processed_events", "user_platform_roles", "platform_roles", "step_up_grants",
                  "login_challenges", "mfa_recovery_codes"):
        op.drop_table(table, schema="bm")
    op.drop_constraint("ck_auth_codes_purpose_valid", "auth_codes", schema="bm", type_="check")
    op.create_check_constraint("ck_auth_codes_purpose_valid", "auth_codes",
                               "purpose IN ('VERIFY_PHONE','VERIFY_EMAIL','RESET_PASSWORD')", schema="bm")
    op.drop_column("user_sessions", "aal", schema="bm")
    for col in ("totp_last_step", "totp_enabled_at", "totp_secret_enc"):
        op.drop_column("users", col, schema="bm")
