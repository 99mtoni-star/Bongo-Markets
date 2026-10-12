"""M03 identity: users, one-time codes, sessions, rate-limit buckets

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-12

Sensitive-Review: approved by Claude (developer) 2026-10-12, pending independent review.
Creates authentication and personal-data tables (users, auth_codes, user_sessions) and
column-level privileges so the application role cannot change immutable identifiers.
"""

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    app_role = context.config.attributes["app_role"]

    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"),
                  nullable=False),
        sa.Column("full_name", sa.String(120), nullable=False),
        sa.Column("phone_e164", sa.String(16), nullable=False),
        sa.Column("phone_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("email", sa.String(254), nullable=True),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('PENDING_VERIFICATION','ACTIVE','SUSPENDED')", name="ck_users_status_valid"),
        sa.CheckConstraint("phone_e164 ~ '^\\+[1-9][0-9]{7,14}$'", name="ck_users_phone_e164_format"),
        sa.CheckConstraint("email IS NULL OR email = lower(btrim(email))", name="ck_users_email_normalized"),
        sa.CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_nonnegative"),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("public_id", name="uq_users_public_id"),
        schema="bm",
    )
    op.create_index("uq_users_phone_e164", "users", ["phone_e164"], unique=True, schema="bm")
    op.create_index("uq_users_verified_email", "users", ["email"], unique=True, schema="bm",
                    postgresql_where=sa.text("email_verified_at IS NOT NULL"))

    op.create_table(
        "auth_codes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"),
                  nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("purpose", sa.String(24), nullable=False),
        sa.Column("target", sa.String(254), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("purpose IN ('VERIFY_PHONE','VERIFY_EMAIL','RESET_PASSWORD')",
                           name="ck_auth_codes_purpose_valid"),
        sa.CheckConstraint("attempts >= 0", name="ck_auth_codes_attempts_nonnegative"),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_auth_codes_user_id_users",
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_auth_codes"),
        sa.UniqueConstraint("public_id", name="uq_auth_codes_public_id"),
        schema="bm",
    )
    op.create_index("ix_auth_codes_user_purpose", "auth_codes", ["user_id", "purpose"], schema="bm")

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(200), nullable=True),
        sa.Column("ip_hash", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_user_sessions_user_id_users",
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_user_sessions"),
        sa.UniqueConstraint("token_hash", name="uq_user_sessions_token_hash"),
        schema="bm",
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"], schema="bm")

    op.create_table(
        "rate_limit_buckets",
        sa.Column("key", sa.String(200), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("key", "window_start", name="pk_rate_limit_buckets"),
        schema="bm",
    )

    # ID-001 / SEC-INV-007: the app may change mutable fields only. id, public_id and
    # created_at can never be rewritten with application credentials, and the app cannot
    # delete users or sessions (account removal follows a controlled procedure, M05/M19).
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.users FROM "{app_role}"')
    op.execute(
        "GRANT UPDATE (full_name, phone_e164, phone_verified_at, email, email_verified_at, password_hash, "
        "password_changed_at, status, failed_login_count, locked_until, last_login_at, updated_at) "
        f'ON bm.users TO "{app_role}"'
    )
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.auth_codes FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (attempts, consumed_at) ON bm.auth_codes TO "{app_role}"')
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.user_sessions FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (last_seen_at, revoked_at, revoke_reason) ON bm.user_sessions TO "{app_role}"')
    op.execute(f'REVOKE TRUNCATE ON bm.rate_limit_buckets FROM "{app_role}"')


def downgrade() -> None:
    op.drop_table("rate_limit_buckets", schema="bm")
    op.drop_table("user_sessions", schema="bm")
    op.drop_table("auth_codes", schema="bm")
    op.drop_table("users", schema="bm")
