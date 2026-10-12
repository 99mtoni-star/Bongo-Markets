"""M07 shops, shop_users, shop_status_history with ownership integrity trigger

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-12

Sensitive-Review: approved by Claude (developer) 2026-10-12, pending independent review.
Shop membership drives shop-scoped authorization (SEC-004); ownership invariants enforced in the DB.
"""

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    app_role = context.config.attributes["app_role"]

    op.create_table(
        "shops",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"),
                  nullable=False),
        sa.Column("slug", sa.String(40), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("region", sa.String(60), nullable=True),
        sa.Column("owner_user_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('PENDING_VERIFICATION','ACTIVE','SUSPENDED','REJECTED','CLOSED')",
                           name="ck_shops_status_valid"),
        sa.CheckConstraint("slug ~ '^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$'", name="ck_shops_slug_format"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["bm.users.id"], name="fk_shops_owner_user_id_users"),
        sa.PrimaryKeyConstraint("id", name="pk_shops"),
        sa.UniqueConstraint("public_id", name="uq_shops_public_id"),
        sa.UniqueConstraint("slug", name="uq_shops_slug"),
        schema="bm",
    )
    op.create_index("ix_shops_owner_user_id", "shops", ["owner_user_id"], schema="bm")

    op.create_table(
        "shop_users",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("shop_id", sa.BigInteger(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("role_code", sa.String(32), nullable=False),
        sa.Column("added_by", sa.BigInteger(), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removed_by", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(["shop_id"], ["bm.shops.id"], name="fk_shop_users_shop_id_shops"),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_shop_users_user_id_users"),
        sa.ForeignKeyConstraint(["role_code"], ["bm.shop_roles.code"], name="fk_shop_users_role_code_shop_roles"),
        sa.ForeignKeyConstraint(["added_by"], ["bm.users.id"], name="fk_shop_users_added_by_users"),
        sa.ForeignKeyConstraint(["removed_by"], ["bm.users.id"], name="fk_shop_users_removed_by_users"),
        sa.PrimaryKeyConstraint("id", name="pk_shop_users"),
        schema="bm",
    )
    op.create_index("uq_shop_users_active_member", "shop_users", ["shop_id", "user_id"], unique=True, schema="bm",
                    postgresql_where=sa.text("removed_at IS NULL"))
    op.create_index("uq_shop_users_one_owner", "shop_users", ["shop_id"], unique=True, schema="bm",
                    postgresql_where=sa.text("removed_at IS NULL AND role_code = 'OWNER'"))
    op.create_index("ix_shop_users_user_id", "shop_users", ["user_id"], schema="bm")

    op.create_table(
        "shop_status_history",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("shop_id", sa.BigInteger(), nullable=False),
        sa.Column("from_status", sa.String(24), nullable=True),
        sa.Column("to_status", sa.String(24), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("changed_by", sa.BigInteger(), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["shop_id"], ["bm.shops.id"], name="fk_shop_status_history_shop_id_shops"),
        sa.ForeignKeyConstraint(["changed_by"], ["bm.users.id"], name="fk_shop_status_history_changed_by_users"),
        sa.PrimaryKeyConstraint("id", name="pk_shop_status_history"),
        schema="bm",
    )
    op.create_index("ix_shop_status_history_shop_id", "shop_status_history", ["shop_id"], schema="bm")

    # BR-003/BR-004/BR-005: at COMMIT, every shop has exactly one active OWNER membership and it is the
    # same user as shops.owner_user_id. Deferred, so an ownership transfer can swap rows inside one transaction.
    op.execute("""
        CREATE FUNCTION bm.check_shop_owner() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE sid bigint;
        DECLARE owner_ok boolean;
        BEGIN
            IF TG_TABLE_NAME = 'shops' THEN sid := NEW.id; ELSE sid := NEW.shop_id; END IF;
            SELECT EXISTS (SELECT 1 FROM bm.shops s JOIN bm.shop_users su
                             ON su.shop_id = s.id AND su.role_code = 'OWNER' AND su.removed_at IS NULL
                            WHERE s.id = sid AND su.user_id = s.owner_user_id)
              INTO owner_ok;
            IF NOT owner_ok THEN
                RAISE EXCEPTION 'shop % must have exactly one active OWNER equal to shops.owner_user_id', sid
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NULL;
        END; $$
    """)
    op.execute("CREATE CONSTRAINT TRIGGER shops_owner_consistent AFTER INSERT OR UPDATE ON bm.shops "
               "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION bm.check_shop_owner()")
    op.execute("CREATE CONSTRAINT TRIGGER shop_users_owner_consistent AFTER INSERT OR UPDATE ON bm.shop_users "
               "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION bm.check_shop_owner()")

    # Privileges: no hard deletes; history is append-only for the app.
    op.execute(f'REVOKE DELETE, TRUNCATE ON bm.shops FROM "{app_role}"')
    op.execute(f'REVOKE UPDATE ON bm.shops FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (name, description, region, owner_user_id, status, updated_at) ON bm.shops '
               f'TO "{app_role}"')
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.shop_users FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (removed_at, removed_by) ON bm.shop_users TO "{app_role}"')
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.shop_status_history FROM "{app_role}"')


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS shop_users_owner_consistent ON bm.shop_users")
    op.execute("DROP TRIGGER IF EXISTS shops_owner_consistent ON bm.shops")
    op.execute("DROP FUNCTION IF EXISTS bm.check_shop_owner()")
    op.drop_table("shop_status_history", schema="bm")
    op.drop_table("shop_users", schema="bm")
    op.drop_table("shops", schema="bm")
