"""M05 data-driven RBAC: permissions, shop roles, SoD conflicts, policy version, capabilities,
legal holds, account closure and controlled audit purge

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-12

Sensitive-Review: approved by Claude (developer) 2026-10-12, pending independent review.
Defines the authorization model, adds a SECURITY DEFINER audit-retention purge callable only by
the schema owner, and adds legal holds and user anonymization fields.
"""

import sqlalchemy as sa
from alembic import context, op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

# Literal copy (migrations must not change if application code changes later).
PERMISSIONS = [
    # code, scope, description, high_risk
    ("platform.roles.assign", "PLATFORM", "Grant or revoke platform roles", True),
    ("platform.rbac.manage", "PLATFORM", "Change which permissions a role has", True),
    ("platform.incident.respond", "PLATFORM", "Suspend accounts, force sign-out, suspend payments", True),
    ("platform.users.view", "PLATFORM", "Search and view users (least-privilege view)", False),
    ("platform.shops.verify", "PLATFORM", "Verify, reject, suspend or reactivate shops", True),
    ("platform.settings.manage", "PLATFORM", "Change platform settings such as stock reservation time", True),
    ("platform.audit.view", "PLATFORM", "View audit logs", False),
    ("platform.audit.export", "PLATFORM", "Export audit logs", True),
    ("platform.legal_hold.manage", "PLATFORM", "Place or release legal holds", True),
    ("platform.content.moderate", "PLATFORM", "Moderate products and reviews", False),
    ("finance.payments.view", "PLATFORM", "View payments and settlements", False),
    ("finance.refunds.approve", "PLATFORM", "Approve and process refunds", True),
    ("finance.reports.view", "PLATFORM", "View financial reports", False),
    ("shop.admin.view", "SHOP", "Open the shop administration area", False),
    ("shop.profile.update", "SHOP", "Edit shop name, description and contact details", False),
    ("shop.managers.manage", "SHOP", "Add or remove shop managers", True),
    ("shop.staff.manage", "SHOP", "Add or remove shop staff", False),
    ("shop.ownership.transfer", "SHOP", "Transfer shop ownership", True),
    ("shop.products.manage", "SHOP", "Create and edit products and images", False),
    ("shop.products.price", "SHOP", "Change product prices", False),
    ("shop.orders.view", "SHOP", "View the shop's orders", False),
    ("shop.orders.fulfil", "SHOP", "Update order fulfilment status", False),
    ("shop.payments.configure", "SHOP", "Configure shop payment options (incl. COD)", True),
    ("shop.commission.configure", "SHOP", "Change commission-sharing setting", True),
    ("shop.analytics.view", "SHOP", "View shop analytics", False),
]
PLATFORM_GRANTS = {
    "SUPER_ADMIN": ["platform.roles.assign", "platform.rbac.manage", "platform.incident.respond",
                    "platform.users.view", "platform.shops.verify", "platform.settings.manage",
                    "platform.audit.view", "platform.audit.export", "platform.legal_hold.manage",
                    "finance.reports.view"],
    "PLATFORM_ADMIN": ["platform.incident.respond", "platform.users.view", "platform.shops.verify",
                       "platform.settings.manage", "platform.audit.view", "platform.content.moderate"],
    "FINANCE": ["finance.payments.view", "finance.refunds.approve", "finance.reports.view"],
    "SUPPORT": ["platform.users.view"],
    "MODERATOR": ["platform.content.moderate"],
}
SHOP_ROLES = [("OWNER", "Mmiliki", 30), ("MANAGER", "Meneja", 20), ("STAFF", "Mfanyakazi", 10)]
SHOP_GRANTS = {
    "OWNER": [p for p, s, _, _ in PERMISSIONS if s == "SHOP"],
    "MANAGER": ["shop.admin.view", "shop.profile.update", "shop.staff.manage", "shop.products.manage",
                "shop.products.price", "shop.orders.view", "shop.orders.fulfil", "shop.analytics.view"],
    "STAFF": ["shop.admin.view", "shop.products.manage", "shop.orders.view", "shop.orders.fulfil"],
}
CONFLICTS = [("FINANCE", "SUPPORT", "Support raises refund requests; Finance approves them"),
             ("FINANCE", "MODERATOR", "Moderation decisions must not be combined with payouts")]


def upgrade() -> None:
    app_role = context.config.attributes["app_role"]

    perms = op.create_table(
        "permissions",
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("description", sa.String(200), nullable=False),
        sa.Column("high_risk", sa.Boolean(), nullable=False),
        sa.CheckConstraint("scope IN ('PLATFORM','SHOP')", name="ck_permissions_scope_valid"),
        sa.PrimaryKeyConstraint("code", name="pk_permissions"),
        schema="bm",
    )
    op.bulk_insert(perms, [{"code": c, "scope": s, "description": d, "high_risk": h} for c, s, d, h in PERMISSIONS])

    prp = op.create_table(
        "platform_role_permissions",
        sa.Column("role_code", sa.String(32), nullable=False),
        sa.Column("permission_code", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["role_code"], ["bm.platform_roles.code"],
                                name="fk_platform_role_permissions_role_code_platform_roles"),
        sa.ForeignKeyConstraint(["permission_code"], ["bm.permissions.code"],
                                name="fk_platform_role_permissions_permission_code_permissions"),
        sa.PrimaryKeyConstraint("role_code", "permission_code", name="pk_platform_role_permissions"),
        schema="bm",
    )
    op.bulk_insert(prp, [{"role_code": r, "permission_code": p} for r, ps in PLATFORM_GRANTS.items() for p in ps])

    sr = op.create_table(
        "shop_roles",
        sa.Column("code", sa.String(32), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("code", name="pk_shop_roles"),
        schema="bm",
    )
    op.bulk_insert(sr, [{"code": c, "name": n, "rank": r} for c, n, r in SHOP_ROLES])

    srp = op.create_table(
        "shop_role_permissions",
        sa.Column("role_code", sa.String(32), nullable=False),
        sa.Column("permission_code", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["role_code"], ["bm.shop_roles.code"],
                                name="fk_shop_role_permissions_role_code_shop_roles"),
        sa.ForeignKeyConstraint(["permission_code"], ["bm.permissions.code"],
                                name="fk_shop_role_permissions_permission_code_permissions"),
        sa.PrimaryKeyConstraint("role_code", "permission_code", name="pk_shop_role_permissions"),
        schema="bm",
    )
    op.bulk_insert(srp, [{"role_code": r, "permission_code": p} for r, ps in SHOP_GRANTS.items() for p in ps])

    rc = op.create_table(
        "role_conflicts",
        sa.Column("role_a", sa.String(32), nullable=False),
        sa.Column("role_b", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(200), nullable=False),
        sa.CheckConstraint("role_a < role_b", name="ck_role_conflicts_ordered"),
        sa.ForeignKeyConstraint(["role_a"], ["bm.platform_roles.code"], name="fk_role_conflicts_role_a_platform_roles"),
        sa.ForeignKeyConstraint(["role_b"], ["bm.platform_roles.code"], name="fk_role_conflicts_role_b_platform_roles"),
        sa.PrimaryKeyConstraint("role_a", "role_b", name="pk_role_conflicts"),
        schema="bm",
    )
    op.bulk_insert(rc, [{"role_a": a, "role_b": b, "reason": r} for a, b, r in CONFLICTS])

    pol = op.create_table(
        "authz_policy",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_authz_policy_single_row"),
        sa.PrimaryKeyConstraint("id", name="pk_authz_policy"),
        schema="bm",
    )
    op.bulk_insert(pol, [{"id": 1, "version": 1}])

    op.create_table(
        "user_capabilities",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("capability", sa.String(24), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("capability IN ('BUYER','SELLER','SERVICE_PROVIDER','DELIVERY_AGENT')",
                           name="ck_user_capabilities_capability_valid"),
        sa.CheckConstraint("status IN ('PENDING','ACTIVE','SUSPENDED','REVOKED')",
                           name="ck_user_capabilities_status_valid"),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_user_capabilities_user_id_users",
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_user_capabilities"),
        schema="bm",
    )
    op.create_index("uq_user_capabilities_user_cap", "user_capabilities", ["user_id", "capability"], unique=True,
                    schema="bm")

    op.create_table(
        "legal_holds",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_legal_holds_user_id_users"),
        sa.PrimaryKeyConstraint("id", name="pk_legal_holds"),
        schema="bm",
    )
    op.create_index("ix_legal_holds_active", "legal_holds", ["user_id"], schema="bm",
                    postgresql_where=sa.text("released_at IS NULL"))

    # users: authorization version (fan-out target), closure and anonymization.
    op.add_column("users", sa.Column("authz_version", sa.Integer(), server_default="1", nullable=False), schema="bm")
    op.add_column("users", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True), schema="bm")
    op.add_column("users", sa.Column("anonymized_at", sa.DateTime(timezone=True), nullable=True), schema="bm")
    op.drop_constraint("ck_users_status_valid", "users", schema="bm", type_="check")
    op.create_check_constraint("ck_users_status_valid", "users",
                               "status IN ('PENDING_VERIFICATION','ACTIVE','SUSPENDED','CLOSED')", schema="bm")

    # Privileges
    op.execute(f'GRANT UPDATE (authz_version, closed_at, anonymized_at) ON bm.users TO "{app_role}"')
    for t in ("permissions", "shop_roles", "role_conflicts"):
        op.execute(f'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bm.{t} FROM "{app_role}"')
    # Role-permission mappings are changed only through the RBAC API (policyVersion-checked, audited).
    for t in ("platform_role_permissions", "shop_role_permissions"):
        op.execute(f'REVOKE UPDATE, TRUNCATE ON bm.{t} FROM "{app_role}"')
    op.execute(f'REVOKE INSERT, DELETE, TRUNCATE ON bm.authz_policy FROM "{app_role}"')
    op.execute(f'REVOKE DELETE, TRUNCATE ON bm.user_capabilities FROM "{app_role}"')
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.legal_holds FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (released_at) ON bm.legal_holds TO "{app_role}"')

    # SEC-AUD-004: audit retention purge is a controlled procedure, never ordinary app DML.
    op.execute("""
        CREATE OR REPLACE FUNCTION bm.reject_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' AND current_setting('bm.audit_purge', true) = 'on' THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION 'audit records are append-only (%)', TG_OP USING ERRCODE = 'insufficient_privilege';
        END;
        $$
    """)
    op.execute("""
        CREATE FUNCTION bm.purge_audit_logs(p_category text, p_before timestamptz) RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = bm, pg_temp AS $$
        DECLARE
            min_age interval := CASE p_category WHEN 'FINANCIAL' THEN interval '10 years'
                                                WHEN 'SECURITY' THEN interval '10 years'
                                                ELSE interval '7 years' END;
            n bigint;
        BEGIN
            IF p_before > now() - min_age THEN
                RAISE EXCEPTION 'retention period for % not reached', p_category;
            END IF;
            PERFORM set_config('bm.audit_purge', 'on', true);
            DELETE FROM bm.audit_logs a
             WHERE a.category = p_category AND a.occurred_at < p_before
               AND NOT EXISTS (SELECT 1 FROM bm.legal_holds h WHERE h.released_at IS NULL
                               AND (h.user_id = a.actor_user_id
                                    OR (a.entity_type = 'user' AND a.entity_id = h.user_id::text)));
            GET DIAGNOSTICS n = ROW_COUNT;
            PERFORM set_config('bm.audit_purge', 'off', true);
            INSERT INTO bm.audit_logs(category, action, actor_type, details)
            VALUES ('SECURITY', 'audit.retention_purge', 'dba',
                    jsonb_build_object('category', p_category, 'before', p_before, 'deleted', n));
            RETURN n;
        END;
        $$
    """)
    op.execute("REVOKE ALL ON FUNCTION bm.purge_audit_logs(text, timestamptz) FROM PUBLIC")
    op.execute(f'REVOKE ALL ON FUNCTION bm.purge_audit_logs(text, timestamptz) FROM "{app_role}"')


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS bm.purge_audit_logs(text, timestamptz)")
    op.execute("""
        CREATE OR REPLACE FUNCTION bm.reject_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit records are append-only (%)', TG_OP USING ERRCODE = 'insufficient_privilege';
        END;
        $$
    """)
    op.drop_constraint("ck_users_status_valid", "users", schema="bm", type_="check")
    op.create_check_constraint("ck_users_status_valid", "users",
                               "status IN ('PENDING_VERIFICATION','ACTIVE','SUSPENDED')", schema="bm")
    for col in ("anonymized_at", "closed_at", "authz_version"):
        op.drop_column("users", col, schema="bm")
    for t in ("legal_holds", "user_capabilities", "authz_policy", "role_conflicts", "shop_role_permissions",
              "shop_roles", "platform_role_permissions", "permissions"):
        op.drop_table(t, schema="bm")
