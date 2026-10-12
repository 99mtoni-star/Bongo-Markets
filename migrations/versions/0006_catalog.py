"""M08 catalogue: categories, products, product images, stock reservations

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-12

Sensitive-Review: approved by Claude (developer) 2026-10-12, pending independent review.
Financial amounts (price) use NUMERIC(18,2); references users (uploader, reservation holder) and sets privileges.
"""

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

CATEGORIES = [
    ("kuku-na-ndege", "Kuku na ndege", 1), ("mayai", "Mayai", 2), ("nyama-na-samaki", "Nyama na samaki", 3),
    ("mboga-na-matunda", "Mboga na matunda", 4), ("nafaka-na-unga", "Nafaka na unga", 5),
    ("vinywaji", "Vinywaji", 6), ("chakula-cha-mifugo", "Chakula cha mifugo", 7),
    ("nyumbani", "Vifaa vya nyumbani", 8), ("mavazi", "Mavazi", 9),
    ("simu-na-elektroniki", "Simu na elektroniki", 10), ("nyingine", "Nyingine", 99),
]


def upgrade() -> None:
    app_role = context.config.attributes["app_role"]

    cats = op.create_table(
        "categories",
        sa.Column("id", sa.Integer(), sa.Identity(always=True), nullable=False),
        sa.Column("slug", sa.String(48), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("parent_id", sa.Integer(), nullable=True),
        sa.Column("sort", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["parent_id"], ["bm.categories.id"], name="fk_categories_parent_id_categories"),
        sa.PrimaryKeyConstraint("id", name="pk_categories"),
        sa.UniqueConstraint("slug", name="uq_categories_slug"),
        schema="bm",
    )
    op.bulk_insert(cats, [{"slug": s, "name": n, "sort": o, "active": True} for s, n, o in CATEGORIES])

    op.create_table(
        "products",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"),
                  nullable=False),
        sa.Column("shop_id", sa.BigInteger(), nullable=False),
        sa.Column("category_id", sa.Integer(), nullable=False),
        sa.Column("sku", sa.String(64), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("unit", sa.String(24), nullable=False),
        sa.Column("price", sa.Numeric(18, 2), nullable=False),
        sa.Column("stock", sa.Integer(), nullable=False),
        sa.Column("reserved", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("marketplace", sa.Boolean(), nullable=False),
        sa.Column("featured", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("price >= 0", name="ck_products_price_nonnegative"),
        sa.CheckConstraint("stock >= 0", name="ck_products_stock_nonnegative"),
        sa.CheckConstraint("reserved >= 0 AND reserved <= stock", name="ck_products_reserved_within_stock"),
        sa.CheckConstraint("status IN ('DRAFT','ACTIVE','SUSPENDED','ARCHIVED')", name="ck_products_status_valid"),
        sa.CheckConstraint("status <> 'ACTIVE' OR price > 0", name="ck_products_active_needs_price"),
        sa.ForeignKeyConstraint(["shop_id"], ["bm.shops.id"], name="fk_products_shop_id_shops"),
        sa.ForeignKeyConstraint(["category_id"], ["bm.categories.id"], name="fk_products_category_id_categories"),
        sa.PrimaryKeyConstraint("id", name="pk_products"),
        sa.UniqueConstraint("public_id", name="uq_products_public_id"),
        sa.UniqueConstraint("shop_id", "sku", name="uq_products_shop_id_sku"),
        schema="bm",
    )
    op.create_index("ix_products_shop_id_status", "products", ["shop_id", "status"], schema="bm")
    op.create_index("ix_products_category_id", "products", ["category_id"], schema="bm")

    op.create_table(
        "product_images",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"),
                  nullable=False),
        sa.Column("product_id", sa.BigInteger(), nullable=False),
        sa.Column("storage_key", sa.String(80), nullable=False),
        sa.Column("content_type", sa.String(24), nullable=False),
        sa.Column("bytes", sa.Integer(), nullable=False),
        sa.Column("width", sa.Integer(), nullable=False),
        sa.Column("height", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("uploaded_by", sa.BigInteger(), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("content_type IN ('image/jpeg','image/png','image/webp')",
                           name="ck_product_images_content_type_valid"),
        sa.CheckConstraint("bytes > 0 AND bytes <= 5242880", name="ck_product_images_size_limit"),
        sa.ForeignKeyConstraint(["product_id"], ["bm.products.id"], name="fk_product_images_product_id_products"),
        sa.ForeignKeyConstraint(["uploaded_by"], ["bm.users.id"], name="fk_product_images_uploaded_by_users"),
        sa.PrimaryKeyConstraint("id", name="pk_product_images"),
        sa.UniqueConstraint("public_id", name="uq_product_images_public_id"),
        sa.UniqueConstraint("storage_key", name="uq_product_images_storage_key"),
        schema="bm",
    )
    op.create_index("ix_product_images_product_id", "product_images", ["product_id"], schema="bm")

    op.create_table(
        "stock_reservations",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"),
                  nullable=False),
        sa.Column("product_id", sa.BigInteger(), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("holder", sa.String(64), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.CheckConstraint("quantity > 0", name="ck_stock_reservations_quantity_positive"),
        sa.CheckConstraint("status IN ('ACTIVE','COMMITTED','RELEASED','EXPIRED')",
                           name="ck_stock_reservations_status_valid"),
        sa.ForeignKeyConstraint(["product_id"], ["bm.products.id"], name="fk_stock_reservations_product_id_products"),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_stock_reservations_user_id_users"),
        sa.PrimaryKeyConstraint("id", name="pk_stock_reservations"),
        sa.UniqueConstraint("public_id", name="uq_stock_reservations_public_id"),
        schema="bm",
    )
    op.create_index("ix_stock_reservations_active_expiry", "stock_reservations", ["expires_at"], schema="bm",
                    postgresql_where=sa.text("status = 'ACTIVE'"))
    op.create_index("ix_stock_reservations_holder", "stock_reservations", ["holder"], schema="bm")

    op.execute("INSERT INTO bm.system_flags(key, value, reason, updated_by) "
               "VALUES ('stock_reservation_minutes', '15', 'STK-001 default', 'migration') ON CONFLICT DO NOTHING")

    for t in ("categories",):
        op.execute(f'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bm.{t} FROM "{app_role}"')
    for t in ("products", "product_images", "stock_reservations"):
        op.execute(f'REVOKE DELETE, TRUNCATE ON bm.{t} FROM "{app_role}"')
    op.execute(f'REVOKE UPDATE ON bm.products FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (category_id, sku, name, description, unit, price, stock, reserved, status, '
               f'marketplace, featured, updated_at) ON bm.products TO "{app_role}"')
    op.execute(f'REVOKE UPDATE ON bm.product_images FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (position, removed_at) ON bm.product_images TO "{app_role}"')
    op.execute(f'REVOKE UPDATE ON bm.stock_reservations FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (status, resolved_at, note) ON bm.stock_reservations TO "{app_role}"')


def downgrade() -> None:
    op.execute("DELETE FROM bm.system_flags WHERE key = 'stock_reservation_minutes'")
    for t in ("stock_reservations", "product_images", "products", "categories"):
        op.drop_table(t, schema="bm")
