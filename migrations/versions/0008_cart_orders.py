"""M11/M12: carts, checkouts (idempotency), orders, order items, order status history

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-12

Sensitive-Review: approved by Claude (developer) 2026-10-12, pending independent review.
Financial amounts and personal delivery data (name, phone, address snapshot). A trigger blocks any
payment_status change that does not run inside the verified payment-provider context (BR-015).
"""

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    app_role = context.config.attributes["app_role"]

    op.create_table(
        "carts",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", TS, server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('ACTIVE','CHECKED_OUT','ABANDONED')", name="ck_carts_status_valid"),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_carts_user_id_users"),
        sa.PrimaryKeyConstraint("id", name="pk_carts"),
        schema="bm",
    )
    op.create_index("uq_carts_one_active", "carts", ["user_id"], unique=True, schema="bm",
                    postgresql_where=sa.text("status = 'ACTIVE'"))

    op.create_table(
        "cart_items",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("cart_id", sa.BigInteger(), nullable=False),
        sa.Column("product_id", sa.BigInteger(), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("added_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", TS, server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("quantity BETWEEN 1 AND 999", name="ck_cart_items_quantity_range"),
        sa.ForeignKeyConstraint(["cart_id"], ["bm.carts.id"], name="fk_cart_items_cart_id_carts"),
        sa.ForeignKeyConstraint(["product_id"], ["bm.products.id"], name="fk_cart_items_product_id_products"),
        sa.PrimaryKeyConstraint("id", name="pk_cart_items"),
        sa.UniqueConstraint("cart_id", "product_id", name="uq_cart_items_cart_id_product_id"),
        schema="bm",
    )

    op.create_table(
        "checkouts",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"),
                  nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("idempotency_key", sa.String(80), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("total", sa.Numeric(18, 2), nullable=False),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["bm.users.id"], name="fk_checkouts_user_id_users"),
        sa.PrimaryKeyConstraint("id", name="pk_checkouts"),
        sa.UniqueConstraint("public_id", name="uq_checkouts_public_id"),
        sa.UniqueConstraint("user_id", "idempotency_key", name="uq_checkouts_user_id_idempotency_key"),
        schema="bm",
    )

    op.execute("CREATE SEQUENCE bm.order_number_seq START 1001")
    op.create_table(
        "orders",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"),
                  nullable=False),
        sa.Column("number", sa.String(24), nullable=False),
        sa.Column("checkout_id", sa.BigInteger(), nullable=False),
        sa.Column("buyer_user_id", sa.BigInteger(), nullable=False),
        sa.Column("shop_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("payment_status", sa.String(16), nullable=False),
        sa.Column("payment_method", sa.String(12), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("subtotal", sa.Numeric(18, 2), nullable=False),
        sa.Column("total", sa.Numeric(18, 2), nullable=False),
        sa.Column("items_count", sa.Integer(), nullable=False),
        sa.Column("delivery_name", sa.String(120), nullable=False),
        sa.Column("delivery_phone", sa.String(16), nullable=False),
        sa.Column("delivery_region", sa.String(60), nullable=False),
        sa.Column("delivery_area", sa.String(80), nullable=True),
        sa.Column("delivery_street", sa.String(160), nullable=True),
        sa.Column("delivery_notes", sa.String(300), nullable=True),
        sa.Column("courier_name", sa.String(120), nullable=True),
        sa.Column("courier_phone", sa.String(16), nullable=True),
        sa.Column("delivery_pin_hash", sa.String(64), nullable=True),
        sa.Column("pin_attempts", sa.Integer(), nullable=False),
        sa.Column("cancel_requested_at", TS, nullable=True),
        sa.Column("cancel_reason", sa.String(300), nullable=True),
        sa.Column("refund_required", sa.Boolean(), nullable=False),
        sa.Column("expires_at", TS, nullable=True),
        sa.Column("confirmed_at", TS, nullable=True),
        sa.Column("shipped_at", TS, nullable=True),
        sa.Column("delivered_at", TS, nullable=True),
        sa.Column("cancelled_at", TS, nullable=True),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", TS, server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('PENDING_PAYMENT','CONFIRMED','PROCESSING','SHIPPED','DELIVERED',"
                           "'CANCELLED','EXPIRED')", name="ck_orders_status_valid"),
        sa.CheckConstraint("payment_status IN ('UNPAID','PAID','REFUND_PENDING','REFUNDED')",
                           name="ck_orders_payment_status_valid"),
        sa.CheckConstraint("payment_method IN ('ONLINE','COD')", name="ck_orders_payment_method_valid"),
        sa.CheckConstraint("subtotal >= 0 AND total >= 0 AND total = subtotal", name="ck_orders_totals"),
        sa.CheckConstraint("pin_attempts >= 0", name="ck_orders_pin_attempts_nonnegative"),
        sa.ForeignKeyConstraint(["checkout_id"], ["bm.checkouts.id"], name="fk_orders_checkout_id_checkouts"),
        sa.ForeignKeyConstraint(["buyer_user_id"], ["bm.users.id"], name="fk_orders_buyer_user_id_users"),
        sa.ForeignKeyConstraint(["shop_id"], ["bm.shops.id"], name="fk_orders_shop_id_shops"),
        sa.PrimaryKeyConstraint("id", name="pk_orders"),
        sa.UniqueConstraint("public_id", name="uq_orders_public_id"),
        sa.UniqueConstraint("number", name="uq_orders_number"),
        schema="bm",
    )
    op.create_index("ix_orders_buyer", "orders", ["buyer_user_id", "created_at"], schema="bm")
    op.create_index("ix_orders_shop_status", "orders", ["shop_id", "status", "created_at"], schema="bm")
    op.create_index("ix_orders_pending_expiry", "orders", ["expires_at"], schema="bm",
                    postgresql_where=sa.text("status = 'PENDING_PAYMENT'"))

    op.create_table(
        "order_items",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"),
                  nullable=False),
        sa.Column("order_id", sa.BigInteger(), nullable=False),
        sa.Column("product_id", sa.BigInteger(), nullable=False),
        sa.Column("reservation_id", sa.BigInteger(), nullable=True),
        sa.Column("sku", sa.String(64), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("image_key", sa.String(80), nullable=True),
        sa.Column("unit", sa.String(24), nullable=False),
        sa.Column("unit_price", sa.Numeric(18, 2), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("line_total", sa.Numeric(18, 2), nullable=False),
        sa.CheckConstraint("quantity > 0 AND unit_price >= 0 AND line_total = unit_price * quantity",
                           name="ck_order_items_line_math"),
        sa.ForeignKeyConstraint(["order_id"], ["bm.orders.id"], name="fk_order_items_order_id_orders"),
        sa.ForeignKeyConstraint(["product_id"], ["bm.products.id"], name="fk_order_items_product_id_products"),
        sa.ForeignKeyConstraint(["reservation_id"], ["bm.stock_reservations.id"],
                                name="fk_order_items_reservation_id_stock_reservations"),
        sa.PrimaryKeyConstraint("id", name="pk_order_items"),
        sa.UniqueConstraint("public_id", name="uq_order_items_public_id"),
        schema="bm",
    )
    op.create_index("ix_order_items_order_id", "order_items", ["order_id"], schema="bm")

    op.create_table(
        "order_status_history",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("order_id", sa.BigInteger(), nullable=False),
        sa.Column("from_status", sa.String(20), nullable=True),
        sa.Column("to_status", sa.String(20), nullable=False),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("actor_user_id", sa.BigInteger(), nullable=True),
        sa.Column("note", sa.String(300), nullable=True),
        sa.Column("at", TS, server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["order_id"], ["bm.orders.id"], name="fk_order_status_history_order_id_orders"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["bm.users.id"],
                                name="fk_order_status_history_actor_user_id_users"),
        sa.PrimaryKeyConstraint("id", name="pk_order_status_history"),
        schema="bm",
    )
    op.create_index("ix_order_status_history_order_id", "order_status_history", ["order_id"], schema="bm")

    # BR-015: payment_status changes only inside the verified payment context (set by the payment service
    # with SET LOCAL after provider verification; M13). Any other path — seller, buyer, admin UI — fails.
    op.execute("""
        CREATE FUNCTION bm.guard_payment_status() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.payment_status IS DISTINCT FROM OLD.payment_status
               AND current_setting('bm.payment_context', true) IS DISTINCT FROM 'provider-verified' THEN
                RAISE EXCEPTION 'payment_status can only change after verified payment confirmation'
                    USING ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN NEW;
        END; $$
    """)
    op.execute("CREATE TRIGGER orders_payment_status_guard BEFORE UPDATE ON bm.orders "
               "FOR EACH ROW EXECUTE FUNCTION bm.guard_payment_status()")
    op.execute("""
        CREATE FUNCTION bm.guard_new_order_payment() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.payment_status <> 'UNPAID' THEN
                RAISE EXCEPTION 'new orders start UNPAID' USING ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN NEW;
        END; $$
    """)
    op.execute("CREATE TRIGGER orders_new_unpaid BEFORE INSERT ON bm.orders "
               "FOR EACH ROW EXECUTE FUNCTION bm.guard_new_order_payment()")

    # Privileges
    op.execute(f'GRANT USAGE ON SEQUENCE bm.order_number_seq TO "{app_role}"')
    op.execute(f'REVOKE DELETE, TRUNCATE ON bm.carts FROM "{app_role}"')
    op.execute(f'REVOKE UPDATE ON bm.carts FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (status, updated_at) ON bm.carts TO "{app_role}"')
    op.execute(f'REVOKE UPDATE, TRUNCATE ON bm.cart_items FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (quantity, updated_at) ON bm.cart_items TO "{app_role}"')
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.checkouts FROM "{app_role}"')
    op.execute(f'REVOKE DELETE, TRUNCATE ON bm.orders FROM "{app_role}"')
    op.execute(f'REVOKE UPDATE ON bm.orders FROM "{app_role}"')
    op.execute(f'GRANT UPDATE (status, payment_status, courier_name, courier_phone, delivery_pin_hash, '
               f'pin_attempts, cancel_requested_at, cancel_reason, refund_required, expires_at, confirmed_at, '
               f'shipped_at, delivered_at, cancelled_at, updated_at) ON bm.orders TO "{app_role}"')
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.order_items FROM "{app_role}"')
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON bm.order_status_history FROM "{app_role}"')


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS orders_new_unpaid ON bm.orders")
    op.execute("DROP TRIGGER IF EXISTS orders_payment_status_guard ON bm.orders")
    op.execute("DROP FUNCTION IF EXISTS bm.guard_new_order_payment()")
    op.execute("DROP FUNCTION IF EXISTS bm.guard_payment_status()")
    for t in ("order_status_history", "order_items", "orders", "checkouts", "cart_items", "carts"):
        op.drop_table(t, schema="bm")
    op.execute("DROP SEQUENCE IF EXISTS bm.order_number_seq")
