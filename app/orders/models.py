"""Cart, checkout and order tables (M11/M12)."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Money

TS = DateTime(timezone=True)


class OrderStatus(StrEnum):
    PENDING_PAYMENT = "PENDING_PAYMENT"
    CONFIRMED = "CONFIRMED"
    PROCESSING = "PROCESSING"
    SHIPPED = "SHIPPED"
    DELIVERED = "DELIVERED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class PaymentStatus(StrEnum):
    UNPAID = "UNPAID"
    PAID = "PAID"
    REFUND_PENDING = "REFUND_PENDING"
    REFUNDED = "REFUNDED"


class Cart(Base):
    __tablename__ = "carts"
    __table_args__ = (
        CheckConstraint("status IN ('ACTIVE','CHECKED_OUT','ABANDONED')", name="status_valid"),
        Index("uq_carts_one_active", "user_id", unique=True, postgresql_where=text("status = 'ACTIVE'")),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), onupdate=func.now(), nullable=False)


class CartItem(Base):
    __tablename__ = "cart_items"
    __table_args__ = (
        UniqueConstraint("cart_id", "product_id", name="uq_cart_items_cart_id_product_id"),  # CART-002
        CheckConstraint("quantity BETWEEN 1 AND 999", name="quantity_range"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    cart_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("carts.id"), nullable=False)
    product_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("products.id"), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    added_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), onupdate=func.now(), nullable=False)


class Checkout(Base):
    __tablename__ = "checkouts"
    __table_args__ = (UniqueConstraint("user_id", "idempotency_key", name="uq_checkouts_user_id_idempotency_key"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True,
                                                 server_default=text("gen_random_uuid()"))
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    total: Mapped[Decimal] = mapped_column(Money, nullable=False)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)


class Order(Base):
    __tablename__ = "orders"
    __table_args__ = (
        CheckConstraint("status IN ('PENDING_PAYMENT','CONFIRMED','PROCESSING','SHIPPED','DELIVERED',"
                        "'CANCELLED','EXPIRED')", name="status_valid"),
        CheckConstraint("payment_status IN ('UNPAID','PAID','REFUND_PENDING','REFUNDED')",
                        name="payment_status_valid"),
        CheckConstraint("payment_method IN ('ONLINE','COD')", name="payment_method_valid"),
        CheckConstraint("subtotal >= 0 AND total >= 0 AND total = subtotal", name="totals"),
        CheckConstraint("pin_attempts >= 0", name="pin_attempts_nonnegative"),
        Index("ix_orders_buyer", "buyer_user_id", "created_at"),
        Index("ix_orders_shop_status", "shop_id", "status", "created_at"),
        Index("ix_orders_pending_expiry", "expires_at", postgresql_where=text("status = 'PENDING_PAYMENT'")),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True,
                                                 server_default=text("gen_random_uuid()"))
    number: Mapped[str] = mapped_column(String(24), nullable=False, unique=True)
    checkout_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("checkouts.id"), nullable=False)
    buyer_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    shop_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("shops.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    payment_status: Mapped[str] = mapped_column(String(16), nullable=False, default=PaymentStatus.UNPAID)
    payment_method: Mapped[str] = mapped_column(String(12), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="TZS")
    subtotal: Mapped[Decimal] = mapped_column(Money, nullable=False)
    total: Mapped[Decimal] = mapped_column(Money, nullable=False)
    items_count: Mapped[int] = mapped_column(Integer, nullable=False)
    delivery_name: Mapped[str] = mapped_column(String(120), nullable=False)
    delivery_phone: Mapped[str] = mapped_column(String(16), nullable=False)
    delivery_region: Mapped[str] = mapped_column(String(60), nullable=False)
    delivery_area: Mapped[str | None] = mapped_column(String(80))
    delivery_street: Mapped[str | None] = mapped_column(String(160))
    delivery_notes: Mapped[str | None] = mapped_column(String(300))
    courier_name: Mapped[str | None] = mapped_column(String(120))
    courier_phone: Mapped[str | None] = mapped_column(String(16))
    delivery_pin_hash: Mapped[str | None] = mapped_column(String(64))
    pin_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(TS)
    cancel_reason: Mapped[str | None] = mapped_column(String(300))
    refund_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(TS)
    confirmed_at: Mapped[datetime | None] = mapped_column(TS)
    shipped_at: Mapped[datetime | None] = mapped_column(TS)
    delivered_at: Mapped[datetime | None] = mapped_column(TS)
    cancelled_at: Mapped[datetime | None] = mapped_column(TS)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), onupdate=func.now(), nullable=False)


class OrderItem(Base):
    """Commercial snapshot at order time (ORD-003, ORD-002 v1.12.2)."""

    __tablename__ = "order_items"
    __table_args__ = (
        CheckConstraint("quantity > 0 AND unit_price >= 0 AND line_total = unit_price * quantity", name="line_math"),
        Index("ix_order_items_order_id", "order_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True,
                                                 server_default=text("gen_random_uuid()"))
    order_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("orders.id"), nullable=False)
    product_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("products.id"), nullable=False)
    reservation_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("stock_reservations.id"))
    sku: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    image_key: Mapped[str | None] = mapped_column(String(80))
    unit: Mapped[str] = mapped_column(String(24), nullable=False)
    unit_price: Mapped[Decimal] = mapped_column(Money, nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    line_total: Mapped[Decimal] = mapped_column(Money, nullable=False)


class OrderStatusHistory(Base):
    __tablename__ = "order_status_history"
    __table_args__ = (Index("ix_order_status_history_order_id", "order_id"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    order_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("orders.id"), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(20))
    to_status: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))
    note: Mapped[str | None] = mapped_column(String(300))
    at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)
