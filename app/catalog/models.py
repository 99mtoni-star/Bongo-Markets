"""Catalogue: categories, products, images and stock reservations (M08)."""

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
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Money


class ProductStatus(StrEnum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    ARCHIVED = "ARCHIVED"


class ReservationStatus(StrEnum):
    ACTIVE = "ACTIVE"
    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


class Category(Base):
    __tablename__ = "categories"

    id: Mapped[int] = mapped_column(Integer, Identity(always=True), primary_key=True)
    slug: Mapped[str] = mapped_column(String(48), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    parent_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("categories.id"))
    sort: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Product(Base):
    """A product belongs to exactly one shop (BR-007, PRD-002)."""

    __tablename__ = "products"
    __table_args__ = (
        UniqueConstraint("shop_id", "sku", name="uq_products_shop_id_sku"),  # PRD-003
        CheckConstraint("price >= 0", name="price_nonnegative"),            # PRD-004
        CheckConstraint("stock >= 0", name="stock_nonnegative"),
        CheckConstraint("reserved >= 0 AND reserved <= stock", name="reserved_within_stock"),
        CheckConstraint("status IN ('DRAFT','ACTIVE','SUSPENDED','ARCHIVED')", name="status_valid"),
        CheckConstraint("status <> 'ACTIVE' OR price > 0", name="active_needs_price"),
        Index("ix_products_shop_id_status", "shop_id", "status"),
        Index("ix_products_category_id", "category_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True,
                                                 server_default=text("gen_random_uuid()"))
    shop_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("shops.id"), nullable=False)
    category_id: Mapped[int] = mapped_column(Integer, ForeignKey("categories.id"), nullable=False)
    sku: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    unit: Mapped[str] = mapped_column(String(24), nullable=False, default="kipande")
    price: Mapped[Decimal] = mapped_column(Money, nullable=False, default=Decimal("0"))
    stock: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reserved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=ProductStatus.DRAFT)
    marketplace: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    featured: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now(), nullable=False)


class ProductImage(Base):
    __tablename__ = "product_images"
    __table_args__ = (
        CheckConstraint("content_type IN ('image/jpeg','image/png','image/webp')", name="content_type_valid"),
        CheckConstraint("bytes > 0 AND bytes <= 5242880", name="size_limit"),
        Index("ix_product_images_product_id", "product_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True,
                                                 server_default=text("gen_random_uuid()"))
    product_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("products.id"), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    content_type: Mapped[str] = mapped_column(String(24), nullable=False)
    bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    width: Mapped[int] = mapped_column(Integer, nullable=False)
    height: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uploaded_by: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class StockReservation(Base):
    """Stock held for a checkout (STK-001..004)."""

    __tablename__ = "stock_reservations"
    __table_args__ = (
        CheckConstraint("quantity > 0", name="quantity_positive"),
        CheckConstraint("status IN ('ACTIVE','COMMITTED','RELEASED','EXPIRED')", name="status_valid"),
        Index("ix_stock_reservations_active_expiry", "expires_at", postgresql_where=text("status = 'ACTIVE'")),
        Index("ix_stock_reservations_holder", "holder"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True,
                                                 server_default=text("gen_random_uuid()"))
    product_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("products.id"), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    holder: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "order:<uuid>"
    user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=ReservationStatus.ACTIVE)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    note: Mapped[str | None] = mapped_column(Text)
