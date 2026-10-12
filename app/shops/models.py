"""Shops, membership and status history (M07)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Identity, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ShopStatus(StrEnum):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REJECTED = "REJECTED"
    CLOSED = "CLOSED"


# Allowed lifecycle transitions (SHOP-006). Anything else is refused.
TRANSITIONS = {
    ShopStatus.PENDING_VERIFICATION: {ShopStatus.ACTIVE, ShopStatus.REJECTED},
    ShopStatus.ACTIVE: {ShopStatus.SUSPENDED, ShopStatus.CLOSED},
    ShopStatus.SUSPENDED: {ShopStatus.ACTIVE, ShopStatus.CLOSED},
    ShopStatus.REJECTED: {ShopStatus.PENDING_VERIFICATION},
    ShopStatus.CLOSED: set(),
}


class Shop(Base):
    __tablename__ = "shops"
    __table_args__ = (
        CheckConstraint("status IN ('PENDING_VERIFICATION','ACTIVE','SUSPENDED','REJECTED','CLOSED')",
                        name="status_valid"),
        CheckConstraint("slug ~ '^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$'", name="slug_format"),
        Index("ix_shops_owner_user_id", "owner_user_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True,
                                                 server_default=text("gen_random_uuid()"))
    slug: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    region: Mapped[str | None] = mapped_column(String(60))
    owner_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default=ShopStatus.PENDING_VERIFICATION)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now(), nullable=False)


class ShopUser(Base):
    """Membership. Exactly one active OWNER per shop, matching shops.owner_user_id (BR-003/004)."""

    __tablename__ = "shop_users"
    __table_args__ = (
        Index("uq_shop_users_active_member", "shop_id", "user_id", unique=True,
              postgresql_where=text("removed_at IS NULL")),
        Index("uq_shop_users_one_owner", "shop_id", unique=True,
              postgresql_where=text("removed_at IS NULL AND role_code = 'OWNER'")),
        Index("ix_shop_users_user_id", "user_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    shop_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("shops.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    role_code: Mapped[str] = mapped_column(String(32), ForeignKey("shop_roles.code"), nullable=False)
    added_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))


class ShopStatusHistory(Base):
    __tablename__ = "shop_status_history"
    __table_args__ = (Index("ix_shop_status_history_shop_id", "shop_id"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    shop_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("shops.id"), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(24))
    to_status: Mapped[str] = mapped_column(String(24), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    changed_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
