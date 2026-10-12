"""Data-driven authorization model (M05).

Identity (users), authorization (roles -> permissions) and participation
(capabilities such as BUYER/SELLER) are separate concepts (ACT-001). A capability
or profile never implies a permission (ACT-004).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (CheckConstraint("scope IN ('PLATFORM','SHOP')", name="scope_valid"),)

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(String(200), nullable=False)
    high_risk: Mapped[bool] = mapped_column(nullable=False, default=False)


class PlatformRolePermission(Base):
    __tablename__ = "platform_role_permissions"

    role_code: Mapped[str] = mapped_column(String(32), ForeignKey("platform_roles.code"), primary_key=True)
    permission_code: Mapped[str] = mapped_column(String(64), ForeignKey("permissions.code"), primary_key=True)


class ShopRole(Base):
    """Shop-scoped roles (OWNER, MANAGER, STAFF) are a separate scope from platform roles (AUTH-002)."""

    __tablename__ = "shop_roles"

    code: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    rank: Mapped[int] = mapped_column(Integer, nullable=False)  # higher = more authority


class ShopRolePermission(Base):
    __tablename__ = "shop_role_permissions"

    role_code: Mapped[str] = mapped_column(String(32), ForeignKey("shop_roles.code"), primary_key=True)
    permission_code: Mapped[str] = mapped_column(String(64), ForeignKey("permissions.code"), primary_key=True)


class RoleConflict(Base):
    """Segregation of duties: a user may not hold both roles (ACT-009, AUTH-006)."""

    __tablename__ = "role_conflicts"
    __table_args__ = (CheckConstraint("role_a < role_b", name="ordered"),)

    role_a: Mapped[str] = mapped_column(String(32), ForeignKey("platform_roles.code"), primary_key=True)
    role_b: Mapped[str] = mapped_column(String(32), ForeignKey("platform_roles.code"), primary_key=True)
    reason: Mapped[str] = mapped_column(String(200), nullable=False)


class AuthzPolicy(Base):
    """Single row. ``version`` increases on every role-permission change (AUTH-014/016)."""

    __tablename__ = "authz_policy"
    __table_args__ = (CheckConstraint("id = 1", name="single_row"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class UserCapability(Base):
    """Marketplace participation (V13-REQ-007): one user may hold several capabilities."""

    __tablename__ = "user_capabilities"
    __table_args__ = (
        CheckConstraint("capability IN ('BUYER','SELLER','SERVICE_PROVIDER','DELIVERY_AGENT')",
                        name="capability_valid"),
        CheckConstraint("status IN ('PENDING','ACTIVE','SUSPENDED','REVOKED')", name="status_valid"),
        Index("uq_user_capabilities_user_cap", "user_id", "capability", unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    capability: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now(), nullable=False)


class LegalHold(Base):
    """Suspends retention deletion/anonymization for a user's records (SEC-COM-004)."""

    __tablename__ = "legal_holds"
    __table_args__ = (Index("ix_legal_holds_active", "user_id", postgresql_where=text("released_at IS NULL")),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
