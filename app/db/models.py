"""Foundation tables owned by M02. Business tables arrive with their modules."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Identity, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditCategory(StrEnum):
    SECURITY = "SECURITY"
    FINANCIAL = "FINANCIAL"
    GENERAL = "GENERAL"


class AuditLog(Base):
    """Append-only audit trail (SEC-AUD-001).

    The application role has INSERT and SELECT only, and a database trigger rejects
    UPDATE and DELETE for every role, so history cannot be rewritten through the app.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("category IN ('SECURITY','FINANCIAL','GENERAL')", name="category_valid"),
        Index("ix_audit_logs_entity", "entity_type", "entity_id"),
        Index("ix_audit_logs_occurred_at", "occurred_at"),
        Index("ix_audit_logs_actor_user_id", "actor_user_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, default="system")
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    shop_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")


class SystemFlag(Base):
    """Operational switches, e.g. payment reconciliation after disaster recovery (NFR-DR-008)."""

    __tablename__ = "system_flags"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system")


PAYMENTS_RECONCILIATION_REQUIRED = "payments_reconciliation_required"
