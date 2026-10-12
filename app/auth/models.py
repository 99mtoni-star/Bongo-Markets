"""Identity and authentication tables (M03)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

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
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UserStatus(StrEnum):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"  # set by administrators (M19)


class CodePurpose(StrEnum):
    VERIFY_PHONE = "VERIFY_PHONE"
    VERIFY_EMAIL = "VERIFY_EMAIL"
    RESET_PASSWORD = "RESET_PASSWORD"  # noqa: S105 - enum label, not a secret


class User(Base):
    """The immutable ``id`` is the principal (ID-001); phone and email are mutable identifiers."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("status IN ('PENDING_VERIFICATION','ACTIVE','SUSPENDED')", name="status_valid"),
        CheckConstraint("phone_e164 ~ '^\\+[1-9][0-9]{7,14}$'", name="phone_e164_format"),
        CheckConstraint("email IS NULL OR email = lower(btrim(email))", name="email_normalized"),
        CheckConstraint("failed_login_count >= 0", name="failed_login_nonnegative"),
        # Only one ACTIVE/SUSPENDED account per phone; abandoned pending sign-ups can be replaced.
        Index("uq_users_phone_e164", "phone_e164", unique=True),
        # A verified email belongs to one account; unverified emails never block anyone.
        Index("uq_users_verified_email", "email", unique=True,
              postgresql_where=text("email_verified_at IS NOT NULL")),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True,
                                                 server_default=text("gen_random_uuid()"))
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone_e164: Mapped[str] = mapped_column(String(16), nullable=False)
    phone_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    email: Mapped[str | None] = mapped_column(String(254))
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                          nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default=UserStatus.PENDING_VERIFICATION)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now(), nullable=False)


class AuthCode(Base):
    """One-time verification / password-reset codes. Only an HMAC of the code is stored."""

    __tablename__ = "auth_codes"
    __table_args__ = (
        CheckConstraint("purpose IN ('VERIFY_PHONE','VERIFY_EMAIL','RESET_PASSWORD')", name="purpose_valid"),
        CheckConstraint("attempts >= 0", name="attempts_nonnegative"),
        Index("ix_auth_codes_user_purpose", "user_id", "purpose"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True,
                                                 server_default=text("gen_random_uuid()"))
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    purpose: Mapped[str] = mapped_column(String(24), nullable=False)
    target: Mapped[str] = mapped_column(String(254), nullable=False)  # phone or email the code was sent to
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class UserSession(Base):
    """Server-side session. The cookie carries a random token; only its SHA-256 is stored."""

    __tablename__ = "user_sessions"
    __table_args__ = (Index("ix_user_sessions_user_id", "user_id"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(200))
    ip_hash: Mapped[str | None] = mapped_column(String(64))


class RateLimitBucket(Base):
    """Fixed-window counters shared by every app process (SEC-009)."""

    __tablename__ = "rate_limit_buckets"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
