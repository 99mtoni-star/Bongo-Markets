"""Identity and authentication tables (M03)."""

from __future__ import annotations

import uuid
from datetime import datetime
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
    CHANGE_PHONE = "CHANGE_PHONE"
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
    # M04: TOTP second factor. The secret is AES-256-GCM encrypted; the last accepted
    # time step blocks code replay.
    totp_secret_enc: Mapped[str | None] = mapped_column(Text)
    totp_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now(), nullable=False)


class AuthCode(Base):
    """One-time verification / password-reset codes. Only an HMAC of the code is stored."""

    __tablename__ = "auth_codes"
    __table_args__ = (
        CheckConstraint("purpose IN ('VERIFY_PHONE','VERIFY_EMAIL','RESET_PASSWORD','CHANGE_PHONE')",
                        name="purpose_valid"),
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
    # Authenticator assurance level: 1 = password (+SMS), 2 = password + TOTP/recovery code.
    aal: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1", default=1)


class RateLimitBucket(Base):
    """Fixed-window counters shared by every app process (SEC-009)."""

    __tablename__ = "rate_limit_buckets"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class RecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"
    __table_args__ = (Index("ix_mfa_recovery_codes_user_id", "user_id"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class LoginChallenge(Base):
    """Second step of an MFA login: password already verified, TOTP pending."""

    __tablename__ = "login_challenges"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class StepUpGrant(Base):
    """Fresh re-authentication for one high-risk action (SEC-MFA-002, AUTH-008 v1.12.2).

    Bound to the session, the user and a single action; valid for at most 300 s; single-use.
    """

    __tablename__ = "step_up_grants"
    __table_args__ = (CheckConstraint("expires_at <= created_at + interval '300 seconds'", name="max_300s"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_sessions.id", ondelete="CASCADE"),
                                            nullable=False)
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    aal: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PlatformRole(Base):
    """Platform-level roles (full permission matrix arrives in M05)."""

    __tablename__ = "platform_roles"

    code: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    privileged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class UserPlatformRole(Base):
    """Role grants are made only by authorized administrators through the backend (AUTH-008)."""

    __tablename__ = "user_platform_roles"
    __table_args__ = (
        Index("uq_user_platform_roles_active", "user_id", "role_code", unique=True,
              postgresql_where=text("revoked_at IS NULL")),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_code: Mapped[str] = mapped_column(String(32), ForeignKey("platform_roles.code"), nullable=False)
    granted_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))


class ProcessedEvent(Base):
    """Replay guard for signed/timestamped events, e.g. payment webhooks (V13-SEC-002)."""

    __tablename__ = "processed_events"

    source: Mapped[str] = mapped_column(String(48), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                  nullable=False)
