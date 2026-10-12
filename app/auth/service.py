"""Registration, verification, login and password management (M03).

Rules enforced here:
- Responses never reveal whether a phone/email/account exists (SEC-PWD-005, ID-006).
- Failure counters and rate limits persist even when the request fails (commit before raising).
- Secrets (passwords, codes, tokens) never reach audit logs (SEC-010).
- Password change/reset revokes sessions (SEC-014).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session

from app.auth import ratelimit as rl
from app.auth.identifiers import IdentifierError, classify, mask_phone, normalize_email, normalize_phone
from app.auth.models import AuthCode, CodePurpose, User, UserSession, UserStatus
from app.auth.notify import Notifier
from app.auth.passwords import PasswordPolicyError, check_policy, hash_password, needs_rehash, verify_password
from app.auth.tokens import equal, keyed_hash, new_otp, new_session_token, sha256_hex
from app.core.config import Settings
from app.db.models import AuditCategory
from app.services import audit

GENERIC_LOGIN_FAILED = "Taarifa za kuingia si sahihi, au akaunti imefungwa kwa muda. Jaribu tena baadaye."
GENERIC_CODE_FAILED = "Namba ya uthibitisho si sahihi au muda wake umekwisha."
REGISTER_ACCEPTED = "Tumetuma namba ya uthibitisho kwa SMS. Iingize ili kukamilisha usajili."
RESET_ACCEPTED = "Kama akaunti ipo, tumetuma namba ya kurejesha nenosiri."
RATE_LIMITED = "Majaribio mengi mno. Subiri kidogo kisha ujaribu tena."


class AuthError(Exception):
    def __init__(self, message: str, *, status: int = 400, code: str = "auth_error", field: str | None = None,
                 retry_after: int | None = None, verification_id: str | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.field = field
        self.retry_after = retry_after
        self.verification_id = verification_id


@dataclass
class Client:
    ip: str = "unknown"
    user_agent: str | None = None


@dataclass
class SessionContext:
    user: User
    session: UserSession


def _now() -> datetime:
    return datetime.now(UTC)


class AuthService:
    def __init__(self, db: Session, settings: Settings, engine: Engine, notifier: Notifier, client: Client):
        self.db = db
        self.settings = settings
        self.engine = engine
        self.notifier = notifier
        self.client = client
        self.ip_key = keyed_hash(settings, "ip", client.ip)

    # ------------------------------------------------------------------ helpers
    def _limit(self, limit: rl.Limit, subject: str) -> None:
        try:
            rl.hit(self.engine, limit, subject)
        except rl.RateLimited as exc:
            audit.record(self.db, action="security.rate_limited", category=AuditCategory.SECURITY,
                         details={"limit": limit.name})
            self.db.commit()
            raise AuthError(RATE_LIMITED, status=429, code="rate_limited", retry_after=exc.retry_after) from None

    def _fail(self, message: str, **kw) -> AuthError:
        self.db.commit()  # persist counters/audit before reporting failure
        return AuthError(message, **kw)

    def _issue_code(self, user: User, purpose: CodePurpose, target: str, ttl_minutes: int) -> tuple[AuthCode, str]:
        now = _now()
        # Only the newest code of a purpose is valid.
        self.db.execute(
            update(AuthCode)
            .where(AuthCode.user_id == user.id, AuthCode.purpose == purpose.value, AuthCode.consumed_at.is_(None))
            .values(consumed_at=now)
        )
        code = new_otp()
        row = AuthCode(user_id=user.id, purpose=purpose.value, target=target,
                       code_hash=keyed_hash(self.settings, f"otp:{purpose.value}", code),
                       attempts=0, expires_at=now + timedelta(minutes=ttl_minutes))
        self.db.add(row)
        self.db.flush()
        return row, code

    def _consume_code(self, public_id: str, purpose: CodePurpose, code: str) -> AuthCode:
        try:
            pid = uuid.UUID(str(public_id))
        except ValueError:
            raise self._fail(GENERIC_CODE_FAILED, code="invalid_code") from None
        row = self.db.execute(
            select(AuthCode).where(AuthCode.public_id == pid, AuthCode.purpose == purpose.value).with_for_update()
        ).scalar_one_or_none()
        if row is None or row.consumed_at is not None or row.expires_at <= _now() \
                or row.attempts >= self.settings.otp_max_attempts:
            raise self._fail(GENERIC_CODE_FAILED, code="invalid_code")
        expected = keyed_hash(self.settings, f"otp:{purpose.value}", (code or "").strip())
        if not equal(expected, row.code_hash):
            row.attempts += 1
            audit.record(self.db, action="auth.code_failed", category=AuditCategory.SECURITY,
                         actor_user_id=row.user_id, entity_type="user", entity_id=row.user_id,
                         details={"purpose": purpose.value, "attempts": row.attempts})
            raise self._fail(GENERIC_CODE_FAILED, code="invalid_code")
        row.consumed_at = _now()
        return row

    def _create_session(self, user: User) -> str:
        token = new_session_token()
        now = _now()
        self.db.add(UserSession(
            user_id=user.id, token_hash=sha256_hex(token),
            expires_at=now + timedelta(hours=self.settings.session_ttl_hours),
            user_agent=(self.client.user_agent or "")[:200] or None, ip_hash=self.ip_key,
        ))
        return token

    def revoke_all_sessions(self, user_id: int, reason: str, except_session_id: int | None = None) -> int:
        stmt = (update(UserSession)
                .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
                .values(revoked_at=_now(), revoke_reason=reason))
        if except_session_id is not None:
            stmt = stmt.where(UserSession.id != except_session_id)
        count = self.db.execute(stmt).rowcount or 0
        audit.record(self.db, action="auth.sessions_revoked", category=AuditCategory.SECURITY,
                     actor_user_id=user_id, entity_type="user", entity_id=user_id,
                     details={"reason": reason, "count": count})
        return count

    def _sms(self, phone: str, body: str) -> None:
        self.notifier.send("sms", phone, body)

    @staticmethod
    def _clean_name(name: str) -> str:
        name = " ".join((name or "").split())
        if not 2 <= len(name) <= 120:
            raise AuthError("Andika jina lako kamili (herufi 2 hadi 120).", status=422, code="invalid",
                            field="full_name")
        return name

    # ------------------------------------------------------------------ registration (AUTH-001)
    def register(self, *, full_name: str, phone: str, password: str, email: str | None = None) -> str:
        self._limit(rl.REGISTER_PER_IP, self.ip_key)
        name = self._clean_name(full_name)
        try:
            phone_e164 = normalize_phone(phone, self.settings.default_phone_region)
        except IdentifierError as exc:
            raise AuthError(str(exc), status=422, code="invalid", field="phone") from None
        email_norm = None
        if email and email.strip():
            try:
                email_norm = normalize_email(email)
            except IdentifierError as exc:
                raise AuthError(str(exc), status=422, code="invalid", field="email") from None
        try:
            check_policy(password, personal=[*name.split(), phone_e164, phone_e164[-9:],
                                             (email_norm or "").split("@")[0]])
        except PasswordPolicyError as exc:
            raise AuthError(str(exc), status=422, code="weak_password", field="password") from None
        self._limit(rl.REGISTER_PER_PHONE, keyed_hash(self.settings, "phone", phone_e164))

        password_hash = hash_password(password)  # always hash: equal work for new and existing numbers
        user = self.db.execute(select(User).where(User.phone_e164 == phone_e164).with_for_update()) \
            .scalar_one_or_none()

        if user is not None and user.status != UserStatus.PENDING_VERIFICATION:
            # Do not reveal that the number is registered (ID-006). Tell the real owner instead.
            self._sms(phone_e164, "Bongo Markets: Mtu amejaribu kufungua akaunti mpya kwa namba yako. "
                                  "Kama ni wewe, tumia 'Umesahau nenosiri?' kuingia.")
            audit.record(self.db, action="user.register_existing_number", category=AuditCategory.SECURITY,
                         entity_type="user", entity_id=user.id)
            self.db.commit()
            return str(uuid.uuid4())  # decoy id: verification will fail exactly like a wrong code

        if user is None:
            user = User(full_name=name, phone_e164=phone_e164, email=email_norm, password_hash=password_hash,
                        status=UserStatus.PENDING_VERIFICATION, failed_login_count=0)
            self.db.add(user)
            self.db.flush()
        else:  # abandoned, never-verified sign-up for this number is replaced
            user.full_name, user.email, user.password_hash = name, email_norm, password_hash
            user.password_changed_at = _now()

        row, code = self._issue_code(user, CodePurpose.VERIFY_PHONE, phone_e164, self.settings.otp_ttl_minutes)
        self._sms(phone_e164, f"Bongo Markets: Namba yako ya uthibitisho ni {code}. "
                              f"Inaisha baada ya dakika {self.settings.otp_ttl_minutes}. Usimpe mtu yeyote.")
        audit.record(self.db, action="user.registration_started", category=AuditCategory.SECURITY,
                     entity_type="user", entity_id=user.id, details={"phone": mask_phone(phone_e164)})
        self.db.commit()
        return str(row.public_id)

    def verify_phone(self, verification_id: str, code: str) -> str:
        """Confirm the phone code, activate the account and sign the user in. Returns a session token."""
        self._limit(rl.OTP_VERIFY_PER_IP, self.ip_key)
        row = self._consume_code(verification_id, CodePurpose.VERIFY_PHONE, code)
        user = self.db.get(User, row.user_id, with_for_update=True)
        if user is None or user.phone_e164 != row.target:
            raise self._fail(GENERIC_CODE_FAILED, code="invalid_code")
        user.phone_verified_at = _now()
        if user.status == UserStatus.PENDING_VERIFICATION:
            user.status = UserStatus.ACTIVE
        audit.record(self.db, action="user.phone_verified", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id)
        token = self._create_session(user)
        user.last_login_at = _now()
        self.db.commit()
        return token

    def resend_code(self, verification_id: str) -> str:
        """Re-send a phone verification code. Always answers the same way."""
        self._limit(rl.RESEND_PER_ID, keyed_hash(self.settings, "vid", str(verification_id)))
        try:
            pid = uuid.UUID(str(verification_id))
        except ValueError:
            return str(uuid.uuid4())
        old = self.db.execute(select(AuthCode).where(
            AuthCode.public_id == pid, AuthCode.purpose == CodePurpose.VERIFY_PHONE.value)).scalar_one_or_none()
        user = self.db.get(User, old.user_id) if old else None
        if not old or not user or user.status != UserStatus.PENDING_VERIFICATION:
            return str(uuid.uuid4())
        row, code = self._issue_code(user, CodePurpose.VERIFY_PHONE, user.phone_e164, self.settings.otp_ttl_minutes)
        self._sms(user.phone_e164, f"Bongo Markets: Namba yako mpya ya uthibitisho ni {code}. Usimpe mtu yeyote.")
        self.db.commit()
        return str(row.public_id)

    # ------------------------------------------------------------------ login (AUTH-007, SEC-PWD-005)
    def login(self, identifier: str, password: str) -> str:
        self._limit(rl.LOGIN_PER_IP, self.ip_key)
        try:
            kind, ident = classify(identifier, self.settings.default_phone_region)
        except IdentifierError:
            kind, ident = "invalid", (identifier or "").strip().lower()[:254]
        self._limit(rl.LOGIN_PER_ID, keyed_hash(self.settings, "id", ident))

        user = None
        if kind == "phone":
            user = self.db.execute(select(User).where(User.phone_e164 == ident).with_for_update()).scalar_one_or_none()
        elif kind == "email":
            user = self.db.execute(select(User).where(
                User.email == ident, User.email_verified_at.is_not(None)).with_for_update()).scalar_one_or_none()

        ok = verify_password(user.password_hash if user else None, password or "")
        now = _now()

        if user is None:
            audit.record(self.db, action="auth.login_failed", category=AuditCategory.SECURITY,
                         details={"identifier_key": keyed_hash(self.settings, "id", ident)[:16], "reason": "unknown"})
            raise self._fail(GENERIC_LOGIN_FAILED, status=401, code="login_failed")

        if user.locked_until and user.locked_until > now:
            audit.record(self.db, action="auth.login_blocked_locked", category=AuditCategory.SECURITY,
                         entity_type="user", entity_id=user.id)
            raise self._fail(GENERIC_LOGIN_FAILED, status=401, code="login_failed")

        if not ok:
            user.failed_login_count += 1
            reason = "bad_password"
            if user.failed_login_count >= self.settings.login_max_failures:
                user.locked_until = now + timedelta(minutes=self.settings.lockout_minutes)
                user.failed_login_count = 0
                reason = "locked"
                audit.record(self.db, action="auth.account_locked", category=AuditCategory.SECURITY,
                             entity_type="user", entity_id=user.id,
                             details={"minutes": self.settings.lockout_minutes})
                self._sms(user.phone_e164, "Bongo Markets: Akaunti yako imefungwa kwa muda baada ya majaribio "
                                           "mengi ya kuingia. Kama si wewe, badilisha nenosiri lako.")
            audit.record(self.db, action="auth.login_failed", category=AuditCategory.SECURITY,
                         entity_type="user", entity_id=user.id, details={"reason": reason})
            raise self._fail(GENERIC_LOGIN_FAILED, status=401, code="login_failed")

        if user.status == UserStatus.SUSPENDED:
            audit.record(self.db, action="auth.login_blocked_suspended", category=AuditCategory.SECURITY,
                         entity_type="user", entity_id=user.id)
            raise self._fail(GENERIC_LOGIN_FAILED, status=401, code="login_failed")

        if user.status == UserStatus.PENDING_VERIFICATION:
            # Correct password proves ownership of the sign-up, so it is safe to say verification is needed.
            row, code = self._issue_code(user, CodePurpose.VERIFY_PHONE, user.phone_e164,
                                         self.settings.otp_ttl_minutes)
            self._sms(user.phone_e164, f"Bongo Markets: Namba yako ya uthibitisho ni {code}. Usimpe mtu yeyote.")
            raise self._fail("Thibitisha namba yako ya simu kwanza. Tumekutumia namba mpya ya uthibitisho.",
                             status=403, code="verification_required", verification_id=str(row.public_id))

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
        token = self._create_session(user)
        audit.record(self.db, action="auth.login_succeeded", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id)
        self.db.commit()
        return token

    # ------------------------------------------------------------------ sessions
    def session_from_token(self, token: str | None) -> SessionContext | None:
        if not token or len(token) > 200:
            return None
        row = self.db.execute(select(UserSession).where(UserSession.token_hash == sha256_hex(token))) \
            .scalar_one_or_none()
        now = _now()
        if row is None or row.revoked_at is not None or row.expires_at <= now \
                or row.last_seen_at + timedelta(hours=self.settings.session_idle_hours) <= now:
            return None
        user = self.db.get(User, row.user_id)
        if user is None or user.status != UserStatus.ACTIVE:
            return None
        if now - row.last_seen_at > timedelta(minutes=5):
            row.last_seen_at = now
        return SessionContext(user=user, session=row)

    def logout(self, ctx: SessionContext) -> None:
        ctx.session.revoked_at = _now()
        ctx.session.revoke_reason = "logout"
        audit.record(self.db, action="auth.logout", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, entity_type="user", entity_id=ctx.user.id)
        self.db.commit()

    # ------------------------------------------------------------------ password change (SEC-014)
    def change_password(self, ctx: SessionContext, current: str, new: str) -> str:
        self._limit(rl.LOGIN_PER_ID, keyed_hash(self.settings, "id", ctx.user.phone_e164))
        user = self.db.get(User, ctx.user.id, with_for_update=True)
        if not verify_password(user.password_hash, current or ""):
            audit.record(self.db, action="auth.password_change_failed", category=AuditCategory.SECURITY,
                         actor_user_id=user.id, entity_type="user", entity_id=user.id)
            raise self._fail("Nenosiri la sasa si sahihi.", status=400, code="bad_current_password",
                             field="current_password")
        try:
            check_policy(new, personal=[*user.full_name.split(), user.phone_e164, user.phone_e164[-9:],
                                        (user.email or "").split("@")[0]])
        except PasswordPolicyError as exc:
            raise AuthError(str(exc), status=422, code="weak_password", field="new_password") from None
        if verify_password(user.password_hash, new):
            raise AuthError("Nenosiri jipya lisifanane na la zamani.", status=422, code="weak_password",
                            field="new_password")
        user.password_hash = hash_password(new)
        user.password_changed_at = _now()
        self.revoke_all_sessions(user.id, "password_changed")
        token = self._create_session(user)
        audit.record(self.db, action="auth.password_changed", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id)
        self._sms(user.phone_e164, "Bongo Markets: Nenosiri lako limebadilishwa. "
                                   "Kama si wewe, wasiliana nasi mara moja.")
        self.db.commit()
        return token

    # ------------------------------------------------------------------ password reset (SEC-PWD-006)
    def forgot_password(self, identifier: str) -> str:
        self._limit(rl.RESET_PER_IP, self.ip_key)
        try:
            kind, ident = classify(identifier, self.settings.default_phone_region)
        except IdentifierError:
            return str(uuid.uuid4())
        self._limit(rl.RESET_PER_ID, keyed_hash(self.settings, "id", ident))
        if kind == "phone":
            user = self.db.execute(select(User).where(User.phone_e164 == ident)).scalar_one_or_none()
        else:
            user = self.db.execute(select(User).where(User.email == ident, User.email_verified_at.is_not(None))) \
                .scalar_one_or_none()
        if user is None or user.status != UserStatus.ACTIVE:
            return str(uuid.uuid4())  # same shape as a real id (ID-006)
        target = user.phone_e164 if kind == "phone" else ident
        row, code = self._issue_code(user, CodePurpose.RESET_PASSWORD, target, self.settings.reset_ttl_minutes)
        body = (f"Bongo Markets: Namba ya kurejesha nenosiri ni {code}. Inaisha baada ya dakika "
                f"{self.settings.reset_ttl_minutes}. Kama hukuomba, puuza ujumbe huu.")
        self.notifier.send("sms" if kind == "phone" else "email", target, body)
        audit.record(self.db, action="auth.password_reset_requested", category=AuditCategory.SECURITY,
                     entity_type="user", entity_id=user.id, details={"channel": kind})
        self.db.commit()
        return str(row.public_id)

    def reset_password(self, reset_id: str, code: str, new_password: str) -> None:
        self._limit(rl.OTP_VERIFY_PER_IP, self.ip_key)
        row = self._consume_code(reset_id, CodePurpose.RESET_PASSWORD, code)
        user = self.db.get(User, row.user_id, with_for_update=True)
        try:
            check_policy(new_password, personal=[*user.full_name.split(), user.phone_e164, user.phone_e164[-9:],
                                                 (user.email or "").split("@")[0]])
        except PasswordPolicyError as exc:
            self.db.rollback()  # the code stays usable so the user can retry with a stronger password
            raise AuthError(str(exc), status=422, code="weak_password", field="new_password") from None
        user.password_hash = hash_password(new_password)
        user.password_changed_at = _now()
        user.failed_login_count = 0
        user.locked_until = None
        self.revoke_all_sessions(user.id, "password_reset")
        audit.record(self.db, action="auth.password_reset_completed", category=AuditCategory.SECURITY,
                     entity_type="user", entity_id=user.id)
        self._sms(user.phone_e164, "Bongo Markets: Nenosiri lako limerejeshwa. Kama si wewe, wasiliana nasi mara moja.")
        self.db.commit()

    # ------------------------------------------------------------------ optional email (ID-002: secondary)
    def request_email_verification(self, ctx: SessionContext, email: str) -> str:
        self._limit(rl.RESEND_PER_ID, keyed_hash(self.settings, "email-verify", str(ctx.user.id)))
        try:
            email_norm = normalize_email(email)
        except IdentifierError as exc:
            raise AuthError(str(exc), status=422, code="invalid", field="email") from None
        user = self.db.get(User, ctx.user.id, with_for_update=True)
        if user.email != email_norm:
            user.email, user.email_verified_at = email_norm, None
        row, code = self._issue_code(user, CodePurpose.VERIFY_EMAIL, email_norm, self.settings.otp_ttl_minutes)
        self.notifier.send("email", email_norm, f"Bongo Markets: Namba ya kuthibitisha barua pepe ni {code}.")
        self.db.commit()
        return str(row.public_id)

    def confirm_email(self, ctx: SessionContext, verification_id: str, code: str) -> None:
        self._limit(rl.OTP_VERIFY_PER_IP, self.ip_key)
        row = self._consume_code(verification_id, CodePurpose.VERIFY_EMAIL, code)
        user = self.db.get(User, row.user_id, with_for_update=True)
        taken = self.db.execute(select(User.id).where(
            User.email == row.target, User.email_verified_at.is_not(None), User.id != user.id)).first()
        if user.id != ctx.user.id or user.email != row.target or taken:
            raise self._fail(GENERIC_CODE_FAILED, code="invalid_code")
        user.email_verified_at = _now()
        audit.record(self.db, action="user.email_verified", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id)
        self.db.commit()
