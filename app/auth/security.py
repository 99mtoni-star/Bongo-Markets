"""M04: MFA, step-up authentication, session management, phone change, platform roles
and incident response.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy import select, update

from app.auth import ratelimit as rl
from app.auth.identifiers import IdentifierError, mask_phone, normalize_phone
from app.auth.mfa import (
    encrypt_secret,
    hash_recovery,
    new_recovery_codes,
    new_totp_secret,
    provisioning_uri,
    qr_svg,
    verify_totp,
)
from app.auth.models import (
    CodePurpose,
    PlatformRole,
    RecoveryCode,
    StepUpGrant,
    User,
    UserPlatformRole,
    UserSession,
    UserStatus,
)
from app.auth.passwords import verify_password
from app.auth.service import GENERIC_CODE_FAILED, AuthError, AuthService, SessionContext
from app.auth.tokens import keyed_hash, new_session_token, sha256_hex
from app.db.models import AuditCategory, SystemFlag
from app.services import audit

STEP_UP_SECONDS = 300  # AUTH-008 (v1.12.2): <= 300 s
PAYMENTS_SUSPENDED = "payments_suspended"


class StepUpAction(StrEnum):
    """High-risk operations that need fresh re-authentication (SEC-MFA-002)."""

    OWNERSHIP_TRANSFER = "OWNERSHIP_TRANSFER"        # M07
    REFUND_APPROVE = "REFUND_APPROVE"                # M17
    COMMISSION_CHANGE = "COMMISSION_CHANGE"          # M15
    ROLE_ASSIGN = "ROLE_ASSIGN"
    PAYMENT_CONFIG_CHANGE = "PAYMENT_CONFIG_CHANGE"  # M13
    MFA_DISABLE = "MFA_DISABLE"
    RECOVERY_CODES = "RECOVERY_CODES"
    PHONE_CHANGE = "PHONE_CHANGE"
    EMAIL_CHANGE = "EMAIL_CHANGE"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"


# Actions that always need the TOTP factor, never password-only (ID-007, SEC-MFA-004).
STRONG_FACTOR_ACTIONS = {StepUpAction.ROLE_ASSIGN, StepUpAction.INCIDENT_RESPONSE,
                         StepUpAction.PAYMENT_CONFIG_CHANGE, StepUpAction.COMMISSION_CHANGE,
                         StepUpAction.REFUND_APPROVE, StepUpAction.OWNERSHIP_TRANSFER}

ROLE_GRANTORS = {"SUPER_ADMIN"}
INCIDENT_RESPONDERS = {"SUPER_ADMIN", "PLATFORM_ADMIN"}


def _now() -> datetime:
    return datetime.now(UTC)


class SecurityService(AuthService):
    # ------------------------------------------------------------------ roles
    def active_roles(self, user_id: int) -> set[str]:
        return set(self.db.execute(select(UserPlatformRole.role_code).where(
            UserPlatformRole.user_id == user_id, UserPlatformRole.revoked_at.is_(None))).scalars())

    def is_privileged(self, user_id: int) -> bool:
        return bool(self.db.execute(
            select(UserPlatformRole.id).join(PlatformRole, PlatformRole.code == UserPlatformRole.role_code)
            .where(UserPlatformRole.user_id == user_id, UserPlatformRole.revoked_at.is_(None),
                   PlatformRole.privileged.is_(True)).limit(1)).first())

    def require_privileged_session(self, ctx: SessionContext, allowed_roles: set[str]) -> set[str]:
        """Privileged APIs need a role AND a session that used the TOTP factor (aal2)."""
        roles = self.active_roles(ctx.user.id)
        if not roles & allowed_roles:
            raise AuthError("Huna ruhusa ya kufanya kitendo hiki.", status=403, code="forbidden")
        if ctx.session.aal < 2:
            raise AuthError("Ingia kwa MFA (programu ya uthibitishaji) ili kutumia sehemu hii.", status=403,
                            code="mfa_required")
        return roles

    # ------------------------------------------------------------------ step-up (SEC-MFA-002)
    def step_up(self, ctx: SessionContext, action: str, password: str, mfa_code: str | None) -> str:
        try:
            act = StepUpAction(action)
        except ValueError:
            raise AuthError("Kitendo hakijulikani.", status=422, code="invalid", field="action") from None
        self._limit(rl.STEP_UP_PER_USER, str(ctx.user.id))
        user = self.db.get(User, ctx.user.id, with_for_update=True)
        has_totp = user.totp_enabled_at is not None
        if (act in STRONG_FACTOR_ACTIONS or self.is_privileged(user.id)) and not has_totp:
            raise AuthError("Kitendo hiki kinahitaji MFA ya programu ya uthibitishaji. Iwashe kwanza.",
                            status=403, code="mfa_enrollment_required")
        ok = verify_password(user.password_hash, password or "")
        factor = self.check_second_factor(user, mfa_code or "") if (ok and has_totp) else None
        if not ok or (has_totp and factor is None):
            audit.record(self.db, action="auth.step_up_failed", category=AuditCategory.SECURITY,
                         actor_user_id=user.id, entity_type="user", entity_id=user.id,
                         details={"action": act.value})
            raise self._fail("Uthibitisho umeshindwa. Angalia nenosiri na namba ya MFA.", status=401,
                             code="step_up_failed")
        token = new_session_token()
        now = _now()
        self.db.add(StepUpGrant(token_hash=sha256_hex(token), user_id=user.id, session_id=ctx.session.id,
                                action=act.value, aal=2 if has_totp else 1, created_at=now,
                                expires_at=now + timedelta(seconds=STEP_UP_SECONDS)))
        audit.record(self.db, action="auth.step_up_granted", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id,
                     details={"action": act.value, "aal": 2 if has_totp else 1})
        self.db.commit()
        return token

    def consume_step_up(self, ctx: SessionContext, action: StepUpAction, token: str | None) -> None:
        """Single-use, bound to user + session + action, expires after 300 s (AUTH-008 v1.12.2)."""
        grant = None
        if token and len(token) <= 200:
            grant = self.db.execute(select(StepUpGrant).where(StepUpGrant.token_hash == sha256_hex(token))
                                    .with_for_update()).scalar_one_or_none()
        if grant is None or grant.used_at is not None or grant.expires_at <= _now() \
                or grant.user_id != ctx.user.id or grant.session_id != ctx.session.id \
                or grant.action != action.value:
            raise AuthError("Thibitisha tena (nenosiri na MFA) kabla ya kitendo hiki.", status=403,
                            code="step_up_required")
        grant.used_at = _now()

    # ------------------------------------------------------------------ TOTP enrollment
    def begin_totp_setup(self, ctx: SessionContext) -> dict:
        user = self.db.get(User, ctx.user.id, with_for_update=True)
        if user.totp_enabled_at is not None:
            raise AuthError("MFA tayari imewashwa.", status=409, code="mfa_already_enabled")
        secret = new_totp_secret()
        user.totp_secret_enc = encrypt_secret(self.settings, secret, user_id=user.id)
        user.totp_last_step = None
        self.db.commit()
        uri = provisioning_uri(secret, mask_phone(user.phone_e164))
        return {"secret": secret, "otpauth_uri": uri, "qr_svg": qr_svg(uri)}

    def confirm_totp_setup(self, ctx: SessionContext, code: str) -> list[str]:
        from app.auth.mfa import decrypt_secret

        self._limit(rl.OTP_VERIFY_PER_IP, self.ip_key)
        user = self.db.get(User, ctx.user.id, with_for_update=True)
        if user.totp_enabled_at is not None or not user.totp_secret_enc:
            raise AuthError("Anza kuwasha MFA kwanza.", status=409, code="mfa_not_pending")
        secret = decrypt_secret(self.settings, user.totp_secret_enc, user_id=user.id)
        step = verify_totp(secret, code, last_used_step=None)
        if step is None:
            raise AuthError("Namba ya programu si sahihi. Hakikisha saa ya simu iko sawa.", status=400,
                            code="invalid_code", field="code")
        now = _now()
        user.totp_enabled_at, user.totp_last_step = now, step
        codes = self._replace_recovery_codes(user.id)
        # ID-010: a new factor changes trust state — sign out every other device, upgrade this one.
        self.revoke_all_sessions(user.id, "mfa_enabled", except_session_id=ctx.session.id)
        self.db.execute(update(UserSession).where(UserSession.id == ctx.session.id).values(aal=2))
        audit.record(self.db, action="auth.mfa_enabled", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id, details={"method": "totp"})
        self._sms(user.phone_e164, "Bongo Markets: MFA (programu ya uthibitishaji) imewashwa kwenye akaunti yako.")
        self.db.commit()
        return codes

    def _replace_recovery_codes(self, user_id: int) -> list[str]:
        self.db.execute(update(RecoveryCode).where(RecoveryCode.user_id == user_id,
                                                   RecoveryCode.used_at.is_(None)).values(used_at=_now()))
        codes = new_recovery_codes()
        for c in codes:
            self.db.add(RecoveryCode(user_id=user_id, code_hash=hash_recovery(c)))
        return codes

    def regenerate_recovery_codes(self, ctx: SessionContext, step_up_token: str | None) -> list[str]:
        self.consume_step_up(ctx, StepUpAction.RECOVERY_CODES, step_up_token)
        codes = self._replace_recovery_codes(ctx.user.id)
        audit.record(self.db, action="auth.recovery_codes_regenerated", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, entity_type="user", entity_id=ctx.user.id)
        self.db.commit()
        return codes

    def disable_totp(self, ctx: SessionContext, step_up_token: str | None) -> None:
        if self.is_privileged(ctx.user.id):
            raise AuthError("Akaunti za wasimamizi lazima ziwe na MFA wakati wote.", status=403,
                            code="mfa_required_for_role")
        self.consume_step_up(ctx, StepUpAction.MFA_DISABLE, step_up_token)
        user = self.db.get(User, ctx.user.id, with_for_update=True)
        user.totp_secret_enc = user.totp_enabled_at = user.totp_last_step = None
        self.db.execute(update(RecoveryCode).where(RecoveryCode.user_id == user.id,
                                                   RecoveryCode.used_at.is_(None)).values(used_at=_now()))
        self.revoke_all_sessions(user.id, "mfa_disabled", except_session_id=ctx.session.id)
        self.db.execute(update(UserSession).where(UserSession.id == ctx.session.id).values(aal=1))
        audit.record(self.db, action="auth.mfa_disabled", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id)
        self._sms(user.phone_e164, "Bongo Markets: MFA imezimwa kwenye akaunti yako. Kama si wewe, wasiliana nasi.")
        self.db.commit()

    # ------------------------------------------------------------------ sessions (AUTH-004/005, AUTH-009)
    def _public_session_id(self, session_id: int) -> str:
        return keyed_hash(self.settings, "sid", str(session_id))[:20]

    def list_sessions(self, ctx: SessionContext) -> list[dict]:
        rows = self.db.execute(select(UserSession).where(
            UserSession.user_id == ctx.user.id, UserSession.revoked_at.is_(None),
            UserSession.expires_at > _now()).order_by(UserSession.last_seen_at.desc())).scalars()
        return [{"id": self._public_session_id(s.id), "current": s.id == ctx.session.id,
                 "created_at": s.created_at, "last_seen_at": s.last_seen_at, "user_agent": s.user_agent,
                 "mfa": s.aal >= 2} for s in rows]

    def revoke_session(self, ctx: SessionContext, public_session_id: str) -> bool:
        for s in self.db.execute(select(UserSession).where(UserSession.user_id == ctx.user.id,
                                                           UserSession.revoked_at.is_(None))).scalars():
            if self._public_session_id(s.id) == public_session_id:
                s.revoked_at, s.revoke_reason = _now(), "user_revoked"
                audit.record(self.db, action="auth.session_revoked", category=AuditCategory.SECURITY,
                             actor_user_id=ctx.user.id, entity_type="user", entity_id=ctx.user.id)
                self.db.commit()
                return True
        return False

    def revoke_other_sessions(self, ctx: SessionContext) -> int:
        n = self.revoke_all_sessions(ctx.user.id, "user_signed_out_others", except_session_id=ctx.session.id)
        self.db.commit()
        return n

    # ------------------------------------------------------------------ phone change (ID-005, ID-008, ID-010)
    def request_phone_change(self, ctx: SessionContext, new_phone: str, step_up_token: str | None) -> str:
        self.consume_step_up(ctx, StepUpAction.PHONE_CHANGE, step_up_token)
        try:
            phone = normalize_phone(new_phone, self.settings.default_phone_region)
        except IdentifierError as exc:
            raise AuthError(str(exc), status=422, code="invalid", field="new_phone") from None
        user = self.db.get(User, ctx.user.id, with_for_update=True)
        if phone == user.phone_e164:
            raise AuthError("Hii ndiyo namba yako ya sasa.", status=422, code="invalid", field="new_phone")
        taken = self.db.execute(select(User.id).where(User.phone_e164 == phone)).first()
        if taken:
            self.db.commit()  # step-up stays consumed
            return str(uuid.uuid4())  # generic: verification will fail like a wrong code
        row, code = self._issue_code(user, CodePurpose.CHANGE_PHONE, phone, self.settings.otp_ttl_minutes)
        self._sms(phone, f"Bongo Markets: Namba ya kuthibitisha namba mpya ya simu ni {code}. Usimpe mtu yeyote.")
        audit.record(self.db, action="user.phone_change_requested", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id,
                     details={"new_phone": mask_phone(phone)})
        self.db.commit()
        return str(row.public_id)

    def confirm_phone_change(self, ctx: SessionContext, verification_id: str, code: str) -> None:
        self._limit(rl.OTP_VERIFY_PER_IP, self.ip_key)
        row = self._consume_code(verification_id, CodePurpose.CHANGE_PHONE, code)
        user = self.db.get(User, row.user_id, with_for_update=True)
        taken = self.db.execute(select(User.id).where(User.phone_e164 == row.target, User.id != user.id)).first()
        if user.id != ctx.user.id or taken:
            raise self._fail(GENERIC_CODE_FAILED, code="invalid_code")
        old = user.phone_e164
        user.phone_e164, user.phone_verified_at = row.target, _now()
        self.revoke_all_sessions(user.id, "phone_changed", except_session_id=ctx.session.id)
        audit.record(self.db, action="user.phone_changed", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id,
                     details={"old": mask_phone(old), "new": mask_phone(row.target)})
        self._sms(old, "Bongo Markets: Namba ya simu ya akaunti yako imebadilishwa. Kama si wewe, wasiliana nasi.")
        self.db.commit()

    def request_email_change(self, ctx: SessionContext, email: str, step_up_token: str | None) -> str:
        """Replacing a VERIFIED email is a sensitive change (SEC-MFA-002); adding a first one is not."""
        if ctx.user.email_verified_at is not None:
            from app.auth.identifiers import normalize_email

            try:
                same = normalize_email(email) == ctx.user.email
            except IdentifierError:
                same = False
            if not same:
                self.consume_step_up(ctx, StepUpAction.EMAIL_CHANGE, step_up_token)
        return self.request_email_verification(ctx, email)

    # ------------------------------------------------------------------ platform roles (AUTH-008, AUTH-005 v1.12.2)
    def _target(self, public_id: str) -> User:
        try:
            pid = uuid.UUID(str(public_id))
        except ValueError:
            raise AuthError("Mtumiaji hapatikani.", status=404, code="not_found") from None
        user = self.db.execute(select(User).where(User.public_id == pid).with_for_update()).scalar_one_or_none()
        if user is None:
            raise AuthError("Mtumiaji hapatikani.", status=404, code="not_found")
        return user

    def grant_role(self, ctx: SessionContext, target_public_id: str, role_code: str, step_up_token: str | None):
        self.require_privileged_session(ctx, ROLE_GRANTORS)
        self.consume_step_up(ctx, StepUpAction.ROLE_ASSIGN, step_up_token)
        role = self.db.get(PlatformRole, role_code)
        if role is None:
            raise AuthError("Jukumu halijulikani.", status=422, code="invalid", field="role")
        target = self._target(target_public_id)
        if target.id == ctx.user.id:
            raise AuthError("Huwezi kujipa jukumu mwenyewe.", status=403, code="self_grant")
        if target.status != UserStatus.ACTIVE:
            raise AuthError("Akaunti ya mtumiaji haiko hai.", status=409, code="inactive")
        if role.privileged and target.totp_enabled_at is None:
            raise AuthError("Mtumiaji lazima awashe MFA ya programu kabla ya kupewa jukumu hili.", status=409,
                            code="target_mfa_required")
        if role_code in self.active_roles(target.id):
            raise AuthError("Tayari ana jukumu hili.", status=409, code="exists")
        self.db.add(UserPlatformRole(user_id=target.id, role_code=role_code, granted_by=ctx.user.id))
        self.revoke_all_sessions(target.id, "role_granted")  # new privileges start with a fresh MFA login
        audit.record(self.db, action="role.granted", category=AuditCategory.SECURITY, actor_user_id=ctx.user.id,
                     actor_type="user", entity_type="user", entity_id=target.id, details={"role": role_code})
        self.db.commit()

    def revoke_role(self, ctx: SessionContext, target_public_id: str, role_code: str, step_up_token: str | None):
        self.require_privileged_session(ctx, ROLE_GRANTORS)
        self.consume_step_up(ctx, StepUpAction.ROLE_ASSIGN, step_up_token)
        target = self._target(target_public_id)
        grant = self.db.execute(select(UserPlatformRole).where(
            UserPlatformRole.user_id == target.id, UserPlatformRole.role_code == role_code,
            UserPlatformRole.revoked_at.is_(None)).with_for_update()).scalar_one_or_none()
        if grant is None:
            raise AuthError("Hana jukumu hili.", status=404, code="not_found")
        if target.id == ctx.user.id and role_code in ROLE_GRANTORS:
            raise AuthError("Huwezi kujiondolea jukumu la juu kabisa mwenyewe.", status=403, code="self_revoke")
        grant.revoked_at, grant.revoked_by = _now(), ctx.user.id
        self.revoke_all_sessions(target.id, "role_revoked")  # AUTH-009: takes effect immediately
        audit.record(self.db, action="role.revoked", category=AuditCategory.SECURITY, actor_user_id=ctx.user.id,
                     actor_type="user", entity_type="user", entity_id=target.id, details={"role": role_code})
        self.db.commit()

    # ------------------------------------------------------------------ incident response (SEC-IR-003)
    def suspend_user(self, ctx: SessionContext, target_public_id: str, reason: str, step_up_token: str | None):
        self.require_privileged_session(ctx, INCIDENT_RESPONDERS)
        self.consume_step_up(ctx, StepUpAction.INCIDENT_RESPONSE, step_up_token)
        target = self._target(target_public_id)
        if target.id == ctx.user.id:
            raise AuthError("Huwezi kujisimamisha mwenyewe.", status=403, code="self_suspend")
        target.status = UserStatus.SUSPENDED
        self.revoke_all_sessions(target.id, "suspended")
        audit.record(self.db, action="incident.user_suspended", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="user", entity_id=target.id,
                     details={"reason": (reason or "")[:200]})
        self.db.commit()

    def reinstate_user(self, ctx: SessionContext, target_public_id: str, reason: str, step_up_token: str | None):
        self.require_privileged_session(ctx, INCIDENT_RESPONDERS)
        self.consume_step_up(ctx, StepUpAction.INCIDENT_RESPONSE, step_up_token)
        target = self._target(target_public_id)
        if target.status == UserStatus.SUSPENDED:
            target.status = UserStatus.ACTIVE
        audit.record(self.db, action="incident.user_reinstated", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="user", entity_id=target.id,
                     details={"reason": (reason or "")[:200]})
        self.db.commit()

    def force_sign_out(self, ctx: SessionContext, target_public_id: str, step_up_token: str | None) -> int:
        self.require_privileged_session(ctx, INCIDENT_RESPONDERS)
        self.consume_step_up(ctx, StepUpAction.INCIDENT_RESPONSE, step_up_token)
        target = self._target(target_public_id)
        n = self.revoke_all_sessions(target.id, "incident_response")
        audit.record(self.db, action="incident.sessions_revoked", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="user", entity_id=target.id)
        self.db.commit()
        return n

    def set_payments_suspended(self, ctx: SessionContext, suspended: bool, reason: str,
                               step_up_token: str | None) -> None:
        self.require_privileged_session(ctx, INCIDENT_RESPONDERS)
        self.consume_step_up(ctx, StepUpAction.INCIDENT_RESPONSE, step_up_token)
        flag = self.db.get(SystemFlag, PAYMENTS_SUSPENDED)
        if flag is None:
            flag = SystemFlag(key=PAYMENTS_SUSPENDED, value="false", updated_by="system")
            self.db.add(flag)
        flag.value, flag.reason = ("true" if suspended else "false"), (reason or "")[:500]
        flag.updated_by = str(ctx.user.public_id)
        audit.record(self.db, action="incident.payments_suspended" if suspended else "incident.payments_resumed",
                     category=AuditCategory.FINANCIAL, actor_user_id=ctx.user.id, actor_type="user",
                     details={"reason": (reason or "")[:200]})
        self.db.commit()


def payments_suspended(db) -> bool:
    """Consulted by the payment module (M13) before starting any payment."""
    flag = db.get(SystemFlag, PAYMENTS_SUSPENDED)
    return flag is not None and flag.value == "true"
