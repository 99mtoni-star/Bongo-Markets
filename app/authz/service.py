"""RBAC administration, audit export, legal holds, capabilities and account closure (M05)."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from sqlalchemy import delete, insert, select, text

from app.auth.models import User, UserStatus
from app.auth.security import SecurityService, StepUpAction
from app.auth.service import AuthError, SessionContext
from app.authz.engine import Authorizer
from app.authz.models import (
    AuthzPolicy,
    LegalHold,
    Permission,
    PlatformRolePermission,
    ShopRolePermission,
    UserCapability,
)
from app.db.models import AuditCategory, AuditLog
from app.services import audit

# Removing these from SUPER_ADMIN would lock everyone out of RBAC administration.
PROTECTED = {("SUPER_ADMIN", "platform.roles.assign"), ("SUPER_ADMIN", "platform.rbac.manage")}
EXPORT_MAX_ROWS = 50_000


def _now() -> datetime:
    return datetime.now(UTC)


class RBACService(SecurityService):
    @property
    def authz(self) -> Authorizer:
        return Authorizer(self.db)

    # ---------------------------------------------------------------- catalogue (AUTH-012)
    def catalogue(self, ctx: SessionContext) -> dict:
        self.require_permission(ctx, "platform.rbac.manage")
        perms = self.db.execute(select(Permission).order_by(Permission.scope, Permission.code)).scalars().all()
        platform: dict[str, list[str]] = {}
        prp = PlatformRolePermission
        for r, p in self.db.execute(select(prp.role_code, prp.permission_code)
                                    .order_by(prp.role_code, prp.permission_code)):
            platform.setdefault(r, []).append(p)
        shop: dict[str, list[str]] = {}
        for r, p in self.db.execute(select(ShopRolePermission.role_code, ShopRolePermission.permission_code)
                                    .order_by(ShopRolePermission.role_code, ShopRolePermission.permission_code)):
            shop.setdefault(r, []).append(p)
        return {
            "policy_version": self.authz.policy_version(),
            "permissions": [{"code": p.code, "scope": p.scope, "description": p.description,
                             "high_risk": p.high_risk} for p in perms],
            "platform_roles": platform,
            "shop_roles": shop,
        }

    def my_permissions(self, ctx: SessionContext) -> dict:
        return {"platform": sorted(self.authz.platform_permissions(ctx.user.id)),
                "policy_version": self.authz.policy_version()}

    # ---------------------------------------------------------------- policy change (AUTH-010/011/014/015/016/017)
    def set_role_permissions(self, ctx: SessionContext, scope: str, role: str, permissions: list[str],
                             expected_version: int | None, step_up_token: str | None) -> int:
        self.require_permission(ctx, "platform.rbac.manage")
        self.consume_step_up(ctx, StepUpAction.RBAC_CHANGE, step_up_token)
        if scope not in ("PLATFORM", "SHOP"):
            raise AuthError("Scope si sahihi.", status=422, code="invalid", field="scope")
        policy = self.db.execute(select(AuthzPolicy).where(AuthzPolicy.id == 1).with_for_update()).scalar_one()
        if expected_version is None or expected_version != policy.version:
            # Optimistic concurrency: the caller edited a stale view of the policy.
            raise AuthError("Sera imebadilishwa na mtu mwingine. Pakia upya kisha ujaribu tena.", status=409,
                            code="policy_version_conflict")
        table = PlatformRolePermission if scope == "PLATFORM" else ShopRolePermission
        role_exists = (text("SELECT 1 FROM bm.platform_roles WHERE code = :c") if scope == "PLATFORM"
                       else text("SELECT 1 FROM bm.shop_roles WHERE code = :c"))
        if not self.db.execute(role_exists, {"c": role}).first():
            raise AuthError("Jukumu halijulikani.", status=422, code="invalid", field="role")
        wanted = set(permissions)
        valid = set(self.db.execute(select(Permission.code).where(Permission.scope == scope)).scalars())
        if unknown := wanted - valid:
            raise AuthError(f"Ruhusa zisizojulikana kwa scope hii: {', '.join(sorted(unknown))}", status=422,
                            code="invalid", field="permissions")
        if scope == "PLATFORM" and any((role, p) in PROTECTED and p not in wanted for _, p in PROTECTED):
            raise AuthError("Ruhusa hizi haziwezi kuondolewa kwa SUPER_ADMIN.", status=409, code="protected")
        current = set(self.db.execute(select(table.permission_code).where(table.role_code == role)).scalars())
        added, removed = sorted(wanted - current), sorted(current - wanted)
        if not added and not removed:
            return policy.version
        if removed:
            self.db.execute(delete(table).where(table.role_code == role, table.permission_code.in_(removed)))
        if added:
            self.db.execute(insert(table), [{"role_code": role, "permission_code": p} for p in added])
        policy.version += 1
        policy.updated_at = _now()
        # Fan-out: every holder of the role gets a new authorization version (cache keys change).
        if scope == "PLATFORM":
            affected = self.db.execute(text(
                "UPDATE bm.users SET authz_version = authz_version + 1 WHERE id IN "
                "(SELECT user_id FROM bm.user_platform_roles WHERE role_code = :r AND revoked_at IS NULL)"
            ), {"r": role}).rowcount
        else:
            exists = self.db.execute(text("SELECT to_regclass('bm.shop_users') IS NOT NULL")).scalar_one()
            affected = self.db.execute(text(
                "UPDATE bm.users SET authz_version = authz_version + 1 WHERE id IN "
                "(SELECT user_id FROM bm.shop_users WHERE role_code = :r AND removed_at IS NULL)"
            ), {"r": role}).rowcount if exists else 0
        audit.record(self.db, action="rbac.role_permissions_changed", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="role", entity_id=f"{scope}:{role}",
                     details={"added": added, "removed": removed, "policy_version": policy.version,
                              "affected_users": affected})
        self.db.commit()
        return policy.version

    # ---------------------------------------------------------------- audit access (SEC-AUD-004, ADM-006)
    def audit_view(self, ctx: SessionContext, limit: int = 100) -> list[dict]:
        self.require_permission(ctx, "platform.audit.view")
        rows = self.db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 500))).scalars()
        return [{"id": r.id, "occurred_at": r.occurred_at.isoformat(), "category": r.category, "action": r.action,
                 "actor_user_id": r.actor_user_id, "entity_type": r.entity_type, "entity_id": r.entity_id}
                for r in rows]

    def audit_export(self, ctx: SessionContext, since: datetime, until: datetime, category: str | None,
                     step_up_token: str | None) -> str:
        self.require_permission(ctx, "platform.audit.export")
        self.consume_step_up(ctx, StepUpAction.AUDIT_EXPORT, step_up_token)
        q = select(AuditLog).where(AuditLog.occurred_at >= since, AuditLog.occurred_at < until)
        if category:
            q = q.where(AuditLog.category == category)
        rows = self.db.execute(q.order_by(AuditLog.id).limit(EXPORT_MAX_ROWS + 1)).scalars().all()
        if len(rows) > EXPORT_MAX_ROWS:
            raise AuthError("Kipindi ni kirefu mno; punguza tarehe.", status=422, code="too_large")
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "occurred_at", "category", "action", "actor_user_id", "actor_type", "entity_type",
                    "entity_id", "shop_id", "request_id", "details"])
        for r in rows:
            w.writerow([r.id, r.occurred_at.isoformat(), r.category, r.action, r.actor_user_id, r.actor_type,
                        r.entity_type, r.entity_id, r.shop_id, r.request_id, r.details])
        audit.record(self.db, action="audit.exported", category=AuditCategory.SECURITY, actor_user_id=ctx.user.id,
                     actor_type="user", details={"since": since.isoformat(), "until": until.isoformat(),
                                                 "category": category, "rows": len(rows)})
        self.db.commit()
        return buf.getvalue()

    # ---------------------------------------------------------------- legal holds (SEC-COM-004)
    def place_legal_hold(self, ctx: SessionContext, target_public_id: str, reason: str,
                         step_up_token: str | None) -> None:
        self.require_permission(ctx, "platform.legal_hold.manage")
        self.consume_step_up(ctx, StepUpAction.LEGAL_HOLD, step_up_token)
        target = self._target(target_public_id)
        self.db.add(LegalHold(user_id=target.id, reason=reason[:2000], created_by=str(ctx.user.public_id)))
        audit.record(self.db, action="legal_hold.placed", category=AuditCategory.SECURITY, actor_user_id=ctx.user.id,
                     actor_type="user", entity_type="user", entity_id=target.id)
        self.db.commit()

    def release_legal_holds(self, ctx: SessionContext, target_public_id: str, step_up_token: str | None) -> int:
        self.require_permission(ctx, "platform.legal_hold.manage")
        self.consume_step_up(ctx, StepUpAction.LEGAL_HOLD, step_up_token)
        target = self._target(target_public_id)
        n = 0
        for h in self.db.execute(select(LegalHold).where(LegalHold.user_id == target.id,
                                                         LegalHold.released_at.is_(None))).scalars():
            h.released_at = _now()
            n += 1
        audit.record(self.db, action="legal_hold.released", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="user", entity_id=target.id,
                     details={"count": n})
        self.db.commit()
        return n

    # ---------------------------------------------------------------- capabilities (ACT-001/004/007, V13-REQ-007)
    def ensure_capability(self, user_id: int, capability: str, *, status: str = "ACTIVE") -> UserCapability:
        """Participation only: never grants a permission. Caller commits."""
        cap = self.db.execute(select(UserCapability).where(UserCapability.user_id == user_id,
                                                           UserCapability.capability == capability)
                              .with_for_update()).scalar_one_or_none()
        if cap is None:
            cap = UserCapability(user_id=user_id, capability=capability, status=status)
            self.db.add(cap)
            audit.record(self.db, action="capability.added", category=AuditCategory.GENERAL,
                         entity_type="user", entity_id=user_id, details={"capability": capability, "status": status})
        return cap

    def set_capability_status(self, ctx: SessionContext, target_public_id: str, capability: str, status: str) -> None:
        self.require_permission(ctx, "platform.shops.verify")
        if status not in ("PENDING", "ACTIVE", "SUSPENDED", "REVOKED"):
            raise AuthError("Hali si sahihi.", status=422, code="invalid", field="status")
        target = self._target(target_public_id)
        cap = self.ensure_capability(target.id, capability, status=status)
        old = cap.status
        cap.status = status
        if status == "ACTIVE" and cap.verified_at is None:
            cap.verified_at = _now()
        audit.record(self.db, action="capability.status_changed", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="user", entity_id=target.id,
                     details={"capability": capability, "from": old, "to": status})
        self.db.commit()

    def capabilities(self, user_id: int) -> list[dict]:
        rows = self.db.execute(select(UserCapability).where(UserCapability.user_id == user_id)).scalars()
        return [{"capability": c.capability, "status": c.status} for c in rows]

    # ---------------------------------------------------------------- account closure (SEC-COM-004)
    def close_account(self, ctx: SessionContext, step_up_token: str | None) -> None:
        self.consume_step_up(ctx, StepUpAction.ACCOUNT_CLOSE, step_up_token)
        user = self.db.get(User, ctx.user.id, with_for_update=True)
        if self.active_roles(user.id):
            raise AuthError("Akaunti yenye majukumu ya usimamizi haiwezi kufungwa hivi.", status=409,
                            code="has_roles")
        user.status, user.closed_at = UserStatus.CLOSED, _now()
        user.authz_version += 1
        self.revoke_all_sessions(user.id, "account_closed")
        audit.record(self.db, action="user.account_closed", category=AuditCategory.SECURITY,
                     actor_user_id=user.id, entity_type="user", entity_id=user.id)
        self.db.commit()
