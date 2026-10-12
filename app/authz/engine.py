"""Authorization engine (M05).

- Deny by default; decisions are made on the server for every protected request (SEC-003, AUTH-001).
- Platform and shop permissions are separate scopes (AUTH-002). Shop membership is read from
  ``shop_users`` in the database, never from client input (SEC-004).
- Decisions may be cached per (user, authz_version, policy_version). The cache is never the sole
  authority for high-risk permissions and any error fails closed (V13-SEC-003, AUTH-015/017).
- Failures return generic messages; objects the caller cannot access look like they do not exist
  (SEC-INV-002, AUTH-004).
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth.service import AuthError, SessionContext
from app.authz.models import AuthzPolicy, Permission, PlatformRolePermission, ShopRolePermission

logger = logging.getLogger("bongomarkets.authz")

FORBIDDEN = "Huna ruhusa ya kufanya kitendo hiki."
NOT_FOUND = "Hakipatikani."


class _DecisionCache:
    """Small process-local LRU. Keys embed both versions, so any change makes old entries unreachable."""

    def __init__(self, size: int = 2048):
        self._data: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self.size = size

    def get(self, key):
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                return self._data[key]
        return None

    def put(self, key, value) -> None:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self.size:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


CACHE = _DecisionCache()


class Authorizer:
    def __init__(self, db: Session):
        self.db = db
        self._high_risk: frozenset[str] | None = None

    # ---------------------------------------------------------------- versions
    def _versions(self, user_id: int) -> tuple[int, int]:
        row = self.db.execute(text(
            "SELECT u.authz_version, p.version FROM bm.users u CROSS JOIN bm.authz_policy p WHERE u.id = :uid"
        ), {"uid": user_id}).first()
        if row is None:
            raise LookupError("user not found")
        return int(row[0]), int(row[1])

    def policy_version(self) -> int:
        return self.db.execute(select(AuthzPolicy.version).where(AuthzPolicy.id == 1)).scalar_one()

    def high_risk_permissions(self) -> frozenset[str]:
        if self._high_risk is None:
            self._high_risk = frozenset(self.db.execute(
                select(Permission.code).where(Permission.high_risk.is_(True))).scalars())
        return self._high_risk

    # ---------------------------------------------------------------- resolution (always from the DB)
    def _platform_from_db(self, user_id: int) -> frozenset[str]:
        return frozenset(self.db.execute(text(
            "SELECT DISTINCT rp.permission_code FROM bm.user_platform_roles ur "
            "JOIN bm.platform_role_permissions rp ON rp.role_code = ur.role_code "
            "JOIN bm.users u ON u.id = ur.user_id "
            "WHERE ur.user_id = :uid AND ur.revoked_at IS NULL AND u.status = 'ACTIVE'"
        ), {"uid": user_id}).scalars())

    def _shop_from_db(self, user_id: int, shop_id: int) -> frozenset[str]:
        # shop_users / shops arrive in M07; until then no user has shop permissions (deny by default).
        exists = self.db.execute(text("SELECT to_regclass('bm.shop_users') IS NOT NULL")).scalar_one()
        if not exists:
            return frozenset()
        return frozenset(self.db.execute(text(
            "SELECT DISTINCT srp.permission_code FROM bm.shop_users su "
            "JOIN bm.shops s ON s.id = su.shop_id "
            "JOIN bm.shop_role_permissions srp ON srp.role_code = su.role_code "
            "JOIN bm.users u ON u.id = su.user_id "
            "WHERE su.user_id = :uid AND su.shop_id = :sid AND su.removed_at IS NULL "
            "AND u.status = 'ACTIVE' AND s.status <> 'CLOSED'"
        ), {"uid": user_id, "sid": shop_id}).scalars())

    # ---------------------------------------------------------------- public API
    def platform_permissions(self, user_id: int, *, use_cache: bool = True) -> frozenset[str]:
        uv, pv = self._versions(user_id)
        key = ("p", user_id, uv, pv)
        if use_cache and (hit := CACHE.get(key)) is not None:
            return hit
        perms = self._platform_from_db(user_id)
        CACHE.put(key, perms)
        return perms

    def shop_permissions(self, user_id: int, shop_id: int, *, use_cache: bool = True) -> frozenset[str]:
        uv, pv = self._versions(user_id)
        key = ("s", user_id, shop_id, uv, pv)
        if use_cache and (hit := CACHE.get(key)) is not None:
            return hit
        perms = self._shop_from_db(user_id, shop_id)
        CACHE.put(key, perms)
        return perms

    def can(self, user_id: int, permission: str, *, shop_id: int | None = None) -> bool:
        """Deny-by-default check. High-risk permissions are always resolved from the database."""
        try:
            fresh = permission in self.high_risk_permissions()
            if permission.startswith("shop."):
                if shop_id is None:
                    return False
                return permission in self.shop_permissions(user_id, shop_id, use_cache=not fresh)
            return permission in self.platform_permissions(user_id, use_cache=not fresh)
        except Exception:  # fail closed (V13-SEC-003)
            logger.warning("authz_error_denied", extra={"extra_fields": {"permission": permission}})
            return False

    def require(self, ctx: SessionContext, permission: str, *, shop_id: int | None = None,
                hide_existence: bool = False) -> None:
        """Raise a generic 403 (or 404 to avoid revealing objects) unless allowed."""
        if self.can(ctx.user.id, permission, shop_id=shop_id):
            if not permission.startswith("shop.") and ctx.session.aal < 2:
                raise AuthError("Ingia kwa MFA (programu ya uthibitishaji) ili kutumia sehemu hii.", status=403,
                                code="mfa_required")
            return
        if hide_existence:
            raise AuthError(NOT_FOUND, status=404, code="not_found")
        raise AuthError(FORBIDDEN, status=403, code="forbidden")

    # ---------------------------------------------------------------- fan-out (AUTH-015/017)
    def bump_user(self, user_id: int) -> None:
        self.db.execute(text("UPDATE bm.users SET authz_version = authz_version + 1 WHERE id = :uid"),
                        {"uid": user_id})

    def platform_role_permissions(self, role_code: str) -> set[str]:
        return set(self.db.execute(select(PlatformRolePermission.permission_code)
                                   .where(PlatformRolePermission.role_code == role_code)).scalars())

    def shop_role_permissions(self, role_code: str) -> set[str]:
        return set(self.db.execute(select(ShopRolePermission.permission_code)
                                   .where(ShopRolePermission.role_code == role_code)).scalars())
