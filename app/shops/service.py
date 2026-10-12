"""Shops, staff and ownership (M07).

- Any active user may open shops (SHOP-001/002, BR-001/002); the creator is the OWNER (SHOP-003, BR-003/004).
- Every shop action is authorized from shop_users in the database (BR-008, SEC-004); non-members get a
  generic 404 so shops' admin areas cannot be probed (AUTH-004).
- Nobody can make themselves OWNER (BR-006); ownership moves only by an audited, step-up-protected,
  single-transaction transfer (BR-005, SHOP-002 v1.12.2).
- Verification/suspension lifecycle with status history (SHOP-006); verification grants no platform
  privilege (CAP-VER-001).
"""

from __future__ import annotations

import re
import unicodedata
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select

from app.auth import ratelimit as rl
from app.auth.identifiers import IdentifierError, normalize_phone
from app.auth.models import User, UserStatus
from app.auth.security import StepUpAction
from app.auth.service import AuthError, SessionContext
from app.authz.service import RBACService
from app.db.models import AuditCategory
from app.services import audit
from app.shops.models import TRANSITIONS, Shop, ShopStatus, ShopStatusHistory, ShopUser

RESERVED_SLUGS = {"admin", "api", "soko", "maduka", "duka", "akaunti", "ingia", "jisajili", "toka", "static",
                  "simamizi", "hali", "dev", "bongo", "bongomarkets", "faragha", "masharti", "help", "msaada"}
MAX_SHOPS_PER_USER = 10
SHOP_CREATE = rl.Limit("shop-create", 5, 3600)
MEMBER_ADD = rl.Limit("shop-member-add", 20, 3600)
NOT_FOUND = "Duka halipatikani."


def _now() -> datetime:
    return datetime.now(UTC)


def slugify(name: str) -> str:
    s = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")[:40].strip("-")
    return s if len(s) >= 3 else f"duka-{s}".strip("-")


class ShopService(RBACService):
    # ---------------------------------------------------------------- lookup
    def shop_by_slug(self, slug: str, *, lock: bool = False) -> Shop | None:
        q = select(Shop).where(Shop.slug == (slug or "").lower()[:40])
        return self.db.execute(q.with_for_update() if lock else q).scalar_one_or_none()

    def shop_for(self, ctx: SessionContext, slug: str, permission: str, *, lock: bool = False) -> Shop:
        """Return the shop if the caller holds ``permission`` in it; otherwise a generic 404."""
        shop = self.shop_by_slug(slug, lock=lock)
        if shop is None or shop.status == ShopStatus.CLOSED:
            raise AuthError(NOT_FOUND, status=404, code="not_found")
        if not self.authz.can(ctx.user.id, permission, shop_id=shop.id):
            if not self.authz.can(ctx.user.id, "shop.admin.view", shop_id=shop.id):
                raise AuthError(NOT_FOUND, status=404, code="not_found")  # non-members cannot probe
            raise AuthError("Huna ruhusa ya kufanya kitendo hiki katika duka hili.", status=403, code="forbidden")
        return shop

    def membership(self, shop_id: int, user_id: int) -> ShopUser | None:
        return self.db.execute(select(ShopUser).where(ShopUser.shop_id == shop_id, ShopUser.user_id == user_id,
                                                      ShopUser.removed_at.is_(None))).scalar_one_or_none()

    def my_shops(self, ctx: SessionContext) -> list[dict]:
        rows = self.db.execute(select(Shop, ShopUser.role_code).join(ShopUser, ShopUser.shop_id == Shop.id)
                               .where(ShopUser.user_id == ctx.user.id, ShopUser.removed_at.is_(None),
                                      Shop.status != ShopStatus.CLOSED).order_by(Shop.created_at)).all()
        return [self._shop_dict(s) | {"my_role": r} for s, r in rows]

    @staticmethod
    def _shop_dict(s: Shop) -> dict:
        return {"id": str(s.public_id), "slug": s.slug, "name": s.name, "description": s.description,
                "region": s.region, "status": s.status}

    # ---------------------------------------------------------------- create (SHOP-001/002/003)
    def create_shop(self, ctx: SessionContext, name: str, description: str | None = None,
                    region: str | None = None, slug: str | None = None) -> Shop:
        self._limit(SHOP_CREATE, str(ctx.user.id))
        name = " ".join((name or "").split())
        if not 3 <= len(name) <= 80:
            raise AuthError("Jina la duka liwe na herufi 3 hadi 80.", status=422, code="invalid", field="name")
        owned = self.db.execute(select(func.count()).select_from(Shop).where(
            Shop.owner_user_id == ctx.user.id, Shop.status != ShopStatus.CLOSED)).scalar_one()
        if owned >= MAX_SHOPS_PER_USER:
            raise AuthError(f"Unaweza kumiliki maduka {MAX_SHOPS_PER_USER} tu.", status=409, code="limit")
        base = (slug or "").strip().lower() or slugify(name)
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])", base) or base in RESERVED_SLUGS:
            raise AuthError("Anwani ya duka itumie herufi ndogo, namba na '-' (herufi 3–40).", status=422,
                            code="invalid", field="slug")
        candidate, n = base, 1
        while self.shop_by_slug(candidate) is not None:
            n += 1
            candidate = f"{base[:36]}-{n}"
        shop = Shop(slug=candidate, name=name, description=(description or "").strip()[:2000] or None,
                    region=(region or "").strip()[:60] or None, owner_user_id=ctx.user.id,
                    status=ShopStatus.PENDING_VERIFICATION)
        self.db.add(shop)
        self.db.flush()
        self.db.add(ShopUser(shop_id=shop.id, user_id=ctx.user.id, role_code="OWNER", added_by=ctx.user.id))
        self.db.add(ShopStatusHistory(shop_id=shop.id, from_status=None, to_status=shop.status,
                                      reason="created", changed_by=ctx.user.id))
        self.ensure_capability(ctx.user.id, "BUYER")
        self.ensure_capability(ctx.user.id, "SELLER", status="PENDING")
        self.authz.bump_user(ctx.user.id)
        audit.record(self.db, action="shop.created", category=AuditCategory.GENERAL, actor_user_id=ctx.user.id,
                     actor_type="user", entity_type="shop", entity_id=shop.id, shop_id=shop.id,
                     details={"slug": shop.slug})
        self.db.commit()
        return shop

    def update_profile(self, ctx: SessionContext, slug: str, *, name: str, description: str | None,
                       region: str | None) -> Shop:
        shop = self.shop_for(ctx, slug, "shop.profile.update", lock=True)
        name = " ".join((name or "").split())
        if not 3 <= len(name) <= 80:
            raise AuthError("Jina la duka liwe na herufi 3 hadi 80.", status=422, code="invalid", field="name")
        shop.name, shop.description = name, (description or "").strip()[:2000] or None
        shop.region = (region or "").strip()[:60] or None
        audit.record(self.db, action="shop.profile_updated", actor_user_id=ctx.user.id, actor_type="user",
                     entity_type="shop", entity_id=shop.id, shop_id=shop.id)
        self.db.commit()
        return shop

    # ---------------------------------------------------------------- staff (SHOP-004, BR-006, BR-008)
    def members(self, ctx: SessionContext, slug: str) -> list[dict]:
        shop = self.shop_for(ctx, slug, "shop.admin.view")
        rows = self.db.execute(select(ShopUser, User).join(User, User.id == ShopUser.user_id)
                               .where(ShopUser.shop_id == shop.id, ShopUser.removed_at.is_(None))
                               .order_by(ShopUser.added_at)).all()
        return [{"user_id": str(u.public_id), "name": u.full_name, "role": m.role_code,
                 "added_at": m.added_at.isoformat()} for m, u in rows]

    def add_member(self, ctx: SessionContext, slug: str, phone: str, role: str) -> dict:
        role = (role or "").upper()
        if role == "OWNER":
            raise AuthError("Umiliki hauwezi kutolewa hivi. Tumia uhamisho wa umiliki.", status=403,
                            code="owner_not_assignable")
        if role not in ("MANAGER", "STAFF"):
            raise AuthError("Jukumu si sahihi.", status=422, code="invalid", field="role")
        perm = "shop.managers.manage" if role == "MANAGER" else "shop.staff.manage"
        shop = self.shop_for(ctx, slug, perm, lock=True)
        self._limit(MEMBER_ADD, str(shop.id))
        try:
            phone_e164 = normalize_phone(phone, self.settings.default_phone_region)
        except IdentifierError as exc:
            raise AuthError(str(exc), status=422, code="invalid", field="phone") from None
        user = self.db.execute(select(User).where(User.phone_e164 == phone_e164)).scalar_one_or_none()
        if user is None or user.status != UserStatus.ACTIVE:
            raise AuthError("Hakuna akaunti hai yenye namba hii. Mwambie ajisajili kwanza.", status=404,
                            code="user_not_found", field="phone")
        if self.membership(shop.id, user.id) is not None:
            raise AuthError("Mtu huyu tayari ni mwanachama wa duka hili.", status=409, code="exists")
        self.db.add(ShopUser(shop_id=shop.id, user_id=user.id, role_code=role, added_by=ctx.user.id))
        self.authz.bump_user(user.id)
        audit.record(self.db, action="shop.member_added", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="user", entity_id=user.id,
                     shop_id=shop.id, details={"role": role})
        self._sms(user.phone_e164, f"Bongo Markets: Umeongezwa kama {role.title()} wa duka '{shop.name}'.")
        self.db.commit()
        return {"user_id": str(user.public_id), "name": user.full_name, "role": role}

    def remove_member(self, ctx: SessionContext, slug: str, member_public_id: str) -> None:
        shop = self.shop_for(ctx, slug, "shop.admin.view", lock=True)
        try:
            pid = uuid.UUID(str(member_public_id))
        except ValueError:
            raise AuthError("Mwanachama hapatikani.", status=404, code="not_found") from None
        target = self.db.execute(select(User).where(User.public_id == pid)).scalar_one_or_none()
        member = self.membership(shop.id, target.id) if target else None
        if member is None:
            raise AuthError("Mwanachama hapatikani.", status=404, code="not_found")
        if member.role_code == "OWNER":
            raise AuthError("Mmiliki hawezi kuondolewa. Hamisha umiliki kwanza.", status=403, code="owner")
        self_removal = target.id == ctx.user.id
        need = "shop.managers.manage" if member.role_code == "MANAGER" else "shop.staff.manage"
        if not self_removal and not self.authz.can(ctx.user.id, need, shop_id=shop.id):
            raise AuthError("Huna ruhusa ya kumwondoa mwanachama huyu.", status=403, code="forbidden")
        member.removed_at, member.removed_by = _now(), ctx.user.id
        self.authz.bump_user(target.id)
        audit.record(self.db, action="shop.member_removed", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="user", entity_id=target.id,
                     shop_id=shop.id, details={"role": member.role_code, "self": self_removal})
        self.db.commit()

    # ---------------------------------------------------------------- ownership transfer (BR-005)
    def transfer_ownership(self, ctx: SessionContext, slug: str, new_owner_public_id: str,
                           step_up_token: str | None) -> None:
        shop = self.shop_for(ctx, slug, "shop.ownership.transfer", lock=True)
        self.consume_step_up(ctx, StepUpAction.OWNERSHIP_TRANSFER, step_up_token)
        try:
            pid = uuid.UUID(str(new_owner_public_id))
        except ValueError:
            raise AuthError("Mwanachama hapatikani.", status=404, code="not_found") from None
        new_owner = self.db.execute(select(User).where(User.public_id == pid)).scalar_one_or_none()
        target_member = self.membership(shop.id, new_owner.id) if new_owner else None
        if target_member is None or new_owner.status != UserStatus.ACTIVE:
            raise AuthError("Mmiliki mpya lazima awe mwanachama hai wa duka hili.", status=409, code="not_member")
        if new_owner.id == ctx.user.id:
            raise AuthError("Tayari wewe ndiye mmiliki.", status=409, code="same_owner")
        old_owner_member = self.membership(shop.id, ctx.user.id)
        now = _now()
        # One transaction; the deferred DB trigger verifies the invariant at COMMIT.
        old_owner_member.removed_at, old_owner_member.removed_by = now, ctx.user.id
        target_member.removed_at, target_member.removed_by = now, ctx.user.id
        self.db.flush()
        self.db.add(ShopUser(shop_id=shop.id, user_id=new_owner.id, role_code="OWNER", added_by=ctx.user.id))
        self.db.add(ShopUser(shop_id=shop.id, user_id=ctx.user.id, role_code="MANAGER", added_by=ctx.user.id))
        shop.owner_user_id = new_owner.id
        self.authz.bump_user(new_owner.id)
        self.authz.bump_user(ctx.user.id)
        self.ensure_capability(new_owner.id, "SELLER", status="PENDING")
        audit.record(self.db, action="shop.ownership_transferred", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="shop", entity_id=shop.id,
                     shop_id=shop.id, details={"from": str(ctx.user.public_id), "to": str(new_owner.public_id)})
        self._sms(new_owner.phone_e164, f"Bongo Markets: Sasa wewe ndiye mmiliki wa duka '{shop.name}'.")
        self._sms(ctx.user.phone_e164, f"Bongo Markets: Umehamisha umiliki wa duka '{shop.name}'.")
        self.db.commit()

    # ---------------------------------------------------------------- lifecycle (SHOP-006, ADM-003)
    def set_status(self, ctx: SessionContext, slug: str, to_status: str, reason: str) -> Shop:
        self.require_permission(ctx, "platform.shops.verify")
        shop = self.shop_by_slug(slug, lock=True)
        if shop is None:
            raise AuthError(NOT_FOUND, status=404, code="not_found")
        try:
            target = ShopStatus(to_status)
        except ValueError:
            raise AuthError("Hali si sahihi.", status=422, code="invalid", field="status") from None
        if target not in TRANSITIONS[ShopStatus(shop.status)]:
            raise AuthError(f"Haiwezekani kubadilisha kutoka {shop.status} kwenda {target}.", status=409,
                            code="invalid_transition")
        if len((reason or "").strip()) < 3:
            raise AuthError("Andika sababu.", status=422, code="invalid", field="reason")
        old = shop.status
        shop.status = target
        self.db.add(ShopStatusHistory(shop_id=shop.id, from_status=old, to_status=target,
                                      reason=reason.strip()[:1000], changed_by=ctx.user.id))
        if target == ShopStatus.ACTIVE:
            self.ensure_capability(shop.owner_user_id, "SELLER").status = "ACTIVE"
        # Members' cached shop permissions must refresh (suspension/closure).
        for (uid,) in self.db.execute(select(ShopUser.user_id).where(ShopUser.shop_id == shop.id,
                                                                     ShopUser.removed_at.is_(None))):
            self.authz.bump_user(uid)
        audit.record(self.db, action="shop.status_changed", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="shop", entity_id=shop.id,
                     shop_id=shop.id, details={"from": old, "to": target, "reason": reason.strip()[:200]})
        owner = self.db.get(User, shop.owner_user_id)
        labels = {"ACTIVE": "limethibitishwa", "REJECTED": "limekataliwa", "SUSPENDED": "limesimamishwa",
                  "CLOSED": "limefungwa", "PENDING_VERIFICATION": "linasubiri uthibitisho"}
        self._sms(owner.phone_e164, f"Bongo Markets: Duka lako '{shop.name}' {labels[target]}.")
        self.db.commit()
        return shop

    def resubmit(self, ctx: SessionContext, slug: str) -> Shop:
        shop = self.shop_for(ctx, slug, "shop.profile.update", lock=True)
        if shop.status != ShopStatus.REJECTED:
            raise AuthError("Duka hili haliwezi kutumwa tena kwa uthibitisho.", status=409, code="invalid_transition")
        shop.status = ShopStatus.PENDING_VERIFICATION
        self.db.add(ShopStatusHistory(shop_id=shop.id, from_status="REJECTED", to_status=shop.status,
                                      reason="resubmitted", changed_by=ctx.user.id))
        self.db.commit()
        return shop

    def history(self, shop: Shop) -> list[dict]:
        rows = self.db.execute(select(ShopStatusHistory).where(ShopStatusHistory.shop_id == shop.id)
                               .order_by(ShopStatusHistory.id)).scalars()
        return [{"from": h.from_status, "to": h.to_status, "reason": h.reason, "at": h.changed_at.isoformat()}
                for h in rows]

    # ---------------------------------------------------------------- shop admin dashboard (SHOP-005, M10)
    def dashboard(self, ctx: SessionContext, slug: str) -> dict:
        """Only for members of this shop (generic 404 otherwise). Sections depend on the caller's permissions."""
        from sqlalchemy import text as sql

        shop = self.shop_for(ctx, slug, "shop.admin.view")
        perms = {p for p in ("shop.products.manage", "shop.profile.update", "shop.staff.manage",
                             "shop.managers.manage", "shop.ownership.transfer", "shop.orders.view",
                             "shop.orders.fulfil", "shop.analytics.view")
                 if self.authz.can(ctx.user.id, p, shop_id=shop.id)}
        counts = dict(self.db.execute(sql("SELECT status, count(*) FROM bm.products WHERE shop_id = :s "
                                          "GROUP BY status"), {"s": shop.id}).all())
        low = [{"name": n, "available": a} for n, a in self.db.execute(sql(
            "SELECT name, stock - reserved FROM bm.products WHERE shop_id = :s AND status = 'ACTIVE' "
            "AND stock - reserved <= 3 ORDER BY stock - reserved, name LIMIT 10"), {"s": shop.id})]
        team = self.db.execute(sql("SELECT count(*) FROM bm.shop_users WHERE shop_id = :s AND removed_at IS NULL"),
                               {"s": shop.id}).scalar_one()
        out = {"shop": self._shop_dict(shop), "my_role": self.membership(shop.id, ctx.user.id).role_code,
               "permissions": sorted(perms), "team_size": team,
               "products": {"active": counts.get("ACTIVE", 0), "draft": counts.get("DRAFT", 0),
                            "suspended": counts.get("SUSPENDED", 0)},
               "low_stock": low if "shop.products.manage" in perms else []}
        from app.shops.dashboard_hooks import extra_sections

        out.update(extra_sections(self.db, shop, perms))
        return out

    def pending_shops(self, ctx: SessionContext) -> list[Shop]:
        self.require_permission(ctx, "platform.shops.verify")
        return list(self.db.execute(select(Shop).where(Shop.status == ShopStatus.PENDING_VERIFICATION)
                                    .order_by(Shop.created_at)).scalars())
