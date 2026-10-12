#!/usr/bin/env python3
"""Operator command line for bootstrap and break-glass incident response (SEC-IR-003).

Runs with the application's database credentials (BM_DATABASE_URL); every action is
written to the audit log with actor_type "cli" and the operator name.

  bootstrap-super-admin  --phone 07XX... --operator NAME
        Grant SUPER_ADMIN to the first administrator. Refused if any active SUPER_ADMIN
        exists, or if the target has not enabled TOTP MFA (SEC-MFA-004).
  revoke-sessions        --phone 07XX... --operator NAME --reason TEXT
  suspend-user           --phone 07XX... --operator NAME --reason TEXT
  payments               --suspend | --resume --operator NAME --reason TEXT
  revoke-all-sessions    --operator NAME --reason TEXT        (platform-wide, e.g. after key compromise)

In normal operation use the authenticated admin API (MFA + step-up). This tool exists for
first-time setup and for emergencies when the admin API itself is unavailable.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select, update  # noqa: E402

from app.auth.identifiers import normalize_phone  # noqa: E402
from app.auth.models import User as UserModel  # noqa: E402
from app.auth.models import UserPlatformRole, UserSession, UserStatus  # noqa: E402
from app.auth.security import PAYMENTS_SUSPENDED  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.models import AuditCategory, SystemFlag  # noqa: E402
from app.db.session import session_factory  # noqa: E402
from app.services import audit  # noqa: E402


def _user(db, phone: str, region: str) -> UserModel:
    user = db.execute(select(UserModel).where(UserModel.phone_e164 == normalize_phone(phone, region))
                      .with_for_update()).scalar_one_or_none()
    if user is None:
        raise SystemExit("No user with that phone number")
    return user


def _revoke(db, user_id: int | None, reason: str) -> int:
    stmt = update(UserSession).where(UserSession.revoked_at.is_(None)).values(
        revoked_at=datetime.now(UTC), revoke_reason=reason[:64])
    if user_id is not None:
        stmt = stmt.where(UserSession.user_id == user_id)
    return db.execute(stmt).rowcount or 0


def run(argv: list[str] | None = None, settings: Settings | None = None) -> str:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["bootstrap-super-admin", "revoke-sessions", "suspend-user", "payments",
                                        "revoke-all-sessions"])
    ap.add_argument("--phone")
    ap.add_argument("--operator", required=True)
    ap.add_argument("--reason", default="")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--suspend", action="store_true")
    g.add_argument("--resume", action="store_true")
    a = ap.parse_args(argv)
    if a.command != "bootstrap-super-admin" and len(a.reason.strip()) < 3:
        raise SystemExit("--reason is required (at least 3 characters)")

    settings = settings or Settings()
    with session_factory(settings)() as db:
        details = {"operator": a.operator[:64], "reason": a.reason[:200]}
        if a.command == "bootstrap-super-admin":
            existing = db.execute(select(UserPlatformRole.id).where(
                UserPlatformRole.role_code == "SUPER_ADMIN", UserPlatformRole.revoked_at.is_(None))).first()
            if existing:
                raise SystemExit("An active SUPER_ADMIN already exists; use the admin API (MFA + step-up)")
            user = _user(db, a.phone or "", settings.default_phone_region)
            if user.status != UserStatus.ACTIVE or user.totp_enabled_at is None:
                raise SystemExit("Target must be an ACTIVE user with TOTP MFA enabled")
            db.add(UserPlatformRole(user_id=user.id, role_code="SUPER_ADMIN"))
            _revoke(db, user.id, "role_granted")
            audit.record(db, action="role.granted", category=AuditCategory.SECURITY, actor_type="cli",
                         entity_type="user", entity_id=user.id, details={**details, "role": "SUPER_ADMIN"})
            msg = "SUPER_ADMIN granted; the user must sign in again with MFA"
        elif a.command in ("revoke-sessions", "suspend-user"):
            user = _user(db, a.phone or "", settings.default_phone_region)
            if a.command == "suspend-user":
                user.status = UserStatus.SUSPENDED
            n = _revoke(db, user.id, "incident_response")
            audit.record(db, action=f"incident.{a.command.replace('-', '_')}", category=AuditCategory.SECURITY,
                         actor_type="cli", entity_type="user", entity_id=user.id, details={**details, "sessions": n})
            msg = f"{a.command}: done ({n} sessions revoked)"
        elif a.command == "revoke-all-sessions":
            n = _revoke(db, None, "incident_global_revoke")
            audit.record(db, action="incident.global_sessions_revoked", category=AuditCategory.SECURITY,
                         actor_type="cli", details={**details, "sessions": n})
            msg = f"All sessions revoked ({n})"
        else:
            if not (a.suspend or a.resume):
                raise SystemExit("payments needs --suspend or --resume")
            flag = db.get(SystemFlag, PAYMENTS_SUSPENDED) or SystemFlag(key=PAYMENTS_SUSPENDED, value="false",
                                                                         updated_by="cli")
            db.add(flag)
            flag.value, flag.reason, flag.updated_by = ("true" if a.suspend else "false"), a.reason[:500], "cli"
            audit.record(db, action="incident.payments_suspended" if a.suspend else "incident.payments_resumed",
                         category=AuditCategory.FINANCIAL, actor_type="cli", details=details)
            msg = f"Payments {'SUSPENDED' if a.suspend else 'resumed'}"
        db.commit()
    return msg


if __name__ == "__main__":
    print(run())
