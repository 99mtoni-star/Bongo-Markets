#!/usr/bin/env python3
"""Personal-data retention (SEC-COM-004).

Anonymizes accounts that were CLOSED more than BM_CLOSED_ACCOUNT_RETENTION_DAYS ago, unless an
active legal hold exists. Identity rows are kept (immutable userId; financial records still point
at them) but name, phone, email, password and MFA data are irreversibly replaced. Run daily.

Audit-log retention is a separate DBA procedure: bm.purge_audit_logs(category, before), which only
the schema owner can execute and which refuses dates inside the retention period.

Usage: python scripts/retention.py [--dry-run]
"""

from __future__ import annotations

import argparse
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import exists, select  # noqa: E402

from app.auth.models import User, UserStatus  # noqa: E402
from app.auth.passwords import hash_password  # noqa: E402
from app.authz.models import LegalHold  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.models import AuditCategory  # noqa: E402
from app.db.session import session_factory  # noqa: E402
from app.services import audit  # noqa: E402


def placeholder_phone(user_id: int) -> str:
    # Valid E.164 shape (DB constraint) in the unassigned +9 range; can never collide with a real number.
    return "+9" + f"{user_id:013d}"[-13:]


def run(settings: Settings | None = None, *, dry_run: bool = False, now: datetime | None = None) -> dict:
    settings = settings or Settings()
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=settings.closed_account_retention_days)
    report = {"anonymized": 0, "held": 0}
    with session_factory(settings)() as db:
        held = exists().where(LegalHold.user_id == User.id, LegalHold.released_at.is_(None))
        due = db.execute(select(User).where(User.status == UserStatus.CLOSED, User.closed_at < cutoff,
                                            User.anonymized_at.is_(None)).with_for_update()).scalars().all()
        for user in due:
            if db.execute(select(held.where(LegalHold.user_id == user.id))).scalar():
                report["held"] += 1
                continue
            report["anonymized"] += 1
            if dry_run:
                continue
            user.full_name = "Mtumiaji aliyefutwa"
            user.phone_e164 = placeholder_phone(user.id)
            user.email = None
            user.email_verified_at = None
            user.password_hash = hash_password(secrets.token_urlsafe(32))
            user.totp_secret_enc = user.totp_enabled_at = user.totp_last_step = None
            user.anonymized_at = now
            audit.record(db, action="user.anonymized", category=AuditCategory.SECURITY, actor_type="retention",
                         entity_type="user", entity_id=user.id)
        if not dry_run:
            db.commit()
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    print(run(dry_run=ap.parse_args().dry_run))
