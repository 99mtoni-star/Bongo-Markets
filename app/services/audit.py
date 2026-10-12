"""Audit trail writer (M02 foundation; used by every later module)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.core.logging import redact, request_id_var
from app.db.models import PAYMENTS_RECONCILIATION_REQUIRED, AuditCategory, AuditLog, SystemFlag


def record(
    session: Session,
    *,
    action: str,
    category: AuditCategory = AuditCategory.GENERAL,
    actor_user_id: int | None = None,
    actor_type: str = "system",
    entity_type: str | None = None,
    entity_id: str | int | None = None,
    shop_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Append one audit event. Secrets in ``details`` are redacted before storage (DON-008)."""
    rid = request_id_var.get()
    session.execute(
        insert(AuditLog).values(
            category=category.value,
            action=action,
            actor_user_id=actor_user_id,
            actor_type=actor_type,
            entity_type=entity_type,
            entity_id=None if entity_id is None else str(entity_id),
            shop_id=shop_id,
            request_id=None if rid == "-" else rid,
            details=redact(details or {}),
        )
    )


def payments_authoritative(session: Session) -> bool:
    """False while post-recovery payment reconciliation is pending (NFR-DR-008).

    While False, payment status in the database must not be treated as final;
    M13 consults this before acting on stored payment state.
    """
    value = session.execute(
        select(SystemFlag.value).where(SystemFlag.key == PAYMENTS_RECONCILIATION_REQUIRED)
    ).scalar_one_or_none()
    return value != "true"
