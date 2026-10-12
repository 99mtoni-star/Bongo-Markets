"""Stock reservations (STK-001..004, STK-001 v1.12.2).

Invariant kept by the database: 0 <= reserved <= stock on every product row.
All operations lock the product row (SELECT ... FOR UPDATE), so concurrent buyers of the last
unit serialize and only one reservation can succeed.

  reserve   available = stock - reserved must cover the quantity; reserved += q
  commit    on verified payment: stock -= q, reserved -= q        (STK-003)
  release   on failure/cancel:   reserved -= q
  expire    ACTIVE reservations past expires_at are released     (STK-003)
The reservation period defaults to 15 minutes and is a platform setting (STK-002).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.catalog.models import Product, ProductStatus, ReservationStatus, StockReservation
from app.db.models import SystemFlag

SETTING_KEY = "stock_reservation_minutes"
DEFAULT_MINUTES = 15
MIN_MINUTES, MAX_MINUTES = 5, 60


class StockError(Exception):
    def __init__(self, message: str, code: str = "stock_error"):
        super().__init__(message)
        self.message = message
        self.code = code


def _now() -> datetime:
    return datetime.now(UTC)


def reservation_minutes(db: Session) -> int:
    flag = db.get(SystemFlag, SETTING_KEY)
    try:
        value = int(flag.value) if flag else DEFAULT_MINUTES
    except ValueError:
        value = DEFAULT_MINUTES
    return min(max(value, MIN_MINUTES), MAX_MINUTES)


def _locked_product(db: Session, product_id: int) -> Product:
    product = db.execute(select(Product).where(Product.id == product_id).with_for_update()).scalar_one_or_none()
    if product is None:
        raise StockError("Bidhaa haipatikani.", "not_found")
    return product


def reserve(db: Session, product_id: int, quantity: int, holder: str, user_id: int | None = None,
            *, now: datetime | None = None) -> StockReservation:
    """Reserve stock inside the caller's transaction. Caller commits."""
    if quantity <= 0:
        raise StockError("Idadi lazima iwe zaidi ya sifuri.", "invalid_quantity")
    now = now or _now()
    product = _locked_product(db, product_id)
    _expire_for_product(db, product, now)
    if product.status != ProductStatus.ACTIVE:
        raise StockError("Bidhaa hii haipatikani kwa sasa.", "unavailable")
    available = product.stock - product.reserved
    if available < quantity:
        raise StockError(f"Stock haitoshi. Zilizobaki: {max(available, 0)}.", "insufficient_stock")
    product.reserved += quantity
    res = StockReservation(product_id=product.id, quantity=quantity, holder=holder[:64], user_id=user_id,
                           status=ReservationStatus.ACTIVE,
                           expires_at=now + timedelta(minutes=reservation_minutes(db)))
    db.add(res)
    db.flush()
    return res


def _resolve(db: Session, res: StockReservation, to: ReservationStatus, *, now: datetime) -> None:
    product = _locked_product(db, res.product_id)
    if to == ReservationStatus.COMMITTED:
        product.stock -= res.quantity
    product.reserved -= res.quantity
    res.status, res.resolved_at = to, now


def commit(db: Session, reservation_id: int, *, now: datetime | None = None) -> StockReservation:
    """Verified payment inside the reservation period consumes the stock (STK-003)."""
    now = now or _now()
    res = db.execute(select(StockReservation).where(StockReservation.id == reservation_id).with_for_update()) \
        .scalar_one()
    if res.status != ReservationStatus.ACTIVE:
        raise StockError("Muda wa kushikilia bidhaa umekwisha.", "reservation_not_active")
    if res.expires_at <= now:
        _resolve(db, res, ReservationStatus.EXPIRED, now=now)
        raise StockError("Muda wa kushikilia bidhaa umekwisha.", "reservation_expired")
    _resolve(db, res, ReservationStatus.COMMITTED, now=now)
    return res


def release(db: Session, reservation_id: int, *, now: datetime | None = None, note: str | None = None) -> None:
    now = now or _now()
    res = db.execute(select(StockReservation).where(StockReservation.id == reservation_id).with_for_update()) \
        .scalar_one()
    if res.status == ReservationStatus.ACTIVE:
        _resolve(db, res, ReservationStatus.RELEASED, now=now)
        res.note = (note or "")[:200] or None


def _expire_for_product(db: Session, product: Product, now: datetime) -> int:
    expired = db.execute(select(StockReservation).where(
        StockReservation.product_id == product.id, StockReservation.status == ReservationStatus.ACTIVE,
        StockReservation.expires_at <= now).with_for_update()).scalars().all()
    for res in expired:
        product.reserved -= res.quantity
        res.status, res.resolved_at = ReservationStatus.EXPIRED, now
    return len(expired)


def expire_all(db: Session, *, now: datetime | None = None) -> int:
    """Background sweep (cron every minute): release every expired reservation. Caller commits."""
    now = now or _now()
    ids = db.execute(select(StockReservation.product_id).where(
        StockReservation.status == ReservationStatus.ACTIVE, StockReservation.expires_at <= now).distinct()
    ).scalars().all()
    total = 0
    for pid in sorted(ids):  # consistent lock order avoids deadlocks
        total += _expire_for_product(db, _locked_product(db, pid), now)
    return total


def restock(db: Session, product_id: int, quantity: int) -> None:
    """Return committed (sold) units to stock when a paid order is cancelled before shipping (ORD-LC-006)."""
    if quantity <= 0:
        raise StockError("Idadi lazima iwe zaidi ya sifuri.", "invalid_quantity")
    _locked_product(db, product_id).stock += quantity
