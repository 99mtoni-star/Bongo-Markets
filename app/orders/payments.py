"""Payment confirmation and unpaid-order expiry (M12 side of the payment boundary).

- Only a *verified* provider event may change ``orders.payment_status``. The database enforces this:
  the trigger ``bm.guard_payment_status`` rejects any change unless the transaction has set
  ``bm.payment_context = 'provider-verified'`` (SET LOCAL, so it never leaks past the transaction).
  Browser input can therefore never mark an order PAID (BR-013, BR-014).
- The real provider adapters (signature verification, webhooks, reconciliation) belong to M13.
  Until then a development-only simulator (``/dev/lipa/{number}``, 404 outside dev/test) calls
  :func:`confirm_payment` with a fake reference so the order lifecycle can be demonstrated.
- Confirmed payment converts every reservation of the order into a sale (STK-003). If the reservation
  window has already passed, the order expires and is flagged ``refund_required`` instead (ORD-LC-006).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.catalog import stock as stock_engine
from app.db.models import AuditCategory
from app.orders.models import Order, OrderItem, OrderStatus, OrderStatusHistory, PaymentStatus
from app.services import audit


def _now() -> datetime:
    return datetime.now(UTC)


def _history(db: Session, order: Order, to: str, actor_type: str, actor_user_id: int | None = None,
             note: str | None = None) -> None:
    db.add(OrderStatusHistory(order_id=order.id, from_status=order.status, to_status=to, actor_type=actor_type,
                              actor_user_id=actor_user_id, note=(note or "")[:300] or None))


def _release_all(db: Session, order: Order, note: str, now: datetime) -> None:
    for item in db.execute(select(OrderItem).where(OrderItem.order_id == order.id)
                           .order_by(OrderItem.product_id)).scalars():
        if item.reservation_id:
            stock_engine.release(db, item.reservation_id, now=now, note=note)


def confirm_payment(db: Session, order_number: str, provider_ref: str, *, now: datetime | None = None) -> str:
    """Apply a verified payment to an order. Idempotent. Returns the resulting order status. Commits."""
    now = now or _now()
    order = db.execute(select(Order).where(Order.number == order_number).with_for_update()).scalar_one_or_none()
    if order is None:
        raise LookupError("order not found")
    if order.payment_status != PaymentStatus.UNPAID:
        db.rollback()
        return order.status  # duplicate provider event: nothing changes (processed once)
    db.execute(text("SET LOCAL bm.payment_context = 'provider-verified'"))
    order.payment_status = PaymentStatus.PAID
    if order.status == OrderStatus.PENDING_PAYMENT:
        try:
            for item in db.execute(select(OrderItem).where(OrderItem.order_id == order.id)
                                   .order_by(OrderItem.product_id)).scalars():
                stock_engine.commit(db, item.reservation_id, now=now)
        except stock_engine.StockError:
            # Paid too late: the hold expired. Undo partial commits, expire the order, flag refund.
            db.rollback()
            db.execute(text("SET LOCAL bm.payment_context = 'provider-verified'"))
            order = db.execute(select(Order).where(Order.id == order.id).with_for_update()).scalar_one()
            order.payment_status = PaymentStatus.PAID
            _release_all(db, order, "payment after expiry", now)
            _history(db, order, OrderStatus.EXPIRED, "system", note="Malipo yamechelewa; marejesho yanahitajika")
            order.status, order.refund_required, order.cancelled_at = OrderStatus.EXPIRED, True, now
        else:
            _history(db, order, OrderStatus.CONFIRMED, "system", note="Malipo yamethibitishwa")
            order.status, order.confirmed_at, order.expires_at = OrderStatus.CONFIRMED, now, None
    else:  # payment for an order that was already cancelled/expired
        order.refund_required = True
    audit.record(db, action="order.payment_confirmed", category=AuditCategory.FINANCIAL, actor_type="provider",
                 entity_type="order", entity_id=order.id, shop_id=order.shop_id,
                 details={"number": order.number, "provider_ref": provider_ref[:64], "status": order.status,
                          "refund_required": order.refund_required})
    db.commit()
    return order.status


def expire_unpaid(db: Session, *, now: datetime | None = None) -> int:
    """Expire PENDING_PAYMENT orders whose hold has passed and release their stock (ORD-LC-006). Commits."""
    now = now or _now()
    orders = db.execute(select(Order).where(Order.status == OrderStatus.PENDING_PAYMENT, Order.expires_at <= now)
                        .order_by(Order.id).with_for_update(skip_locked=True)).scalars().all()
    for order in orders:
        _release_all(db, order, "order expired", now)
        _history(db, order, OrderStatus.EXPIRED, "system", note="Muda wa kulipa umekwisha")
        order.status, order.cancelled_at = OrderStatus.EXPIRED, now
        audit.record(db, action="order.expired", category=AuditCategory.FINANCIAL, entity_type="order",
                     entity_id=order.id, shop_id=order.shop_id, details={"number": order.number})
    db.commit()
    return len(orders)
