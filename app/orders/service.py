"""Orders, fulfilment and delivery confirmation (M12).

Lifecycle (ORD-LC-*):

    PENDING_PAYMENT --verified payment--> CONFIRMED --seller--> PROCESSING --seller+courier--> SHIPPED
          |                                  |                     |                             |
     buyer cancel / expiry             seller cancel         seller cancel                delivery PIN
          v                                  v                     v                             v
    CANCELLED / EXPIRED                  CANCELLED (stock back, refund_required)            DELIVERED

- Buyers see only their own orders; anything else is a generic 404 (ORD-004).
- Shop members see only orders of shops where they hold ``shop.orders.view``; transitions need
  ``shop.orders.fulfil`` (ORD-005, ORD-LC-002). Customers have no endpoint that sets a fulfilment state
  (ORD-LC-004); a buyer can only cancel while unpaid or *request* cancellation afterwards (ORD-LC-001).
- Every transition locks the order row, checks the current state, writes history and an audit event in
  the same transaction (ORD-006, DEL-001).
- Delivery confirmation (DEL-002, V13-TRUST-002): a 6-digit PIN is generated when the order ships and sent
  by SMS to the buyer. Only an HMAC bound to this order is stored, it works once (cleared on success),
  it is useless for any other order, and 5 wrong attempts lock it until the buyer requests a new one.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select

from app.auth.identifiers import IdentifierError, normalize_phone
from app.auth.models import User
from app.auth.service import AuthError, SessionContext
from app.catalog import stock as stock_engine
from app.catalog.models import ReservationStatus, StockReservation
from app.db.models import AuditCategory
from app.orders.cart import CartService
from app.orders.models import Order, OrderItem, OrderStatus, OrderStatusHistory
from app.orders.payments import _history, _release_all
from app.services import audit
from app.shops.models import Shop

ORDER_NOT_FOUND = "Oda haipatikani."
PIN_MAX_ATTEMPTS = 5
SELLER_NEXT = {OrderStatus.CONFIRMED: OrderStatus.PROCESSING, OrderStatus.PROCESSING: OrderStatus.SHIPPED}
SELLER_CANCELLABLE = (OrderStatus.CONFIRMED, OrderStatus.PROCESSING)
STATUS_LABELS = {
    "PENDING_PAYMENT": "Inasubiri malipo", "CONFIRMED": "Imethibitishwa", "PROCESSING": "Inaandaliwa",
    "SHIPPED": "Imesafirishwa", "DELIVERED": "Imefika", "CANCELLED": "Imeghairiwa", "EXPIRED": "Muda umekwisha",
}


def _now() -> datetime:
    return datetime.now(UTC)


class OrderService(CartService):
    # ---------------------------------------------------------------- lookup
    def _by_number(self, number: str, *, lock: bool = False) -> Order | None:
        q = select(Order).where(Order.number == (number or "").upper()[:24])
        return self.db.execute(q.with_for_update() if lock else q).scalar_one_or_none()

    def buyer_order(self, ctx: SessionContext, number: str, *, lock: bool = False) -> Order:
        order = self._by_number(number, lock=lock)
        if order is None or order.buyer_user_id != ctx.user.id:
            raise AuthError(ORDER_NOT_FOUND, status=404, code="not_found")  # ORD-004: no probing
        return order

    def shop_order(self, ctx: SessionContext, slug: str, number: str, permission: str,
                   *, lock: bool = False) -> tuple[Shop, Order]:
        shop = self.shop_for(ctx, slug, permission)
        order = self._by_number(number, lock=lock)
        if order is None or order.shop_id != shop.id:
            raise AuthError(ORDER_NOT_FOUND, status=404, code="not_found")  # ORD-005
        return shop, order

    # ---------------------------------------------------------------- views
    def order_dict(self, order: Order, *, seller: bool = False) -> dict:
        items = self.db.execute(select(OrderItem).where(OrderItem.order_id == order.id).order_by(OrderItem.id)) \
            .scalars().all()
        history = self.db.execute(select(OrderStatusHistory).where(OrderStatusHistory.order_id == order.id)
                                  .order_by(OrderStatusHistory.id)).scalars().all()
        shop = self.db.get(Shop, order.shop_id)
        out = {
            "number": order.number, "id": str(order.public_id), "status": order.status,
            "status_label": STATUS_LABELS.get(order.status, order.status), "payment_status": order.payment_status,
            "payment_method": order.payment_method, "currency": order.currency, "subtotal": str(order.subtotal),
            "total": str(order.total), "items_count": order.items_count,
            "shop": {"slug": shop.slug, "name": shop.name},
            "delivery": {"name": order.delivery_name, "phone": order.delivery_phone, "region": order.delivery_region,
                         "area": order.delivery_area, "street": order.delivery_street, "notes": order.delivery_notes},
            "courier": ({"name": order.courier_name, "phone": order.courier_phone} if order.courier_name else None),
            "cancel_requested": order.cancel_requested_at is not None, "cancel_reason": order.cancel_reason,
            "refund_required": order.refund_required,
            "pin_active": order.delivery_pin_hash is not None, "pin_locked": order.pin_attempts >= PIN_MAX_ATTEMPTS,
            "created_at": order.created_at.isoformat(),
            "expires_at": order.expires_at.isoformat() if order.expires_at else None,
            "items": [{"id": str(i.public_id), "sku": i.sku, "name": i.name, "unit": i.unit,
                       "image": f"/media/{i.image_key}" if i.image_key else None, "unit_price": str(i.unit_price),
                       "quantity": i.quantity, "line_total": str(i.line_total)} for i in items],
            "history": [{"from": h.from_status, "to": h.to_status, "actor": h.actor_type, "note": h.note,
                         "at": h.at.isoformat()} for h in history],
        }
        if seller:
            out["actions"] = self._seller_actions(order)
        else:
            out["actions"] = self._buyer_actions(order)
        return out

    @staticmethod
    def _buyer_actions(o: Order) -> list[str]:
        acts = []
        if o.status == OrderStatus.PENDING_PAYMENT:
            acts.append("cancel")
        if o.status in SELLER_CANCELLABLE and o.cancel_requested_at is None:
            acts.append("request_cancel")
        if o.status == OrderStatus.SHIPPED:
            acts.append("resend_pin")
        return acts

    @staticmethod
    def _seller_actions(o: Order) -> list[str]:
        acts = []
        if o.status == OrderStatus.CONFIRMED:
            acts.append("process")
        if o.status == OrderStatus.PROCESSING:
            acts.append("ship")
        if o.status == OrderStatus.SHIPPED:
            acts += ["deliver", "assign_courier"]
        if o.status in SELLER_CANCELLABLE:
            acts.append("cancel")
        return acts

    def _summary(self, o: Order, shop: Shop | None = None) -> dict:
        shop = shop or self.db.get(Shop, o.shop_id)
        return {"number": o.number, "status": o.status, "status_label": STATUS_LABELS.get(o.status, o.status),
                "payment_status": o.payment_status, "total": str(o.total), "items_count": o.items_count,
                "shop": {"slug": shop.slug, "name": shop.name}, "customer": o.delivery_name,
                "cancel_requested": o.cancel_requested_at is not None, "created_at": o.created_at.isoformat()}

    def my_orders(self, ctx: SessionContext, limit: int = 50) -> list[dict]:
        rows = self.db.execute(select(Order, Shop).join(Shop, Shop.id == Order.shop_id)
                               .where(Order.buyer_user_id == ctx.user.id)
                               .order_by(Order.created_at.desc(), Order.id.desc()).limit(limit)).all()
        return [self._summary(o, s) for o, s in rows]

    def shop_orders(self, ctx: SessionContext, slug: str, status: str | None = None, limit: int = 100) -> list[dict]:
        shop = self.shop_for(ctx, slug, "shop.orders.view")
        q = select(Order).where(Order.shop_id == shop.id)
        if status:
            if status.upper() not in STATUS_LABELS:
                raise AuthError("Hali ya oda si sahihi.", status=422, code="invalid", field="status")
            q = q.where(Order.status == status.upper())
        rows = self.db.execute(q.order_by(Order.created_at.desc(), Order.id.desc()).limit(limit)).scalars()
        return [self._summary(o, shop) for o in rows]

    def shop_order_counts(self, shop_id: int) -> dict[str, int]:
        return dict(self.db.execute(select(Order.status, func.count()).where(Order.shop_id == shop_id)
                                    .group_by(Order.status)).all())

    # ---------------------------------------------------------------- buyer actions (ORD-LC-001)
    def buyer_cancel(self, ctx: SessionContext, number: str, reason: str = "") -> Order:
        order = self.buyer_order(ctx, number, lock=True)
        reason = " ".join((reason or "").split())[:300]
        now = _now()
        if order.status == OrderStatus.PENDING_PAYMENT:
            _release_all(self.db, order, "buyer cancelled", now)
            _history(self.db, order, OrderStatus.CANCELLED, "buyer", ctx.user.id, reason or "Mnunuzi ameghairi")
            order.status, order.cancelled_at, order.cancel_reason = OrderStatus.CANCELLED, now, reason or None
            self._audit(ctx, order, "order.cancelled_by_buyer", {"reason": reason})
        elif order.status in SELLER_CANCELLABLE:
            # After confirmation the buyer can only ask; the seller/support decides (ORD-LC-001).
            if order.cancel_requested_at is not None:
                raise AuthError("Ombi la kughairi limeshatumwa.", status=409, code="already_requested")
            if len(reason) < 3:
                raise AuthError("Eleza sababu ya kughairi.", status=422, code="invalid", field="reason")
            order.cancel_requested_at, order.cancel_reason = now, reason
            self._audit(ctx, order, "order.cancel_requested", {"reason": reason})
        else:
            raise AuthError("Oda hii haiwezi kughairiwa sasa.", status=409, code="invalid_state")
        self.db.commit()
        return order

    def resend_pin(self, ctx: SessionContext, number: str) -> None:
        order = self.buyer_order(ctx, number, lock=True)
        if order.status != OrderStatus.SHIPPED:
            raise AuthError("PIN hutolewa oda ikiwa imesafirishwa tu.", status=409, code="invalid_state")
        pin = self._issue_pin(order)
        self._audit(ctx, order, "order.delivery_pin_reissued", {})
        self.db.commit()
        self._send_pin(order, pin)

    # ---------------------------------------------------------------- seller actions (ORD-LC-002, DEL-001)
    def advance(self, ctx: SessionContext, slug: str, number: str, to_status: str, *,
                courier_name: str = "", courier_phone: str = "") -> Order:
        _, order = self.shop_order(ctx, slug, number, "shop.orders.fulfil", lock=True)
        to_status = (to_status or "").upper()
        if SELLER_NEXT.get(order.status) != to_status:
            raise AuthError(f"Haiwezekani kuhamisha oda kutoka '{STATUS_LABELS.get(order.status)}' "
                            f"kwenda '{STATUS_LABELS.get(to_status, to_status)}'.", status=409,
                            code="invalid_transition")
        now = _now()
        details: dict = {"from": order.status, "to": to_status}
        pin = None
        if to_status == OrderStatus.SHIPPED:
            name, phone = self._courier(courier_name, courier_phone)
            order.courier_name, order.courier_phone, order.shipped_at = name, phone, now
            details["courier"] = {"name": name, "phone": phone}
            pin = self._issue_pin(order)
        _history(self.db, order, to_status, "seller", ctx.user.id)
        order.status = to_status
        self._audit(ctx, order, "order.status_changed", details)
        self.db.commit()
        if pin:
            self._send_pin(order, pin)
        return order

    def assign_courier(self, ctx: SessionContext, slug: str, number: str, courier_name: str,
                       courier_phone: str) -> Order:
        _, order = self.shop_order(ctx, slug, number, "shop.orders.fulfil", lock=True)
        if order.status != OrderStatus.SHIPPED:
            raise AuthError("Msafirishaji hubadilishwa oda ikiwa njiani tu.", status=409, code="invalid_state")
        name, phone = self._courier(courier_name, courier_phone)
        before = {"name": order.courier_name, "phone": order.courier_phone}
        order.courier_name, order.courier_phone = name, phone
        self._audit(ctx, order, "order.courier_reassigned", {"before": before, "after": {"name": name, "phone": phone}})
        self.db.commit()
        return order

    def seller_cancel(self, ctx: SessionContext, slug: str, number: str, reason: str) -> Order:
        _, order = self.shop_order(ctx, slug, number, "shop.orders.fulfil", lock=True)
        reason = " ".join((reason or "").split())[:300]
        if len(reason) < 3:
            raise AuthError("Eleza sababu ya kughairi.", status=422, code="invalid", field="reason")
        if order.status not in SELLER_CANCELLABLE:
            raise AuthError("Oda hii haiwezi kughairiwa na duka sasa.", status=409, code="invalid_state")
        now = _now()
        for item in self.db.execute(select(OrderItem).where(OrderItem.order_id == order.id)
                                    .order_by(OrderItem.product_id)).scalars():
            res = self.db.get(StockReservation, item.reservation_id) if item.reservation_id else None
            if res is not None and res.status == ReservationStatus.COMMITTED:
                stock_engine.restock(self.db, item.product_id, item.quantity)  # sold units go back (ORD-LC-006)
        _history(self.db, order, OrderStatus.CANCELLED, "seller", ctx.user.id, reason)
        order.status, order.cancelled_at, order.cancel_reason = OrderStatus.CANCELLED, now, reason
        order.refund_required = order.payment_status == "PAID"  # refund executed by Finance (M13)
        self._audit(ctx, order, "order.cancelled_by_seller",
                    {"reason": reason, "refund_required": order.refund_required})
        self.db.commit()
        self._notify_buyer(order, f"Bongo Markets: oda {order.number} imeghairiwa na duka. "
                                  "Marejesho ya fedha yatashughulikiwa.")
        return order

    # ---------------------------------------------------------------- delivery PIN (DEL-002, V13-TRUST-002)
    def _pin_hash(self, order: Order, pin: str) -> str:
        key = hashlib.sha256(b"bm-delivery-pin|" + self.settings.secret_key.get_secret_value().encode()).digest()
        return hmac.new(key, f"{order.public_id}|{pin}".encode(), hashlib.sha256).hexdigest()

    def _issue_pin(self, order: Order) -> str:
        """Store only the order-bound HMAC. The caller sends the SMS after the commit succeeds."""
        pin = f"{secrets.randbelow(1_000_000):06d}"
        order.delivery_pin_hash, order.pin_attempts = self._pin_hash(order, pin), 0
        return pin

    def _send_pin(self, order: Order, pin: str) -> None:
        self._notify_buyer(order, f"Bongo Markets: PIN ya kupokea oda {order.number} ni {pin}. "
                                  "Mpe msafirishaji UKIPOKEA mzigo tu. Usiitume kwa mtu mwingine.")

    def confirm_delivery(self, ctx: SessionContext, slug: str, number: str, pin: str) -> Order:
        _, order = self.shop_order(ctx, slug, number, "shop.orders.fulfil", lock=True)
        if order.status != OrderStatus.SHIPPED or order.delivery_pin_hash is None:
            raise AuthError("Oda hii haisubiri uthibitisho wa kufika.", status=409, code="invalid_state")
        if order.pin_attempts >= PIN_MAX_ATTEMPTS:
            raise AuthError("PIN imefungwa baada ya majaribio mengi. Mnunuzi aombe PIN mpya.", status=423,
                            code="pin_locked")
        candidate = "".join(ch for ch in (pin or "") if ch.isdigit())[:6]
        if len(candidate) != 6 or not hmac.compare_digest(self._pin_hash(order, candidate), order.delivery_pin_hash):
            order.pin_attempts += 1
            self._audit(ctx, order, "order.delivery_pin_failed", {"attempts": order.pin_attempts})
            self.db.commit()
            left = PIN_MAX_ATTEMPTS - order.pin_attempts
            raise AuthError(f"PIN si sahihi. Majaribio yaliyobaki: {left}." if left else
                            "PIN imefungwa baada ya majaribio mengi. Mnunuzi aombe PIN mpya.",
                            status=422 if left else 423, code="invalid_pin" if left else "pin_locked", field="pin")
        now = _now()
        _history(self.db, order, OrderStatus.DELIVERED, "seller", ctx.user.id, "Imethibitishwa kwa PIN ya mnunuzi")
        order.status, order.delivered_at, order.delivery_pin_hash = OrderStatus.DELIVERED, now, None  # single use
        self._audit(ctx, order, "order.delivered", {"method": "pin"})
        self.db.commit()
        return order

    # ---------------------------------------------------------------- reviews gate (BR-017)
    def can_review(self, user_id: int, order_item_public_id: str) -> bool:
        try:
            iid = uuid.UUID(str(order_item_public_id))
        except ValueError:
            return False
        row = self.db.execute(select(Order.buyer_user_id, Order.status).join(OrderItem, OrderItem.order_id == Order.id)
                              .where(OrderItem.public_id == iid)).first()
        return row is not None and row[0] == user_id and row[1] == OrderStatus.DELIVERED

    # ---------------------------------------------------------------- helpers
    def _courier(self, name: str, phone: str) -> tuple[str, str]:
        name = " ".join((name or "").split())
        if not 2 <= len(name) <= 120:
            raise AuthError("Andika jina la msafirishaji.", status=422, code="invalid", field="courier_name")
        try:
            return name, normalize_phone(phone, self.settings.default_phone_region)
        except IdentifierError as exc:
            raise AuthError(str(exc), status=422, code="invalid", field="courier_phone") from None

    def _notify_buyer(self, order: Order, body: str) -> None:
        buyer = self.db.get(User, order.buyer_user_id)
        if buyer is not None:
            self.notifier.send("sms", buyer.phone_e164, body)

    def _audit(self, ctx: SessionContext, order: Order, action: str, details: dict) -> None:
        audit.record(self.db, action=action, category=AuditCategory.FINANCIAL, actor_user_id=ctx.user.id,
                     actor_type="user", entity_type="order", entity_id=order.id, shop_id=order.shop_id,
                     details={"number": order.number, **details})
