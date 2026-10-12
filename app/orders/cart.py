"""Cart and checkout (M11).

- One ACTIVE cart per user, enforced by a partial unique index (BR-018, CART-001).
- One row per (cart, product) (CART-002). Carts store quantities only, never prices.
- Checkout re-reads price, visibility and stock from the database, reserves stock and creates one
  order per shop inside a single transaction (CART-003, CART-001 v1.12, ORD-006, ORD-LC-005/008).
- A client-supplied expected total is only a confirmation: on mismatch the checkout stops (409) and
  the new server total is returned; the frontend is never the source of truth (BR-013, BR-014).
- Checkout is idempotent per (user, Idempotency-Key) (ORD-001 v1.12).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError

from app.auth.identifiers import IdentifierError, normalize_phone
from app.auth.service import AuthError, SessionContext
from app.catalog import stock as stock_engine
from app.catalog.models import Product, ProductImage, ProductStatus
from app.db.models import AuditCategory
from app.orders.models import Cart, CartItem, Checkout, Order, OrderItem, OrderStatus, OrderStatusHistory
from app.services import audit
from app.shops.models import Shop, ShopStatus
from app.shops.service import ShopService

MAX_QTY = 999
PAYMENT_METHODS = ("ONLINE", "COD")


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(ts: datetime | None) -> str | None:
    return ts.astimezone(UTC).isoformat(timespec="seconds") if ts else None


@dataclass
class Address:
    name: str
    phone: str
    region: str
    area: str = ""
    street: str = ""
    notes: str = ""


class CartService(ShopService):
    # ---------------------------------------------------------------- cart (BR-018, CART-001/002)
    def active_cart(self, user_id: int, *, create: bool = True, lock: bool = False) -> Cart | None:
        q = select(Cart).where(Cart.user_id == user_id, Cart.status == "ACTIVE")
        cart = self.db.execute(q.with_for_update() if lock else q).scalar_one_or_none()
        if cart is None and create:
            try:
                with self.db.begin_nested():
                    cart = Cart(user_id=user_id, status="ACTIVE")
                    self.db.add(cart)
                    self.db.flush()
            except IntegrityError:  # a concurrent request created it first: wait for it and use it
                cart = self.db.execute(q.with_for_update() if lock else q).scalar_one()
        return cart

    def _visible_product(self, public_id: str, *, lock: bool = False) -> tuple[Product, Shop]:
        try:
            pid = uuid.UUID(str(public_id))
        except ValueError:
            raise AuthError("Bidhaa haipatikani.", status=404, code="not_found") from None
        q = select(Product, Shop).join(Shop, Shop.id == Product.shop_id).where(Product.public_id == pid)
        row = self.db.execute(q.with_for_update(of=Product) if lock else q).first()
        if row is None or not self._is_visible(*row):
            raise AuthError("Bidhaa haipatikani.", status=404, code="not_found")
        return row[0], row[1]

    @staticmethod
    def _is_visible(p: Product, s: Shop) -> bool:
        return p.status == ProductStatus.ACTIVE and p.marketplace and s.status == ShopStatus.ACTIVE

    def add_item(self, ctx: SessionContext, product_id: str, quantity: int = 1) -> None:
        if not 1 <= int(quantity) <= MAX_QTY:
            raise AuthError("Idadi si sahihi.", status=422, code="invalid", field="quantity")
        product, _ = self._visible_product(product_id)
        cart = self.active_cart(ctx.user.id, lock=True)
        item = self.db.execute(select(CartItem).where(CartItem.cart_id == cart.id,
                                                      CartItem.product_id == product.id)).scalar_one_or_none()
        new_qty = (item.quantity if item else 0) + int(quantity)
        available = product.stock - product.reserved
        if new_qty > min(available, MAX_QTY):
            raise AuthError(f"Zimebaki {max(available, 0)} tu za bidhaa hii.", status=409, code="insufficient_stock")
        if item:
            item.quantity = new_qty
        else:
            self.db.add(CartItem(cart_id=cart.id, product_id=product.id, quantity=new_qty))
        self.db.commit()

    def set_quantity(self, ctx: SessionContext, product_id: str, quantity: int) -> None:
        cart = self.active_cart(ctx.user.id, lock=True)
        try:
            pid = uuid.UUID(str(product_id))
        except ValueError:
            raise AuthError("Bidhaa haipatikani.", status=404, code="not_found") from None
        product = self.db.execute(select(Product).where(Product.public_id == pid)).scalar_one_or_none()
        item = self.db.execute(select(CartItem).where(CartItem.cart_id == cart.id, CartItem.product_id == product.id)
                               ).scalar_one_or_none() if product else None
        if item is None:
            raise AuthError("Bidhaa haipo kwenye kikapu.", status=404, code="not_found")
        if int(quantity) <= 0:
            self.db.execute(delete(CartItem).where(CartItem.id == item.id))
        else:
            if int(quantity) > min(product.stock - product.reserved, MAX_QTY):
                raise AuthError(f"Zimebaki {max(product.stock - product.reserved, 0)} tu.", status=409,
                                code="insufficient_stock")
            item.quantity = int(quantity)
        self.db.commit()

    def view(self, ctx: SessionContext) -> dict:
        """Current cart with prices read from the database right now."""
        cart = self.active_cart(ctx.user.id, create=False)
        groups: OrderedDict[int, dict] = OrderedDict()
        total = Decimal("0")
        if cart is not None:
            rows = self.db.execute(select(CartItem, Product, Shop).join(Product, Product.id == CartItem.product_id)
                                   .join(Shop, Shop.id == Product.shop_id).where(CartItem.cart_id == cart.id)
                                   .order_by(Shop.name, CartItem.added_at)).all()
            images = self._first_images([p.id for _, p, _ in rows])
            for item, p, s in rows:
                ok = self._is_visible(p, s)
                avail = max(p.stock - p.reserved, 0)
                line = p.price * item.quantity
                g = groups.setdefault(s.id, {"shop": {"slug": s.slug, "name": s.name}, "items": [],
                                             "subtotal": Decimal("0")})
                problem = None if ok else "Haipatikani tena"
                if ok and item.quantity > avail:
                    problem = f"Zimebaki {avail} tu"
                g["items"].append({"product_id": str(p.public_id), "name": p.name, "unit": p.unit,
                                   "unit_price": str(p.price), "quantity": item.quantity, "line_total": str(line),
                                   "image": images.get(p.id), "problem": problem})
                if ok:
                    g["subtotal"] += line
                    total += line
        out_groups = [{**g, "subtotal": str(g["subtotal"])} for g in groups.values()]
        return {"groups": out_groups, "total": str(total), "currency": "TZS",
                "count": sum(len(g["items"]) for g in out_groups)}

    def count(self, user_id: int) -> int:
        cart = self.active_cart(user_id, create=False)
        if cart is None:
            return 0
        q = text("SELECT count(*) FROM bm.cart_items WHERE cart_id = :c")
        return self.db.execute(q, {"c": cart.id}).scalar_one()

    def _first_images(self, product_ids: list[int]) -> dict[int, str]:
        out: dict[int, str] = {}
        if product_ids:
            for pid, key in self.db.execute(select(ProductImage.product_id, ProductImage.storage_key)
                                            .where(ProductImage.product_id.in_(product_ids),
                                                   ProductImage.removed_at.is_(None))
                                            .order_by(ProductImage.product_id, ProductImage.position, ProductImage.id)):
                out.setdefault(pid, f"/media/{key}")
        return out

    # ---------------------------------------------------------------- checkout (CART-003, ORD-001, ORD-006)
    def _validate_address(self, a: Address) -> Address:
        name = " ".join((a.name or "").split())
        if not 2 <= len(name) <= 120:
            raise AuthError("Andika jina la mpokeaji.", status=422, code="invalid", field="name")
        try:
            phone = normalize_phone(a.phone, self.settings.default_phone_region)
        except IdentifierError as exc:
            raise AuthError(str(exc), status=422, code="invalid", field="phone") from None
        region = " ".join((a.region or "").split())
        if not 2 <= len(region) <= 60:
            raise AuthError("Andika mkoa wa kupelekea.", status=422, code="invalid", field="region")
        return Address(name=name, phone=phone, region=region, area=(a.area or "").strip()[:80],
                       street=(a.street or "").strip()[:160], notes=(a.notes or "").strip()[:300])

    def checkout(self, ctx: SessionContext, address: Address, payment_method: str, idempotency_key: str,
                 expected_total: str | None = None) -> dict:
        key = (idempotency_key or "").strip()
        if not 8 <= len(key) <= 80:
            raise AuthError("Ombi halina Idempotency-Key halali.", status=422, code="invalid", field="idempotency_key")
        method = (payment_method or "").upper()
        if method not in PAYMENT_METHODS:
            raise AuthError("Chagua njia ya malipo.", status=422, code="invalid", field="payment_method")
        if method == "COD":
            raise AuthError("Kulipa mzigo ukifika (COD) kutawezeshwa hivi karibuni (Module 14).", status=422,
                            code="cod_unavailable", field="payment_method")
        addr = self._validate_address(address)
        req_hash = hashlib.sha256(json.dumps([addr.__dict__, method], sort_keys=True).encode()).hexdigest()

        existing = self.db.execute(select(Checkout).where(Checkout.user_id == ctx.user.id,
                                                          Checkout.idempotency_key == key)).scalar_one_or_none()
        if existing is not None:  # retry of the same request: same answer, nothing new created
            if existing.request_hash != req_hash:
                raise AuthError("Idempotency-Key hii ilitumika kwa ombi tofauti.", status=409,
                                code="idempotency_conflict")
            return self._checkout_result(existing, replay=True)

        cart = self.active_cart(ctx.user.id, create=False, lock=True)
        rows = []
        if cart is not None:
            rows = self.db.execute(select(CartItem).where(CartItem.cart_id == cart.id)
                                   .order_by(CartItem.product_id)).scalars().all()  # stable lock order
        if not rows:
            raise AuthError("Kikapu chako ni tupu.", status=409, code="empty_cart")

        lines = []
        total = Decimal("0")
        for item in rows:
            product = self.db.execute(select(Product).where(Product.id == item.product_id).with_for_update()) \
                .scalar_one()
            shop = self.db.get(Shop, product.shop_id)
            if not self._is_visible(product, shop):
                self.db.rollback()
                raise AuthError(f"'{product.name}' haipatikani tena. Iondoe kwenye kikapu.", status=409,
                                code="product_unavailable")
            lines.append((item, product, shop))
            total += product.price * item.quantity  # server-side price (BR-014, CART-003)

        if expected_total is not None and str(expected_total).strip():
            try:
                expected = Decimal(str(expected_total))
            except Exception:
                expected = None
            if expected != total:
                self.db.rollback()
                raise AuthError(f"Bei zimebadilika. Jumla mpya ni TZS {total:,.2f}. Thibitisha tena.", status=409,
                                code="price_changed")

        checkout = Checkout(user_id=ctx.user.id, idempotency_key=key, request_hash=req_hash, total=total)
        try:
            with self.db.begin_nested():
                self.db.add(checkout)
                self.db.flush()
        except IntegrityError:  # concurrent duplicate submit with the same key
            self.db.rollback()
            existing = self.db.execute(select(Checkout).where(Checkout.user_id == ctx.user.id,
                                                              Checkout.idempotency_key == key)).scalar_one()
            return self._checkout_result(existing, replay=True)

        by_shop: OrderedDict[int, list] = OrderedDict()
        for line in lines:
            by_shop.setdefault(line[2].id, []).append(line)
        images = self._first_images([p.id for _, p, _ in lines])
        try:
            for shop_id, shop_lines in by_shop.items():
                seq = self.db.execute(text("SELECT nextval('bm.order_number_seq')")).scalar_one()
                subtotal = sum((p.price * it.quantity for it, p, _ in shop_lines), Decimal("0"))
                order = Order(number=f"BM{_now():%y%m}-{seq:06d}", checkout_id=checkout.id,
                              buyer_user_id=ctx.user.id, shop_id=shop_id, status=OrderStatus.PENDING_PAYMENT,
                              payment_status="UNPAID", payment_method=method, currency="TZS", subtotal=subtotal,
                              total=subtotal, items_count=sum(it.quantity for it, _, _ in shop_lines),
                              delivery_name=addr.name, delivery_phone=addr.phone, delivery_region=addr.region,
                              delivery_area=addr.area or None, delivery_street=addr.street or None,
                              delivery_notes=addr.notes or None, pin_attempts=0, refund_required=False)
                self.db.add(order)
                self.db.flush()
                expires = None
                for it, p, _ in shop_lines:
                    res = stock_engine.reserve(self.db, p.id, it.quantity, f"order:{order.public_id}", ctx.user.id)
                    expires = res.expires_at if expires is None else min(expires, res.expires_at)
                    key_img = (images.get(p.id) or "").removeprefix("/media/") or None
                    self.db.add(OrderItem(order_id=order.id, product_id=p.id, reservation_id=res.id, sku=p.sku,
                                          name=p.name, image_key=key_img, unit=p.unit, unit_price=p.price,
                                          quantity=it.quantity, line_total=p.price * it.quantity))
                order.expires_at = expires
                self.db.add(OrderStatusHistory(order_id=order.id, from_status=None,
                                               to_status=OrderStatus.PENDING_PAYMENT, actor_type="buyer",
                                               actor_user_id=ctx.user.id, note="checkout"))
                audit.record(self.db, action="order.created", category=AuditCategory.FINANCIAL,
                             actor_user_id=ctx.user.id, actor_type="user", entity_type="order", entity_id=order.id,
                             shop_id=shop_id, details={"number": order.number, "total": str(subtotal)})
        except stock_engine.StockError as exc:
            self.db.rollback()  # nothing from this checkout survives (ORD-006)
            raise AuthError(exc.message, status=409, code=exc.code) from None
        cart.status = "CHECKED_OUT"
        self.db.commit()
        return self._checkout_result(checkout, replay=False)

    def _checkout_result(self, checkout: Checkout, *, replay: bool) -> dict:
        orders = self.db.execute(select(Order).where(Order.checkout_id == checkout.id).order_by(Order.id)).scalars()
        return {"checkout_id": str(checkout.public_id), "replayed": replay, "total": str(checkout.total),
                "orders": [{"number": o.number, "id": str(o.public_id), "status": o.status, "total": str(o.total),
                            "expires_at": _iso(o.expires_at)} for o in orders]}
