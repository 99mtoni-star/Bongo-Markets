"""Products, prices, stock and images (M08)."""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.auth.security import StepUpAction
from app.auth.service import AuthError, SessionContext
from app.catalog import stock as stock_engine
from app.catalog.media import ImageRejected, Storage, clean_image, new_storage_key
from app.catalog.models import Category, Product, ProductImage, ProductStatus
from app.db.models import AuditCategory, SystemFlag
from app.services import audit
from app.shops.models import Shop, ShopStatus
from app.shops.service import ShopService

MAX_IMAGES = 8
MAX_PRICE = Decimal("100000000")  # TZS 100m per unit ceiling
UNITS = ("kipande", "kilo", "trei", "lita", "fungu", "boksi", "jozi", "mfuko")
NOT_FOUND = "Bidhaa haipatikani."


def _now() -> datetime:
    return datetime.now(UTC)


def parse_price(raw) -> Decimal:
    try:
        value = Decimal(str(raw).replace(",", "").strip() or "0")
    except InvalidOperation:
        raise AuthError("Bei si sahihi.", status=422, code="invalid", field="price") from None
    if value < 0 or value > MAX_PRICE or value != value.quantize(Decimal("0.01")):
        raise AuthError("Bei lazima iwe 0 au zaidi, isizidi senti mbili za desimali.", status=422, code="invalid",
                        field="price")
    return value.quantize(Decimal("0.01"))


def parse_stock(raw) -> int:
    try:
        value = int(str(raw).strip() or "0")
    except ValueError:
        raise AuthError("Idadi ya stock si sahihi.", status=422, code="invalid", field="stock") from None
    if value < 0 or value > 10_000_000:
        raise AuthError("Stock haiwezi kuwa hasi.", status=422, code="invalid", field="stock")
    return value


class CatalogService(ShopService):
    storage: Storage | None = None

    # ---------------------------------------------------------------- categories
    def categories(self) -> list[Category]:
        q = select(Category).where(Category.active.is_(True)).order_by(Category.sort)
        return list(self.db.execute(q).scalars())

    def _category(self, slug: str) -> Category:
        cat = self.db.execute(select(Category).where(Category.slug == (slug or "")[:48],
                                                     Category.active.is_(True))).scalar_one_or_none()
        if cat is None:
            raise AuthError("Chagua kundi la bidhaa.", status=422, code="invalid", field="category")
        return cat

    # ---------------------------------------------------------------- product lookup (no IDOR)
    def product_in_shop(self, shop: Shop, product_public_id: str, *, lock: bool = False) -> Product:
        try:
            pid = uuid.UUID(str(product_public_id))
        except ValueError:
            raise AuthError(NOT_FOUND, status=404, code="not_found") from None
        q = select(Product).where(Product.public_id == pid, Product.shop_id == shop.id)
        product = self.db.execute(q.with_for_update() if lock else q).scalar_one_or_none()
        if product is None:
            raise AuthError(NOT_FOUND, status=404, code="not_found")
        return product

    # ---------------------------------------------------------------- create / update (PRD-001..004)
    def create_product(self, ctx: SessionContext, slug: str, *, name: str, category: str, price="0", stock="0",
                       unit: str = "kipande", sku: str | None = None, description: str | None = None,
                       marketplace: bool = True) -> Product:
        shop = self.shop_for(ctx, slug, "shop.products.manage", lock=True)
        name = " ".join((name or "").split())
        if not 2 <= len(name) <= 120:
            raise AuthError("Jina la bidhaa liwe na herufi 2 hadi 120.", status=422, code="invalid", field="name")
        price_v, stock_v = parse_price(price), parse_stock(stock)
        if price_v > 0 and not self.authz.can(ctx.user.id, "shop.products.price", shop_id=shop.id):
            raise AuthError("Huna ruhusa ya kuweka bei. Meneja au mmiliki ataweka bei.", status=403,
                            code="forbidden", field="price")
        sku = (sku or "").strip().upper()[:64] or f"BM-{secrets.token_hex(3).upper()}"
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{0,63}", sku):
            raise AuthError("SKU itumie herufi, namba, '.', '_' au '-'.", status=422, code="invalid", field="sku")
        product = Product(shop_id=shop.id, category_id=self._category(category).id, sku=sku, name=name,
                          description=(description or "").strip()[:2000] or None,
                          unit=unit if unit in UNITS else "kipande", price=price_v, stock=stock_v, reserved=0,
                          status=ProductStatus.DRAFT, marketplace=bool(marketplace), featured=False)
        try:
            with self.db.begin_nested():
                self.db.add(product)
                self.db.flush()
        except IntegrityError:
            raise AuthError("SKU hii tayari ipo katika duka hili.", status=409, code="sku_exists",
                            field="sku") from None
        audit.record(self.db, action="product.created", actor_user_id=ctx.user.id, actor_type="user",
                     entity_type="product", entity_id=product.id, shop_id=shop.id,
                     details={"sku": sku, "price": str(price_v), "stock": stock_v})
        self.db.commit()
        return product

    def update_product(self, ctx: SessionContext, slug: str, product_id: str, **fields) -> Product:
        shop = self.shop_for(ctx, slug, "shop.products.manage", lock=True)
        product = self.product_in_shop(shop, product_id, lock=True)
        changes: dict[str, str] = {}
        if "name" in fields and fields["name"] is not None:
            name = " ".join(fields["name"].split())
            if not 2 <= len(name) <= 120:
                raise AuthError("Jina la bidhaa liwe na herufi 2 hadi 120.", status=422, code="invalid", field="name")
            product.name = name
        if fields.get("description") is not None:
            product.description = fields["description"].strip()[:2000] or None
        if fields.get("category"):
            product.category_id = self._category(fields["category"]).id
        if fields.get("unit") in UNITS:
            product.unit = fields["unit"]
        if fields.get("marketplace") is not None:
            product.marketplace = bool(fields["marketplace"])
        if fields.get("price") is not None:
            new_price = parse_price(fields["price"])
            if new_price != product.price:
                if not self.authz.can(ctx.user.id, "shop.products.price", shop_id=shop.id):
                    raise AuthError("Huna ruhusa ya kubadilisha bei.", status=403, code="forbidden", field="price")
                changes["price"] = f"{product.price}->{new_price}"
                product.price = new_price
        if fields.get("stock") is not None:
            new_stock = parse_stock(fields["stock"])
            if new_stock < product.reserved:
                raise AuthError(f"Stock haiwezi kuwa chini ya zilizoshikiliwa kwa oda ({product.reserved}).",
                                status=409, code="below_reserved", field="stock")
            if new_stock != product.stock:
                changes["stock"] = f"{product.stock}->{new_stock}"
                product.stock = new_stock
        if fields.get("status"):
            target = fields["status"].upper()
            if target not in (ProductStatus.DRAFT, ProductStatus.ACTIVE, ProductStatus.SUSPENDED,
                              ProductStatus.ARCHIVED):
                raise AuthError("Hali si sahihi.", status=422, code="invalid", field="status")
            if target == ProductStatus.ACTIVE and product.price <= 0:
                raise AuthError("Weka bei kabla ya kuchapisha bidhaa.", status=409, code="needs_price", field="status")
            if target != product.status:
                changes["status"] = f"{product.status}->{target}"
                product.status = target
        audit.record(self.db, action="product.updated", actor_user_id=ctx.user.id, actor_type="user",
                     entity_type="product", entity_id=product.id, shop_id=shop.id, details=changes)
        self.db.commit()
        return product

    # ---------------------------------------------------------------- images (PRD-005, V13-SEC-004)
    def add_image(self, ctx: SessionContext, slug: str, product_id: str, raw: bytes) -> ProductImage:
        shop = self.shop_for(ctx, slug, "shop.products.manage")
        product = self.product_in_shop(shop, product_id, lock=True)
        count = self.db.execute(select(func.count()).select_from(ProductImage).where(
            ProductImage.product_id == product.id, ProductImage.removed_at.is_(None))).scalar_one()
        if count >= MAX_IMAGES:
            raise AuthError(f"Bidhaa inaweza kuwa na picha {MAX_IMAGES} tu.", status=409, code="limit")
        try:
            img = clean_image(raw)
        except ImageRejected as exc:
            audit.record(self.db, action="product.image_rejected", category=AuditCategory.SECURITY,
                         actor_user_id=ctx.user.id, actor_type="user", entity_type="product", entity_id=product.id,
                         shop_id=shop.id, details={"reason": str(exc)[:120], "bytes": len(raw)})
            self.db.commit()
            raise AuthError(str(exc), status=422, code="image_rejected", field="image") from None
        key = new_storage_key()
        self.storage.put(key, img.data, img.content_type)
        row = ProductImage(product_id=product.id, storage_key=key, content_type=img.content_type,
                           bytes=len(img.data), width=img.width, height=img.height, sha256=img.sha256,
                           position=count, uploaded_by=ctx.user.id)
        self.db.add(row)
        audit.record(self.db, action="product.image_added", actor_user_id=ctx.user.id, actor_type="user",
                     entity_type="product", entity_id=product.id, shop_id=shop.id, details={"sha256": img.sha256})
        self.db.commit()
        return row

    def remove_image(self, ctx: SessionContext, slug: str, product_id: str, image_id: str) -> None:
        shop = self.shop_for(ctx, slug, "shop.products.manage")
        product = self.product_in_shop(shop, product_id)
        try:
            iid = uuid.UUID(str(image_id))
        except ValueError:
            raise AuthError("Picha haipatikani.", status=404, code="not_found") from None
        img = self.db.execute(select(ProductImage).where(ProductImage.public_id == iid,
                                                         ProductImage.product_id == product.id,
                                                         ProductImage.removed_at.is_(None))).scalar_one_or_none()
        if img is None:
            raise AuthError("Picha haipatikani.", status=404, code="not_found")
        img.removed_at = _now()
        audit.record(self.db, action="product.image_removed", actor_user_id=ctx.user.id, actor_type="user",
                     entity_type="product", entity_id=product.id, shop_id=shop.id)
        self.db.commit()

    def images(self, product: Product) -> list[ProductImage]:
        return list(self.db.execute(select(ProductImage).where(ProductImage.product_id == product.id,
                                                               ProductImage.removed_at.is_(None))
                                    .order_by(ProductImage.position, ProductImage.id)).scalars())

    # ---------------------------------------------------------------- listing
    def shop_products(self, shop: Shop, *, public: bool) -> list[Product]:
        q = select(Product).where(Product.shop_id == shop.id)
        if public:
            q = q.where(Product.status == ProductStatus.ACTIVE)
        else:
            q = q.where(Product.status != ProductStatus.ARCHIVED)
        return list(self.db.execute(q.order_by(Product.created_at.desc())).scalars())

    @staticmethod
    def is_publicly_visible(product: Product, shop: Shop) -> bool:
        """BR-011: Active product, flagged for the marketplace, in an Active shop."""
        return product.status == ProductStatus.ACTIVE and product.marketplace and shop.status == ShopStatus.ACTIVE

    def product_dict(self, p: Product, *, include_admin: bool = False) -> dict:
        cat = self.db.get(Category, p.category_id)
        imgs = self.images(p)
        out = {"id": str(p.public_id), "name": p.name, "description": p.description, "unit": p.unit,
               "price": str(p.price), "currency": "TZS", "category": cat.slug, "category_name": cat.name,
               "available": max(p.stock - p.reserved, 0) > 0,
               "images": [f"/media/{i.storage_key}" for i in imgs]}
        if include_admin:
            out |= {"sku": p.sku, "stock": p.stock, "reserved": p.reserved, "status": p.status,
                    "marketplace": p.marketplace, "image_ids": [str(i.public_id) for i in imgs]}
        return out

    # ---------------------------------------------------------------- platform setting (STK-002)
    def set_reservation_minutes(self, ctx: SessionContext, minutes: int, step_up_token: str | None) -> int:
        self.require_permission(ctx, "platform.settings.manage")
        self.consume_step_up(ctx, StepUpAction.SETTINGS_CHANGE, step_up_token)
        if not stock_engine.MIN_MINUTES <= minutes <= stock_engine.MAX_MINUTES:
            raise AuthError(f"Muda uwe kati ya dakika {stock_engine.MIN_MINUTES} na {stock_engine.MAX_MINUTES}.",
                            status=422, code="invalid", field="minutes")
        flag = self.db.get(SystemFlag, stock_engine.SETTING_KEY)
        if flag is None:
            flag = SystemFlag(key=stock_engine.SETTING_KEY, value="15", updated_by="system")
            self.db.add(flag)
        old = flag.value
        flag.value, flag.updated_by, flag.reason = str(minutes), str(ctx.user.public_id), "admin change"
        audit.record(self.db, action="settings.stock_reservation_minutes", category=AuditCategory.SECURITY,
                     actor_user_id=ctx.user.id, actor_type="user", details={"from": old, "to": minutes})
        self.db.commit()
        return minutes
