"""Bongo Markets Sokoni: marketplace listing, search, filters and batches (M09).

- Shows Active, marketplace-flagged products of Active shops only, across all shops (MKT-001, BR-011).
- Search (product name, description, shop name) and filters: category, price range, region/location
  of the shop, shop (MKT-002, MKT-001 v1.12).
- Keyset pagination in batches of 24 until the catalogue is exhausted; stable under inserts (MKT-003).
- ``featured`` only adds a product to the highlighted section; it is never a condition for being
  listed (MKT-006).
- Behind a small interface so a dedicated search index can replace SQL later (V13-REQ-004).
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation

from sqlalchemy import and_, or_, select, tuple_
from sqlalchemy.orm import Session

from app.catalog.models import Category, Product, ProductImage, ProductStatus
from app.shops.models import Shop, ShopStatus

BATCH = 24
MAX_BATCH = 48
SORTS = ("newest", "price_asc", "price_desc")


@dataclass
class Filters:
    q: str = ""
    category: str = ""
    min_price: str = ""
    max_price: str = ""
    region: str = ""
    shop: str = ""
    sort: str = "newest"
    cursor: str = ""
    limit: int = BATCH


def _like(term: str) -> str:
    term = term.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{term}%"


def _dec(raw: str) -> Decimal | None:
    try:
        v = Decimal(raw.replace(",", "").strip()) if raw and raw.strip() else None
    except InvalidOperation:
        return None
    return v if v is not None and v >= 0 else None


def encode_cursor(sort: str, p: Product) -> str:
    key = [p.created_at.isoformat(), p.id] if sort == "newest" else [str(p.price), p.id]
    return base64.urlsafe_b64encode(json.dumps(key).encode()).decode().rstrip("=")


def decode_cursor(sort: str, raw: str):
    if not raw:
        return None
    try:
        a, b = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        return (datetime.fromisoformat(a) if sort == "newest" else Decimal(a)), int(b)
    except Exception:
        return None  # a malformed cursor simply restarts from the beginning


def _base():
    return (select(Product, Shop, Category)
            .join(Shop, Shop.id == Product.shop_id)
            .join(Category, Category.id == Product.category_id)
            .where(Product.status == ProductStatus.ACTIVE, Product.marketplace.is_(True),
                   Shop.status == ShopStatus.ACTIVE))


def search(db: Session, f: Filters) -> tuple[list[dict], str | None]:
    sort = f.sort if f.sort in SORTS else "newest"
    limit = max(1, min(int(f.limit or BATCH), MAX_BATCH))
    q = _base()
    term = " ".join((f.q or "").split())[:80]
    if term:
        pat = _like(term)
        q = q.where(or_(Product.name.ilike(pat, escape="\\"), Product.description.ilike(pat, escape="\\"),
                        Shop.name.ilike(pat, escape="\\")))
    if f.category:
        q = q.where(Category.slug == f.category[:48])
    if (lo := _dec(f.min_price)) is not None:
        q = q.where(Product.price >= lo)
    if (hi := _dec(f.max_price)) is not None:
        q = q.where(Product.price <= hi)
    if f.region:
        q = q.where(Shop.region.ilike(_like(f.region[:60]), escape="\\"))
    if f.shop:
        q = q.where(Shop.slug == f.shop[:40])
    cur = decode_cursor(sort, f.cursor)
    if sort == "newest":
        if cur:
            q = q.where(tuple_(Product.created_at, Product.id) < tuple_(*cur))
        q = q.order_by(Product.created_at.desc(), Product.id.desc())
    elif sort == "price_asc":
        if cur:
            q = q.where(tuple_(Product.price, Product.id) > tuple_(*cur))
        q = q.order_by(Product.price.asc(), Product.id.asc())
    else:
        if cur:
            q = q.where(or_(Product.price < cur[0], and_(Product.price == cur[0], Product.id < cur[1])))
        q = q.order_by(Product.price.desc(), Product.id.desc())
    rows = db.execute(q.limit(limit + 1)).all()
    more = len(rows) > limit
    rows = rows[:limit]
    items = serialize(db, rows)
    return items, (encode_cursor(sort, rows[-1][0]) if more and rows else None)


def featured(db: Session, limit: int = 8) -> list[dict]:
    rows = db.execute(_base().where(Product.featured.is_(True))
                      .order_by(Product.updated_at.desc(), Product.id.desc()).limit(limit)).all()
    return serialize(db, rows)


def serialize(db: Session, rows) -> list[dict]:
    ids = [p.id for p, _, _ in rows]
    first_image: dict[int, str] = {}
    if ids:
        for pid, key in db.execute(select(ProductImage.product_id, ProductImage.storage_key)
                                   .where(ProductImage.product_id.in_(ids), ProductImage.removed_at.is_(None))
                                   .order_by(ProductImage.product_id, ProductImage.position, ProductImage.id)):
            first_image.setdefault(pid, f"/media/{key}")
    return [{"id": str(p.public_id), "name": p.name, "price": str(p.price), "currency": "TZS", "unit": p.unit,
             "available": p.stock - p.reserved > 0, "featured": p.featured,
             "images": [first_image[p.id]] if p.id in first_image else [],
             "category": c.slug, "category_name": c.name,
             "shop": {"slug": s.slug, "name": s.name, "region": s.region}} for p, s, c in rows]


def product_detail(db: Session, public_id: str) -> dict | None:
    import uuid

    try:
        pid = uuid.UUID(str(public_id))
    except ValueError:
        return None
    row = db.execute(_base().where(Product.public_id == pid)).first()
    if row is None:
        return None
    p, s, c = row
    images = [f"/media/{k}" for (k,) in db.execute(
        select(ProductImage.storage_key).where(ProductImage.product_id == p.id, ProductImage.removed_at.is_(None))
        .order_by(ProductImage.position, ProductImage.id))]
    return {"id": str(p.public_id), "name": p.name, "description": p.description, "price": str(p.price),
            "currency": "TZS", "unit": p.unit, "available_quantity": max(p.stock - p.reserved, 0),
            "images": images, "category": c.slug, "category_name": c.name,
            "shop": {"slug": s.slug, "name": s.name, "region": s.region}}
