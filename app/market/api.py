"""Marketplace API (M09)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.api import StrictModel, error_response
from app.auth.deps import require_session
from app.auth.service import AuthError, SessionContext
from app.authz.api import privileged_mutation
from app.catalog.api import get_catalog_service
from app.catalog.models import Product
from app.catalog.service import CatalogService
from app.db.models import AuditCategory
from app.db.session import get_db
from app.market import service as market
from app.services import audit

router = APIRouter(tags=["marketplace"])


@router.get("/marketplace/products")
def products(q: str = "", category: str = "", min_price: str = "", max_price: str = "", region: str = "",
             shop: str = "", sort: str = "newest", cursor: str = "", limit: int = market.BATCH,
             db: Session = Depends(get_db)):
    items, nxt = market.search(db, market.Filters(q=q[:80], category=category[:48], min_price=min_price[:20],
                                                  max_price=max_price[:20], region=region[:60], shop=shop[:40],
                                                  sort=sort[:16], cursor=cursor[:200], limit=limit))
    return {"products": items, "next_cursor": nxt}


@router.get("/marketplace/featured")
def featured(db: Session = Depends(get_db)):
    return {"products": market.featured(db)}


@router.get("/marketplace/products/{product_id}")
def detail(product_id: str, db: Session = Depends(get_db)):
    d = market.product_detail(db, product_id[:40])
    if d is None:
        return JSONResponse({"error": {"code": "not_found", "message": "Bidhaa haipatikani."}}, status_code=404)
    return d


class FeaturedIn(StrictModel):
    featured: bool
    reason: str = Field(..., min_length=3, max_length=300)


@router.patch("/admin/products/{product_id}/featured", dependencies=[Depends(privileged_mutation)])
def set_featured(product_id: str, body: FeaturedIn, ctx: SessionContext = Depends(require_session),
                 svc: CatalogService = Depends(get_catalog_service)):
    """Featured placement is a platform (moderation) decision, not something a seller can self-assign."""
    try:
        svc.require_permission(ctx, "platform.content.moderate")
        try:
            pid = uuid.UUID(product_id[:40])
        except ValueError:
            raise AuthError("Bidhaa haipatikani.", status=404, code="not_found") from None
        p = svc.db.execute(select(Product).where(Product.public_id == pid).with_for_update()).scalar_one_or_none()
        if p is None:
            raise AuthError("Bidhaa haipatikani.", status=404, code="not_found")
        p.featured = body.featured
        audit.record(svc.db, action="product.featured_changed", category=AuditCategory.GENERAL,
                     actor_user_id=ctx.user.id, actor_type="user", entity_type="product", entity_id=p.id,
                     shop_id=p.shop_id, details={"featured": body.featured, "reason": body.reason[:200]})
        svc.db.commit()
    except AuthError as exc:
        return error_response(exc)
    return {"id": str(p.public_id), "featured": p.featured}
