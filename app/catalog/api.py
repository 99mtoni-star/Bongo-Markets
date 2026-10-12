"""Catalogue API and media serving (M08)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Header, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.api import StrictModel, error_response
from app.auth.deps import client_of, optional_session, require_session
from app.auth.service import AuthError, SessionContext
from app.authz.api import privileged_mutation
from app.catalog.media import ImageRejected, read_limited
from app.catalog.models import Product, ProductImage
from app.catalog.service import CatalogService
from app.db.session import get_db, get_engine
from app.shops.models import ShopStatus

router = APIRouter(tags=["catalog"])


def get_catalog_service(request: Request, db: Session = Depends(get_db)) -> CatalogService:
    s = request.app.state.settings
    svc = CatalogService(db, s, get_engine(s), request.app.state.notifier, client_of(request))
    svc.storage = request.app.state.storage
    return svc


def _run(fn, ok_status: int = 200):
    try:
        result = fn()
    except AuthError as exc:
        return error_response(exc)
    return JSONResponse(result, status_code=ok_status)


class ProductIn(StrictModel):
    name: str = Field(..., max_length=200)
    category: str = Field(..., max_length=48)
    price: str = Field("0", max_length=20)
    stock: int = Field(0, ge=0, le=10_000_000)
    unit: str = Field("kipande", max_length=24)
    sku: str | None = Field(None, max_length=64)
    description: str | None = Field(None, max_length=2000)
    marketplace: bool = True


class ProductPatch(StrictModel):
    name: str | None = Field(None, max_length=200)
    category: str | None = Field(None, max_length=48)
    price: str | None = Field(None, max_length=20)
    stock: int | None = Field(None, ge=0, le=10_000_000)
    unit: str | None = Field(None, max_length=24)
    description: str | None = Field(None, max_length=2000)
    marketplace: bool | None = None
    status: str | None = Field(None, max_length=16)


class MinutesIn(StrictModel):
    minutes: int


@router.get("/categories")
def categories(svc: CatalogService = Depends(get_catalog_service)):
    return {"categories": [{"slug": c.slug, "name": c.name} for c in svc.categories()]}


@router.post("/shops/{slug}/products", status_code=201)
def create(slug: str, body: ProductIn, ctx: SessionContext = Depends(require_session),
           svc: CatalogService = Depends(get_catalog_service)):
    return _run(lambda: svc.product_dict(svc.create_product(ctx, slug, **body.model_dump()), include_admin=True),
                ok_status=201)


@router.get("/shops/{slug}/products")
def list_products(slug: str, ctx: SessionContext | None = Depends(optional_session),
                  svc: CatalogService = Depends(get_catalog_service)):
    shop = svc.shop_by_slug(slug)
    member = bool(shop and ctx and svc.authz.can(ctx.user.id, "shop.products.manage", shop_id=shop.id))
    if shop is None or (shop.status != ShopStatus.ACTIVE and not member):
        return JSONResponse({"error": {"code": "not_found", "message": "Duka halipatikani."}}, status_code=404)
    return {"products": [svc.product_dict(p, include_admin=member) for p in svc.shop_products(shop, public=not member)]}


@router.patch("/shops/{slug}/products/{product_id}")
def update(slug: str, product_id: str, body: ProductPatch, ctx: SessionContext = Depends(require_session),
           svc: CatalogService = Depends(get_catalog_service)):
    return _run(lambda: svc.product_dict(svc.update_product(ctx, slug, product_id[:40],
                                                            **body.model_dump(exclude_unset=True)),
                                         include_admin=True))


@router.post("/shops/{slug}/products/{product_id}/images", status_code=201)
def upload(slug: str, product_id: str, image: UploadFile = File(...), ctx: SessionContext = Depends(require_session),
           svc: CatalogService = Depends(get_catalog_service)):
    try:
        raw = read_limited(image.file)
    except ImageRejected as exc:
        return error_response(AuthError(str(exc), status=413, code="image_rejected", field="image"))
    return _run(lambda: {"id": str((row := svc.add_image(ctx, slug, product_id[:40], raw)).public_id),
                         "url": f"/media/{row.storage_key}", "width": row.width, "height": row.height},
                ok_status=201)


@router.delete("/shops/{slug}/products/{product_id}/images/{image_id}")
def delete_image(slug: str, product_id: str, image_id: str, ctx: SessionContext = Depends(require_session),
                 svc: CatalogService = Depends(get_catalog_service)):
    return _run(lambda: svc.remove_image(ctx, slug, product_id[:40], image_id[:40])
                or {"message": "Picha imeondolewa."})


@router.put("/admin/settings/stock-reservation-minutes", dependencies=[Depends(privileged_mutation)])
def set_minutes(body: MinutesIn, ctx: SessionContext = Depends(require_session),
                svc: CatalogService = Depends(get_catalog_service),
                step_up_token: str | None = Header(None, alias="X-Step-Up-Token", max_length=200)):
    return _run(lambda: {"minutes": svc.set_reservation_minutes(ctx, body.minutes, step_up_token)})


# ---------------------------------------------------------------- media (outside /api)
media_router = APIRouter(include_in_schema=False)


@media_router.get("/media/{key}")
def media(key: str, request: Request, db: Session = Depends(get_db)):
    img = db.execute(select(ProductImage).where(ProductImage.storage_key == key[:80],
                                                ProductImage.removed_at.is_(None))).scalar_one_or_none()
    data = request.app.state.storage.get(img.storage_key) if img else None
    if img is None or data is None or db.get(Product, img.product_id) is None:
        return Response(status_code=404)
    return Response(data, media_type=img.content_type, headers={
        "Cache-Control": "public, max-age=86400", "Content-Disposition": "inline",
        "Content-Security-Policy": "default-src 'none'; sandbox", "X-Content-Type-Options": "nosniff"})
