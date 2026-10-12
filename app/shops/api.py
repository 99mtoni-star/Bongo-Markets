"""Shop API (M07). Client input never sets owner, status or membership roles directly (BR-013)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import Field
from sqlalchemy.orm import Session

from app.auth.api import StrictModel, error_response
from app.auth.deps import client_of, optional_session, require_session
from app.auth.service import AuthError, SessionContext
from app.authz.api import privileged_mutation
from app.db.session import get_db, get_engine
from app.shops.models import ShopStatus
from app.shops.service import NOT_FOUND, ShopService

router = APIRouter(tags=["shops"])


def get_shop_service(request: Request, db: Session = Depends(get_db)) -> ShopService:
    s = request.app.state.settings
    return ShopService(db, s, get_engine(s), request.app.state.notifier, client_of(request))


def _run(fn, ok_status: int = 200):
    try:
        result = fn()
    except AuthError as exc:
        return error_response(exc)
    return JSONResponse(result, status_code=ok_status)


class ShopIn(StrictModel):
    name: str = Field(..., max_length=120)
    description: str | None = Field(None, max_length=2000)
    region: str | None = Field(None, max_length=60)
    slug: str | None = Field(None, max_length=40)


class ShopUpdateIn(StrictModel):
    name: str = Field(..., max_length=120)
    description: str | None = Field(None, max_length=2000)
    region: str | None = Field(None, max_length=60)


class MemberIn(StrictModel):
    phone: str = Field(..., max_length=32)
    role: str = Field(..., max_length=16)


class TransferIn(StrictModel):
    new_owner_id: str = Field(..., max_length=40)


class StatusIn(StrictModel):
    status: str = Field(..., max_length=24)
    reason: str = Field(..., min_length=3, max_length=1000)


@router.post("/shops", status_code=201)
def create(body: ShopIn, ctx: SessionContext = Depends(require_session),
           svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: svc._shop_dict(svc.create_shop(ctx, body.name, body.description, body.region, body.slug))
                | {"my_role": "OWNER"}, ok_status=201)


@router.get("/shops/mine")
def mine(ctx: SessionContext = Depends(require_session), svc: ShopService = Depends(get_shop_service)):
    return {"shops": svc.my_shops(ctx)}


@router.get("/shops/{slug}")
def public(slug: str, ctx: SessionContext | None = Depends(optional_session),
           svc: ShopService = Depends(get_shop_service)):
    shop = svc.shop_by_slug(slug)
    member = svc.membership(shop.id, ctx.user.id) if (shop and ctx) else None
    if shop is None or (shop.status != ShopStatus.ACTIVE and member is None):
        return JSONResponse({"error": {"code": "not_found", "message": NOT_FOUND}}, status_code=404)
    out = svc._shop_dict(shop)
    if member is None:
        out.pop("status")  # customers see a shop, not its admin state (SHOP-008)
    else:
        out["my_role"] = member.role_code
    return out


@router.patch("/shops/{slug}")
def update(slug: str, body: ShopUpdateIn, ctx: SessionContext = Depends(require_session),
           svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: svc._shop_dict(svc.update_profile(ctx, slug, name=body.name, description=body.description,
                                                          region=body.region)))


@router.get("/shops/{slug}/members")
def members(slug: str, ctx: SessionContext = Depends(require_session), svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: {"members": svc.members(ctx, slug)})


@router.post("/shops/{slug}/members", status_code=201)
def add_member(slug: str, body: MemberIn, ctx: SessionContext = Depends(require_session),
               svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: svc.add_member(ctx, slug, body.phone, body.role), ok_status=201)


@router.delete("/shops/{slug}/members/{user_id}")
def remove_member(slug: str, user_id: str, ctx: SessionContext = Depends(require_session),
                  svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: svc.remove_member(ctx, slug, user_id[:40]) or {"message": "Mwanachama ameondolewa."})


@router.post("/shops/{slug}/transfer-ownership")
def transfer(slug: str, body: TransferIn, ctx: SessionContext = Depends(require_session),
             svc: ShopService = Depends(get_shop_service),
             step_up_token: str | None = Header(None, alias="X-Step-Up-Token", max_length=200)):
    return _run(lambda: svc.transfer_ownership(ctx, slug, body.new_owner_id, step_up_token)
                or {"message": "Umiliki umehamishwa."})


@router.post("/shops/{slug}/resubmit")
def resubmit(slug: str, ctx: SessionContext = Depends(require_session), svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: svc._shop_dict(svc.resubmit(ctx, slug)))


@router.get("/shops/{slug}/dashboard")
def dashboard(slug: str, ctx: SessionContext = Depends(require_session), svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: svc.dashboard(ctx, slug))


@router.get("/shops/{slug}/history")
def history(slug: str, ctx: SessionContext = Depends(require_session), svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: {"history": svc.history(svc.shop_for(ctx, slug, "shop.admin.view"))})


@router.get("/admin/shops/pending")
def pending(ctx: SessionContext = Depends(require_session), svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: {"shops": [svc._shop_dict(s) for s in svc.pending_shops(ctx)]})


@router.post("/admin/shops/{slug}/status", dependencies=[Depends(privileged_mutation)])
def set_status(slug: str, body: StatusIn, ctx: SessionContext = Depends(require_session),
               svc: ShopService = Depends(get_shop_service)):
    return _run(lambda: svc._shop_dict(svc.set_status(ctx, slug, body.status.upper(), body.reason)))
