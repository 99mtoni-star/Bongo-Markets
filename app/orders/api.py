"""Cart, checkout and order API (M11/M12).

There is deliberately no endpoint through which a customer sets an order or payment status
(ORD-LC-004, BR-013). Request bodies are strict: unknown fields such as ``price`` or ``status`` are rejected.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import Field
from sqlalchemy.orm import Session

from app.auth.api import StrictModel, error_response
from app.auth.deps import client_of, require_session
from app.auth.service import AuthError, SessionContext
from app.authz.api import privileged_mutation
from app.db.session import get_db, get_engine
from app.orders.cart import Address
from app.orders.service import OrderService

router = APIRouter(tags=["orders"])


def get_order_service(request: Request, db: Session = Depends(get_db)) -> OrderService:
    s = request.app.state.settings
    return OrderService(db, s, get_engine(s), request.app.state.notifier, client_of(request))


def _run(fn, ok_status: int = 200):
    try:
        result = fn()
    except AuthError as exc:
        return error_response(exc)
    return JSONResponse(result, status_code=ok_status)


class CartItemIn(StrictModel):
    product_id: str = Field(..., max_length=40)
    quantity: int = Field(1, ge=1, le=999)


class QuantityIn(StrictModel):
    quantity: int = Field(..., ge=0, le=999)


class CheckoutIn(StrictModel):
    name: str = Field(..., max_length=120)
    phone: str = Field(..., max_length=32)
    region: str = Field(..., max_length=60)
    area: str = Field("", max_length=80)
    street: str = Field("", max_length=160)
    notes: str = Field("", max_length=300)
    payment_method: str = Field("ONLINE", max_length=12)
    expected_total: str | None = Field(None, max_length=24)


class ReasonIn(StrictModel):
    reason: str = Field("", max_length=300)


class AdvanceIn(StrictModel):
    status: str = Field(..., max_length=20)
    courier_name: str = Field("", max_length=120)
    courier_phone: str = Field("", max_length=32)


class CourierIn(StrictModel):
    courier_name: str = Field(..., max_length=120)
    courier_phone: str = Field(..., max_length=32)


class PinIn(StrictModel):
    pin: str = Field(..., max_length=12)


# ------------------------------------------------------------------ cart (M11)
@router.get("/cart")
def cart(ctx: SessionContext = Depends(require_session), svc: OrderService = Depends(get_order_service)):
    return svc.view(ctx)


@router.post("/cart/items", status_code=201)
def add_item(body: CartItemIn, ctx: SessionContext = Depends(require_session),
             svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.add_item(ctx, body.product_id, body.quantity) or svc.view(ctx), ok_status=201)


@router.patch("/cart/items/{product_id}")
def set_quantity(product_id: str, body: QuantityIn, ctx: SessionContext = Depends(require_session),
                 svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.set_quantity(ctx, product_id[:40], body.quantity) or svc.view(ctx))


@router.delete("/cart/items/{product_id}")
def remove_item(product_id: str, ctx: SessionContext = Depends(require_session),
                svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.set_quantity(ctx, product_id[:40], 0) or svc.view(ctx))


@router.post("/checkout", status_code=201)
def checkout(body: CheckoutIn, ctx: SessionContext = Depends(require_session),
             svc: OrderService = Depends(get_order_service),
             idempotency_key: str | None = Header(None, alias="Idempotency-Key", max_length=80)):
    addr = Address(name=body.name, phone=body.phone, region=body.region, area=body.area, street=body.street,
                   notes=body.notes)
    try:
        result = svc.checkout(ctx, addr, body.payment_method, idempotency_key or "", body.expected_total)
    except AuthError as exc:
        resp = error_response(exc)
        if exc.code == "price_changed":  # tell the client the authoritative total to re-confirm
            payload = json.loads(resp.body)
            payload["error"]["cart"] = svc.view(ctx)
            resp = JSONResponse(payload, status_code=exc.status)
        return resp
    return JSONResponse(result, status_code=200 if result["replayed"] else 201)


# ------------------------------------------------------------------ buyer orders (M12)
@router.get("/orders")
def my_orders(ctx: SessionContext = Depends(require_session), svc: OrderService = Depends(get_order_service)):
    return {"orders": svc.my_orders(ctx)}


@router.get("/orders/{number}")
def my_order(number: str, ctx: SessionContext = Depends(require_session),
             svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.order_dict(svc.buyer_order(ctx, number)))


@router.post("/orders/{number}/cancel")
def cancel(number: str, body: ReasonIn, ctx: SessionContext = Depends(require_session),
           svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.order_dict(svc.buyer_cancel(ctx, number, body.reason)))


@router.post("/orders/{number}/resend-pin")
def resend_pin(number: str, ctx: SessionContext = Depends(require_session),
               svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.resend_pin(ctx, number) or {"message": "PIN mpya imetumwa kwa SMS."})


@router.get("/order-items/{item_id}/review-eligibility")
def review_eligibility(item_id: str, ctx: SessionContext = Depends(require_session),
                       svc: OrderService = Depends(get_order_service)):
    return {"eligible": svc.can_review(ctx.user.id, item_id[:40])}


# ------------------------------------------------------------------ shop orders (M12)
@router.get("/shops/{slug}/orders")
def shop_orders(slug: str, status: str = "", ctx: SessionContext = Depends(require_session),
                svc: OrderService = Depends(get_order_service)):
    return _run(lambda: {"orders": svc.shop_orders(ctx, slug, status[:20] or None)})


@router.get("/shops/{slug}/orders/{number}")
def shop_order(slug: str, number: str, ctx: SessionContext = Depends(require_session),
               svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.order_dict(svc.shop_order(ctx, slug, number, "shop.orders.view")[1], seller=True))


@router.post("/shops/{slug}/orders/{number}/status", dependencies=[Depends(privileged_mutation)])
def advance(slug: str, number: str, body: AdvanceIn, ctx: SessionContext = Depends(require_session),
            svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.order_dict(svc.advance(ctx, slug, number, body.status, courier_name=body.courier_name,
                                                   courier_phone=body.courier_phone), seller=True))


@router.post("/shops/{slug}/orders/{number}/courier", dependencies=[Depends(privileged_mutation)])
def courier(slug: str, number: str, body: CourierIn, ctx: SessionContext = Depends(require_session),
            svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.order_dict(svc.assign_courier(ctx, slug, number, body.courier_name, body.courier_phone),
                                       seller=True))


@router.post("/shops/{slug}/orders/{number}/cancel", dependencies=[Depends(privileged_mutation)])
def seller_cancel(slug: str, number: str, body: ReasonIn, ctx: SessionContext = Depends(require_session),
                  svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.order_dict(svc.seller_cancel(ctx, slug, number, body.reason), seller=True))


@router.post("/shops/{slug}/orders/{number}/deliver", dependencies=[Depends(privileged_mutation)])
def deliver(slug: str, number: str, body: PinIn, ctx: SessionContext = Depends(require_session),
            svc: OrderService = Depends(get_order_service)):
    return _run(lambda: svc.order_dict(svc.confirm_delivery(ctx, slug, number, body.pin), seller=True))
