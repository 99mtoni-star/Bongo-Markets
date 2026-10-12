"""RBAC and compliance API (M05). Authoritative contract: docs/api/rbac.md (AUTH-012).

Every privileged mutation needs: a permission (deny by default), an aal2 session, a single-use
step-up token, an explicit CSRF token AND an allowed Origin (AUTH-013).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import Field
from sqlalchemy.orm import Session

from app.auth.api import StrictModel, error_response
from app.auth.deps import CSRF_COOKIE, client_of, require_session
from app.auth.service import AuthError, SessionContext
from app.auth.tokens import equal
from app.authz.service import RBACService
from app.db.session import get_db, get_engine

router = APIRouter(tags=["rbac"])
StepUp = Header(None, alias="X-Step-Up-Token", max_length=200)


def get_rbac_service(request: Request, db: Session = Depends(get_db)) -> RBACService:
    s = request.app.state.settings
    return RBACService(db, s, get_engine(s), request.app.state.notifier, client_of(request))


def privileged_mutation(request: Request) -> None:
    """AUTH-013: explicit CSRF token (double submit) AND an allowed Origin/Referer, both required."""
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get("X-CSRF-Token")
    if not cookie or not header or not equal(cookie, header):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
    own = f"{request.url.scheme}://{request.headers.get('host', '')}"
    allowed = {own, *request.app.state.settings.cors_origins}
    origin = request.headers.get("origin")
    referer = request.headers.get("referer", "")
    if origin:
        ok = origin in allowed
    else:
        ok = any(referer == a or referer.startswith(a + "/") for a in allowed)
    if not ok:
        raise HTTPException(status_code=403, detail="Origin not allowed")


def _run(fn, ok_status: int = 200):
    try:
        result = fn()
    except AuthError as exc:
        return error_response(exc)
    return JSONResponse(result, status_code=ok_status)


@router.get("/admin/rbac")
def catalogue(ctx: SessionContext = Depends(require_session), svc: RBACService = Depends(get_rbac_service)):
    return _run(lambda: svc.catalogue(ctx))


@router.get("/auth/me/permissions")
def my_permissions(ctx: SessionContext = Depends(require_session), svc: RBACService = Depends(get_rbac_service)):
    return {**svc.my_permissions(ctx), "capabilities": svc.capabilities(ctx.user.id)}


class RolePermissionsIn(StrictModel):
    permissions: list[str] = Field(..., max_length=100)


@router.put("/admin/rbac/{scope}/roles/{role}", dependencies=[Depends(privileged_mutation)])
def set_role_permissions(scope: str, role: str, body: RolePermissionsIn, request: Request,
                         ctx: SessionContext = Depends(require_session), svc: RBACService = Depends(get_rbac_service),
                         if_match: str | None = Header(None, alias="If-Match", max_length=20),
                         step_up_token: str | None = StepUp):
    try:
        expected = int((if_match or "").strip('"')) if if_match else None
    except ValueError:
        expected = None
    return _run(lambda: {"policy_version": svc.set_role_permissions(ctx, scope.upper()[:16], role[:32],
                                                                     body.permissions, expected, step_up_token)})


@router.get("/admin/audit")
def audit_view(limit: int = 100, ctx: SessionContext = Depends(require_session),
               svc: RBACService = Depends(get_rbac_service)):
    return _run(lambda: {"events": svc.audit_view(ctx, limit)})


class ExportIn(StrictModel):
    since: datetime
    until: datetime
    category: str | None = Field(None, pattern="^(SECURITY|FINANCIAL|GENERAL)$")


@router.post("/admin/audit/export", dependencies=[Depends(privileged_mutation)])
def audit_export(body: ExportIn, ctx: SessionContext = Depends(require_session),
                 svc: RBACService = Depends(get_rbac_service), step_up_token: str | None = StepUp):
    try:
        data = svc.audit_export(ctx, body.since, body.until, body.category, step_up_token)
    except AuthError as exc:
        return error_response(exc)
    return PlainTextResponse(data, media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="audit-export.csv"',
                                      "Cache-Control": "no-store"})


class HoldIn(StrictModel):
    reason: str = Field(..., min_length=5, max_length=2000)


@router.post("/admin/users/{public_id}/legal-hold", status_code=201, dependencies=[Depends(privileged_mutation)])
def place_hold(public_id: str, body: HoldIn, ctx: SessionContext = Depends(require_session),
               svc: RBACService = Depends(get_rbac_service), step_up_token: str | None = StepUp):
    return _run(lambda: svc.place_legal_hold(ctx, public_id[:40], body.reason, step_up_token)
                or {"message": "Legal hold imewekwa."}, ok_status=201)


@router.delete("/admin/users/{public_id}/legal-hold", dependencies=[Depends(privileged_mutation)])
def release_hold(public_id: str, ctx: SessionContext = Depends(require_session),
                 svc: RBACService = Depends(get_rbac_service), step_up_token: str | None = StepUp):
    return _run(lambda: {"released": svc.release_legal_holds(ctx, public_id[:40], step_up_token)})


class CapabilityIn(StrictModel):
    status: str = Field(..., max_length=16)


@router.put("/admin/users/{public_id}/capabilities/{capability}", dependencies=[Depends(privileged_mutation)])
def capability_status(public_id: str, capability: str, body: CapabilityIn,
                      ctx: SessionContext = Depends(require_session), svc: RBACService = Depends(get_rbac_service)):
    cap = capability.upper()[:24]
    if cap not in ("BUYER", "SELLER", "SERVICE_PROVIDER", "DELIVERY_AGENT"):
        return JSONResponse({"error": {"code": "invalid", "message": "Uwezo haujulikani."}}, status_code=422)
    return _run(lambda: svc.set_capability_status(ctx, public_id[:40], cap, body.status.upper())
                or {"capability": cap, "status": body.status.upper()})


@router.post("/auth/account/close")
def close_account(request: Request, ctx: SessionContext = Depends(require_session),
                  svc: RBACService = Depends(get_rbac_service), step_up_token: str | None = StepUp):
    return _run(lambda: svc.close_account(ctx, step_up_token) or {"message": "Akaunti imefungwa."})
