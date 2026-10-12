"""M04 JSON API: MFA, step-up, sessions, phone change, roles and incident response."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import Field
from sqlalchemy.orm import Session

from app.auth.api import StrictModel, error_response
from app.auth.deps import client_of, require_session
from app.auth.security import SecurityService, StepUpAction
from app.auth.service import AuthError, SessionContext
from app.db.session import get_db, get_engine

router = APIRouter(tags=["security"])
StepUpHeader = Header(None, alias="X-Step-Up-Token", max_length=200)


def get_security_service(request: Request, db: Session = Depends(get_db)) -> SecurityService:
    settings = request.app.state.settings
    return SecurityService(db, settings, get_engine(settings), request.app.state.notifier, client_of(request))


def _run(fn, *args, ok_status: int = 200, **kwargs):
    try:
        result = fn(*args, **kwargs)
    except AuthError as exc:
        return error_response(exc)
    return JSONResponse(result if isinstance(result, dict) else {"result": result}, status_code=ok_status)


# ---------------------------------------------------------------- step-up
class StepUpIn(StrictModel):
    action: str = Field(..., max_length=48)
    password: str = Field(..., max_length=1024)
    mfa_code: str | None = Field(None, max_length=16)


@router.post("/auth/step-up")
def step_up(body: StepUpIn, ctx: SessionContext = Depends(require_session),
            svc: SecurityService = Depends(get_security_service)):
    """Returns a single-use token for ONE action, valid 300 s. Send it as X-Step-Up-Token."""
    return _run(lambda: {"step_up_token": svc.step_up(ctx, body.action, body.password, body.mfa_code),
                         "expires_in": 300, "action": body.action})


# ---------------------------------------------------------------- MFA
class CodeIn(StrictModel):
    code: str = Field(..., max_length=16)


@router.post("/auth/mfa/totp/setup")
def totp_setup(ctx: SessionContext = Depends(require_session), svc: SecurityService = Depends(get_security_service)):
    return _run(svc.begin_totp_setup, ctx)


@router.post("/auth/mfa/totp/confirm")
def totp_confirm(body: CodeIn, ctx: SessionContext = Depends(require_session),
                 svc: SecurityService = Depends(get_security_service)):
    return _run(lambda: {"recovery_codes": svc.confirm_totp_setup(ctx, body.code),
                         "message": "MFA imewashwa. Hifadhi namba hizi za dharura mahali salama."})


@router.post("/auth/mfa/totp/disable")
def totp_disable(ctx: SessionContext = Depends(require_session), svc: SecurityService = Depends(get_security_service),
                 step_up_token: str | None = StepUpHeader):
    return _run(lambda: svc.disable_totp(ctx, step_up_token) or {"message": "MFA imezimwa."})


@router.post("/auth/mfa/recovery-codes")
def recovery_codes(ctx: SessionContext = Depends(require_session),
                   svc: SecurityService = Depends(get_security_service), step_up_token: str | None = StepUpHeader):
    return _run(lambda: {"recovery_codes": svc.regenerate_recovery_codes(ctx, step_up_token)})


# ---------------------------------------------------------------- sessions
@router.get("/auth/sessions")
def sessions(ctx: SessionContext = Depends(require_session), svc: SecurityService = Depends(get_security_service)):
    return {"sessions": [{**s, "created_at": s["created_at"].isoformat(),
                          "last_seen_at": s["last_seen_at"].isoformat()} for s in svc.list_sessions(ctx)]}


@router.delete("/auth/sessions/{session_id}")
def revoke_session(session_id: str, ctx: SessionContext = Depends(require_session),
                   svc: SecurityService = Depends(get_security_service)):
    if not svc.revoke_session(ctx, session_id[:40]):
        return JSONResponse({"error": {"code": "not_found", "message": "Kifaa hakipatikani."}}, status_code=404)
    return {"message": "Kifaa kimetolewa kwenye akaunti."}


@router.post("/auth/sessions/revoke-others")
def revoke_others(ctx: SessionContext = Depends(require_session),
                  svc: SecurityService = Depends(get_security_service)):
    return {"revoked": svc.revoke_other_sessions(ctx)}


# ---------------------------------------------------------------- phone / email change
class PhoneChangeIn(StrictModel):
    new_phone: str = Field(..., max_length=32)


class VerifyIn(StrictModel):
    verification_id: str = Field(..., max_length=64)
    code: str = Field(..., max_length=12)


@router.post("/auth/phone/change-request", status_code=202)
def phone_change(body: PhoneChangeIn, ctx: SessionContext = Depends(require_session),
                 svc: SecurityService = Depends(get_security_service), step_up_token: str | None = StepUpHeader):
    return _run(lambda: {"verification_id": svc.request_phone_change(ctx, body.new_phone, step_up_token),
                         "message": "Tumetuma namba ya uthibitisho kwa namba mpya."}, ok_status=202)


@router.post("/auth/phone/confirm")
def phone_confirm(body: VerifyIn, ctx: SessionContext = Depends(require_session),
                  svc: SecurityService = Depends(get_security_service)):
    return _run(lambda: svc.confirm_phone_change(ctx, body.verification_id, body.code)
                or {"message": "Namba ya simu imebadilishwa."})


# ---------------------------------------------------------------- platform roles (AUTH-008, AUTH-005 v1.12.2)
class RoleIn(StrictModel):
    role: str = Field(..., max_length=32)


@router.post("/admin/users/{public_id}/roles", status_code=201)
def grant_role(public_id: str, body: RoleIn, ctx: SessionContext = Depends(require_session),
               svc: SecurityService = Depends(get_security_service), step_up_token: str | None = StepUpHeader):
    return _run(lambda: svc.grant_role(ctx, public_id[:40], body.role, step_up_token)
                or {"message": "Jukumu limetolewa."}, ok_status=201)


@router.delete("/admin/users/{public_id}/roles/{role}")
def revoke_role(public_id: str, role: str, ctx: SessionContext = Depends(require_session),
                svc: SecurityService = Depends(get_security_service), step_up_token: str | None = StepUpHeader):
    return _run(lambda: svc.revoke_role(ctx, public_id[:40], role[:32], step_up_token)
                or {"message": "Jukumu limeondolewa."})


# ---------------------------------------------------------------- incident response (SEC-IR-003)
class ReasonIn(StrictModel):
    reason: str = Field(..., min_length=3, max_length=500)


class PaymentsIn(StrictModel):
    suspended: bool
    reason: str = Field(..., min_length=3, max_length=500)


@router.post("/admin/incident/users/{public_id}/suspend")
def suspend(public_id: str, body: ReasonIn, ctx: SessionContext = Depends(require_session),
            svc: SecurityService = Depends(get_security_service), step_up_token: str | None = StepUpHeader):
    return _run(lambda: svc.suspend_user(ctx, public_id[:40], body.reason, step_up_token)
                or {"message": "Akaunti imesimamishwa na vifaa vyote vimetolewa."})


@router.post("/admin/incident/users/{public_id}/reinstate")
def reinstate(public_id: str, body: ReasonIn, ctx: SessionContext = Depends(require_session),
              svc: SecurityService = Depends(get_security_service), step_up_token: str | None = StepUpHeader):
    return _run(lambda: svc.reinstate_user(ctx, public_id[:40], body.reason, step_up_token)
                or {"message": "Akaunti imerejeshwa."})


@router.post("/admin/incident/users/{public_id}/sign-out")
def sign_out(public_id: str, ctx: SessionContext = Depends(require_session),
             svc: SecurityService = Depends(get_security_service), step_up_token: str | None = StepUpHeader):
    return _run(lambda: {"revoked": svc.force_sign_out(ctx, public_id[:40], step_up_token)})


@router.post("/admin/incident/payments")
def payments(body: PaymentsIn, ctx: SessionContext = Depends(require_session),
             svc: SecurityService = Depends(get_security_service), step_up_token: str | None = StepUpHeader):
    return _run(lambda: svc.set_payments_suspended(ctx, body.suspended, body.reason, step_up_token)
                or {"payments_suspended": body.suspended})


__all__ = ["router", "StepUpAction"]
