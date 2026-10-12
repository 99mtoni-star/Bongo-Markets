"""JSON API for authentication: /api/v1/auth/* (M03)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.auth.deps import (
    clear_session_cookie,
    get_auth_service,
    require_session,
    set_session_cookie,
)
from app.auth.identifiers import mask_phone
from app.auth.service import REGISTER_ACCEPTED, RESET_ACCEPTED, AuthError, AuthService, SessionContext

router = APIRouter(prefix="/auth", tags=["auth"])


class StrictModel(BaseModel):
    """Unknown fields are rejected, so clients cannot smuggle e.g. a "role" (AUTH-008)."""

    model_config = ConfigDict(extra="forbid")

# Schema ceilings are far above the policy maximum, so over-long passwords get an explicit
# policy error instead of being silently truncated (SEC-PWD-004).
Pw = Field(..., min_length=1, max_length=1024)


class RegisterIn(StrictModel):
    full_name: str = Field(..., max_length=200)
    phone: str = Field(..., max_length=32)
    password: str = Pw
    email: str | None = Field(None, max_length=254)


class VerifyIn(StrictModel):
    verification_id: str = Field(..., max_length=64)
    code: str = Field(..., max_length=12)


class ResendIn(StrictModel):
    verification_id: str = Field(..., max_length=64)


class LoginIn(StrictModel):
    identifier: str = Field(..., max_length=254)
    password: str = Pw


class ChangePasswordIn(StrictModel):
    current_password: str = Pw
    new_password: str = Pw


class ForgotIn(StrictModel):
    identifier: str = Field(..., max_length=254)


class ResetIn(StrictModel):
    reset_id: str = Field(..., max_length=64)
    code: str = Field(..., max_length=12)
    new_password: str = Pw
    mfa_code: str | None = Field(None, max_length=16)  # required when the account has MFA (ID-008)


class EmailIn(StrictModel):
    email: str = Field(..., max_length=254)


def error_response(exc: AuthError) -> JSONResponse:
    body: dict = {"code": exc.code, "message": exc.message}
    if exc.field:
        body["field"] = exc.field
    if exc.verification_id:
        body["verification_id"] = exc.verification_id
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    return JSONResponse({"error": body}, status_code=exc.status, headers=headers)


@router.post("/register", status_code=202)
def register(body: RegisterIn, svc: AuthService = Depends(get_auth_service)):
    try:
        vid = svc.register(full_name=body.full_name, phone=body.phone, password=body.password, email=body.email)
    except AuthError as exc:
        return error_response(exc)
    return {"message": REGISTER_ACCEPTED, "verification_id": vid}


@router.post("/verify-phone")
def verify_phone(body: VerifyIn, request: Request, svc: AuthService = Depends(get_auth_service)):
    try:
        token = svc.verify_phone(body.verification_id, body.code)
    except AuthError as exc:
        return error_response(exc)
    response = JSONResponse({"message": "Namba imethibitishwa. Karibu Bongo Markets!"})
    set_session_cookie(response, request, token)
    return response


@router.post("/resend-code", status_code=202)
def resend(body: ResendIn, svc: AuthService = Depends(get_auth_service)):
    try:
        vid = svc.resend_code(body.verification_id)
    except AuthError as exc:
        return error_response(exc)
    return {"message": REGISTER_ACCEPTED, "verification_id": vid}


@router.post("/login")
def login(body: LoginIn, request: Request, svc: AuthService = Depends(get_auth_service)):
    try:
        result = svc.login(body.identifier, body.password)
    except AuthError as exc:
        return error_response(exc)
    if result.challenge_id:
        # Password accepted; the authenticator code is still required. No cookie yet.
        return {"mfa_required": True, "challenge_id": result.challenge_id,
                "message": "Weka namba kutoka kwenye programu yako ya uthibitishaji."}
    response = JSONResponse({"message": "Umeingia.", "mfa_required": False})
    set_session_cookie(response, request, result.token)
    return response


class MfaLoginIn(StrictModel):
    challenge_id: str = Field(..., max_length=64)
    code: str = Field(..., max_length=16)


@router.post("/login/mfa")
def login_mfa(body: MfaLoginIn, request: Request, svc: AuthService = Depends(get_auth_service)):
    try:
        token = svc.complete_mfa_login(body.challenge_id, body.code)
    except AuthError as exc:
        return error_response(exc)
    response = JSONResponse({"message": "Umeingia kwa MFA."})
    set_session_cookie(response, request, token)
    return response


@router.post("/logout", status_code=204)
def logout(request: Request, ctx: SessionContext = Depends(require_session),
           svc: AuthService = Depends(get_auth_service)):
    svc.logout(ctx)
    response = Response(status_code=204)
    clear_session_cookie(response, request)
    return response


@router.get("/me")
def me(ctx: SessionContext = Depends(require_session)):
    u = ctx.user
    return {
        "id": str(u.public_id),  # the internal numeric id is never exposed
        "full_name": u.full_name,
        "phone": u.phone_e164,
        "phone_masked": mask_phone(u.phone_e164),
        "email": u.email,
        "email_verified": u.email_verified_at is not None,
        "status": u.status,
    }


@router.post("/password/change")
def change_password(body: ChangePasswordIn, request: Request, ctx: SessionContext = Depends(require_session),
                    svc: AuthService = Depends(get_auth_service)):
    try:
        token = svc.change_password(ctx, body.current_password, body.new_password)
    except AuthError as exc:
        return error_response(exc)
    response = JSONResponse({"message": "Nenosiri limebadilishwa. Vifaa vingine vimetolewa kwenye akaunti."})
    set_session_cookie(response, request, token)
    return response


@router.post("/password/forgot", status_code=202)
def forgot(body: ForgotIn, svc: AuthService = Depends(get_auth_service)):
    try:
        rid = svc.forgot_password(body.identifier)
    except AuthError as exc:
        return error_response(exc)
    return {"message": RESET_ACCEPTED, "reset_id": rid}


@router.post("/password/reset")
def reset(body: ResetIn, svc: AuthService = Depends(get_auth_service)):
    try:
        svc.reset_password(body.reset_id, body.code, body.new_password, body.mfa_code)
    except AuthError as exc:
        return error_response(exc)
    return {"message": "Nenosiri limerejeshwa. Sasa unaweza kuingia."}


@router.post("/email/verify-request", status_code=202)
def email_request(body: EmailIn, request: Request, ctx: SessionContext = Depends(require_session),
                  svc: AuthService = Depends(get_auth_service),
                  step_up_token: str | None = Header(None, alias="X-Step-Up-Token", max_length=200)):
    from app.auth.security import SecurityService

    sec = SecurityService(svc.db, svc.settings, svc.engine, svc.notifier, svc.client)
    try:
        vid = sec.request_email_change(ctx, body.email, step_up_token)
    except AuthError as exc:
        return error_response(exc)
    return {"message": "Tumetuma namba ya uthibitisho kwa barua pepe.", "verification_id": vid}


@router.post("/email/verify")
def email_verify(body: VerifyIn, ctx: SessionContext = Depends(require_session),
                 svc: AuthService = Depends(get_auth_service)):
    try:
        svc.confirm_email(ctx, body.verification_id, body.code)
    except AuthError as exc:
        return error_response(exc)
    return {"message": "Barua pepe imethibitishwa."}
