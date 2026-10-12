"""FastAPI dependencies and cookie handling for authentication."""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.auth.service import AuthService, Client, SessionContext
from app.auth.tokens import equal
from app.db.session import get_db, get_engine

SESSION_COOKIE = "bm_session"
CSRF_COOKIE = "bm_csrf"


def client_of(request: Request) -> Client:
    # Behind a reverse proxy the trusted client IP is configured in M20 (proxy headers).
    host = request.client.host if request.client else "unknown"
    return Client(ip=host, user_agent=request.headers.get("user-agent"))


def get_auth_service(request: Request, db: Session = Depends(get_db)) -> AuthService:
    settings = request.app.state.settings
    return AuthService(db, settings, get_engine(settings), request.app.state.notifier, client_of(request))


def set_session_cookie(response: Response, request: Request, token: str) -> None:
    """SEC-WEB-002: HttpOnly, Secure, SameSite=Lax, Path=/, bounded lifetime."""
    settings = request.app.state.settings
    response.set_cookie(
        SESSION_COOKIE, token, max_age=settings.session_ttl_hours * 3600, path="/",
        httponly=True, secure=settings.cookie_secure, samesite="lax",
    )


def clear_session_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True,
                           secure=request.app.state.settings.cookie_secure, samesite="lax")


def optional_session(request: Request, svc: AuthService = Depends(get_auth_service)) -> SessionContext | None:
    return svc.session_from_token(request.cookies.get(SESSION_COOKIE))


def require_session(ctx: SessionContext | None = Depends(optional_session)) -> SessionContext:
    if ctx is None:
        raise HTTPException(status_code=401, detail="Tafadhali ingia kwanza.")
    return ctx


# ---------------------------------------------------------------- CSRF for HTML forms
def csrf_token(request: Request) -> str:
    """Return the per-browser CSRF token, creating one if needed (set by ensure_csrf_cookie)."""
    token = request.cookies.get(CSRF_COOKIE) or getattr(request.state, "new_csrf", None)
    if not token:
        token = secrets.token_urlsafe(24)
        request.state.new_csrf = token
    return token


def ensure_csrf_cookie(request: Request, response: Response) -> None:
    new = getattr(request.state, "new_csrf", None)
    if new:
        response.set_cookie(CSRF_COOKIE, new, path="/", httponly=True,
                            secure=request.app.state.settings.cookie_secure, samesite="strict")


def check_csrf(request: Request, submitted: str | None) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    if not cookie or not submitted or not equal(cookie, submitted):
        raise HTTPException(status_code=403, detail="Ombi limekataliwa (CSRF). Pakia ukurasa upya.")
