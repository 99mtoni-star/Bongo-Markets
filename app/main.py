"""Bongo Markets application factory (M01)."""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import health, system
from app.auth import api as auth_api
from app.auth import security_api, security_web
from app.auth import web as auth_web
from app.auth.notify import build_notifier
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, request_id_var
from app.db.session import session_factory
from app.web import pages

logger = logging.getLogger("bongomarkets")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
    ),
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        debug=settings.debug,
        docs_url=None if settings.is_production_like else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production_like else "/openapi.json",
    )
    app.state.settings = settings
    app.state.session_factory = session_factory(settings)  # engine connects lazily
    app.state.notifier = build_notifier(settings.notifier)

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-Request-ID", "X-CSRF-Token"],
        )

    allowed_origins = set(settings.cors_origins)

    @app.middleware("http")
    async def origin_guard(request: Request, call_next):
        # Cookie-authenticated state changes must come from our own origin or an approved
        # one (SEC-WEB-003; full CSRF policy in M06). Browsers always send Origin on POST.
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("origin")
            if origin and origin != "null":
                own = {f"{request.url.scheme}://{request.headers.get('host', '')}"}
                if origin not in own and origin not in allowed_origins:
                    return JSONResponse({"error": {"code": 403, "message": "Origin not allowed"}}, status_code=403)
            elif origin == "null":
                return JSONResponse({"error": {"code": 403, "message": "Origin not allowed"}}, status_code=403)
        return await call_next(request)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("X-Request-ID", "")
        rid = incoming if incoming.isalnum() and len(incoming) <= 64 else uuid.uuid4().hex
        token = request_id_var.set(rid)
        start = time.perf_counter()
        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            response.headers["X-Request-ID"] = rid
            for key, value in SECURITY_HEADERS.items():
                # Swagger UI (dev only; disabled in staging/production) loads assets from its CDN.
                if key == "Content-Security-Policy" and request.url.path == "/docs":
                    continue
                response.headers.setdefault(key, value)
            if settings.is_production_like:
                response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            logger.info(
                "request",
                extra={"extra_fields": {"method": request.method, "path": request.url.path,
                                        "status": response.status_code, "duration_ms": duration_ms}},
            )
            return response
        finally:
            request_id_var.reset(token)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.status_code, "message": exc.detail}},
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):
        # Controlled error handling: never leak stack traces or internals to clients.
        logger.exception("unhandled_error")
        return JSONResponse(
            status_code=500,
            content={"error": {"code": 500, "message": "Internal server error"}},
        )

    app.include_router(health.router)
    app.include_router(system.router, prefix="/api/v1")
    app.include_router(auth_api.router, prefix="/api/v1")
    app.include_router(security_api.router, prefix="/api/v1")
    app.include_router(security_web.router)
    app.include_router(auth_web.router)
    app.include_router(pages.router)
    return app


app = create_app()
