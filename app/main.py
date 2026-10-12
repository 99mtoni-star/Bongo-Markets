"""Bongo Markets application factory (M01)."""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import health, system
from app.auth import api as auth_api
from app.auth import security_api, security_web
from app.auth import web as auth_web
from app.auth.notify import build_notifier
from app.authz import api as authz_api
from app.authz import web as authz_web
from app.catalog import api as catalog_api
from app.catalog import web as catalog_web
from app.catalog.media import LocalStorage
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, request_id_var
from app.db.session import session_factory
from app.market import api as market_api
from app.market import web as market_web
from app.orders import api as orders_api
from app.orders import web as orders_web
from app.shops import api as shops_api
from app.shops import web as shops_web
from app.web import pages
from app.web.layout import STATIC_DIR

logger = logging.getLogger("bongomarkets")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    # SEC-007 (M06): no inline scripts or styles anywhere; only same-origin assets.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
        "form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
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
    app.state.storage = LocalStorage(settings.media_dir)

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
    # Server-to-server callbacks authenticate with signatures + replay guard instead (M13).
    csrf_exempt_prefixes = ("/api/v1/webhooks/",)

    def _deny(message: str) -> JSONResponse:
        return JSONResponse({"error": {"code": 403, "message": message}}, status_code=403)

    @app.middleware("http")
    async def csrf_origin_guard(request: Request, call_next):
        """SEC-008, SEC-WEB-004, SEC-INV-003: two INDEPENDENT controls on every state-changing request.

        1. Origin (or, if absent, Referer) must be our own origin or an approved one.
        2. A CSRF token: JSON API requests send X-CSRF-Token equal to the bm_csrf cookie (double submit);
           HTML forms send the same token as a hidden field, checked in the route (check_csrf).
        Passing one control never substitutes for the other.
        """
        if request.method in ("POST", "PUT", "PATCH", "DELETE") \
                and not request.url.path.startswith(csrf_exempt_prefixes):
            own = f"{request.url.scheme}://{request.headers.get('host', '')}"
            allowed = {own, *allowed_origins}
            origin = request.headers.get("origin")
            if origin is not None:
                if origin not in allowed:
                    return _deny("Origin not allowed")
            else:
                referer = request.headers.get("referer", "")
                if not any(referer == a or referer.startswith(a + "/") for a in allowed):
                    return _deny("Origin or Referer required")
            if request.url.path.startswith("/api/"):
                from app.auth.deps import CSRF_COOKIE
                from app.auth.tokens import equal

                cookie = request.cookies.get(CSRF_COOKIE)
                header = request.headers.get("x-csrf-token")
                if not cookie or not header or not equal(cookie, header):
                    return _deny("CSRF token missing or invalid")
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
            if request.url.path.startswith("/static/"):
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"  # versioned URLs
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
    app.include_router(authz_api.router, prefix="/api/v1")
    app.include_router(authz_web.router)
    app.include_router(shops_api.router, prefix="/api/v1")
    app.include_router(shops_web.router)
    app.include_router(catalog_api.router, prefix="/api/v1")
    app.include_router(catalog_api.media_router)
    app.include_router(catalog_web.router)
    app.include_router(market_api.router, prefix="/api/v1")
    app.include_router(market_web.router)
    app.include_router(orders_api.router, prefix="/api/v1")
    app.include_router(orders_web.router)
    app.include_router(security_web.router)
    app.include_router(auth_web.router)
    app.include_router(pages.router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
