"""Liveness and readiness probes."""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

router = APIRouter(tags=["health"])
logger = logging.getLogger("bongomarkets")
ROOT = Path(__file__).resolve().parent.parent.parent


@lru_cache
def expected_revision() -> str | None:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    return ScriptDirectory.from_config(cfg).get_current_head()


def database_status(request: Request) -> dict:
    """Return a non-sensitive summary of database health."""
    try:
        with request.app.state.session_factory() as session:
            session.execute(text("SELECT 1"))
            revision = session.execute(text("SELECT version_num FROM bm.alembic_version")).scalar_one_or_none()
            reconcile = session.execute(
                text("SELECT value FROM bm.system_flags WHERE key = 'payments_reconciliation_required'")
            ).scalar_one_or_none()
            server_version = session.execute(text("SHOW server_version")).scalar_one()
    except Exception as exc:  # never expose driver errors to clients
        logger.warning("readiness_db_failed", extra={"extra_fields": {"error_type": type(exc).__name__}})
        return {"database": "unavailable"}
    head = expected_revision()
    return {
        "database": "ok",
        "server": f"PostgreSQL {server_version.split()[0]}",
        "migrations": "up-to-date" if revision == head else f"behind (db={revision}, code={head})",
        "payments_authoritative": reconcile != "true",
    }


@router.get("/health/live")
def live() -> dict:
    return {"status": "ok"}


@router.get("/health/ready")
def ready(request: Request):
    settings = request.app.state.settings
    db = database_status(request)
    ok = db.get("database") == "ok" and db.get("migrations") == "up-to-date"
    body = {"status": "ok" if ok else "unavailable", "environment": settings.environment.value,
            "checks": {"config": "ok", **db}}
    return JSONResponse(body, status_code=200 if ok else 503)
