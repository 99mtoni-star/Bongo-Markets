"""Public, non-sensitive system information."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Request

from app.core.modules import MODULES, TOTAL_REQUIREMENTS

router = APIRouter(tags=["system"])


@router.get("/system/info")
def info(request: Request) -> dict:
    s = request.app.state.settings
    # Deliberately excludes secrets, database URL and host details.
    return {"name": s.app_name, "version": s.version, "environment": s.environment.value}


@router.get("/system/modules")
def modules() -> dict:
    return {
        "total_requirements": TOTAL_REQUIREMENTS,
        "modules": [{**asdict(m), "status": m.status.value} for m in MODULES],
    }
