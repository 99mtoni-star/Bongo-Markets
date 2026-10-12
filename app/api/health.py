"""Liveness and readiness probes."""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(tags=["health"])


@router.get("/health/live")
def live() -> dict:
    return {"status": "ok"}


@router.get("/health/ready")
def ready(request: Request) -> dict:
    settings = request.app.state.settings
    # Database readiness check is added by M02.
    return {"status": "ok", "environment": settings.environment.value, "checks": {"config": "ok"}}
