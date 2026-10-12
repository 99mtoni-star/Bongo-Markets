"""Engine and session management (M02).

The application connects as the least-privilege role (SEC-005). All queries go
through SQLAlchemy with bound parameters; raw string interpolation into SQL is
forbidden (SEC-006).
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from fastapi import Request
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings


@lru_cache(maxsize=8)
def _engine_for(url: str, pool_size: int, statement_timeout_ms: int) -> Engine:
    engine = create_engine(
        url,
        pool_size=pool_size,
        max_overflow=pool_size,
        pool_pre_ping=True,
        pool_recycle=1800,
        future=True,
    )

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_conn, _record):  # pragma: no cover - exercised against a live DB
        with dbapi_conn.cursor() as cur:
            cur.execute("SET search_path TO bm")
            cur.execute("SELECT set_config('statement_timeout', %s, false)", (str(int(statement_timeout_ms)),))
            cur.execute("SET TIME ZONE 'UTC'")

    return engine


def get_engine(settings: Settings) -> Engine:
    return _engine_for(
        settings.database_url.get_secret_value(), settings.db_pool_size, settings.db_statement_timeout_ms
    )


def session_factory(settings: Settings) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(settings), expire_on_commit=False, autoflush=False)


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one transaction-scoped session per request."""
    factory: sessionmaker[Session] = request.app.state.session_factory
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
