"""Alembic environment. Migrations run as the schema owner, never as the app role."""

from __future__ import annotations

import os
import re

from alembic import context
from sqlalchemy import create_engine, pool, text

from app.db import models  # noqa: F401  (register tables on Base.metadata)
from app.db.base import SCHEMA, Base

ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _role(env_name: str, default: str) -> str:
    value = os.environ.get(env_name, default)
    if not ROLE_RE.match(value):
        raise RuntimeError(f"{env_name} is not a valid role name")
    return value


def _url() -> str:
    url = os.environ.get("BM_MIGRATION_DATABASE_URL")
    if not url:
        secrets_dir = os.environ.get("BM_SECRETS_DIR")
        if secrets_dir and os.path.exists(os.path.join(secrets_dir, "bm_migration_database_url")):
            with open(os.path.join(secrets_dir, "bm_migration_database_url"), encoding="utf-8") as fh:
                url = fh.read().strip()
    if not url:
        raise RuntimeError("Set BM_MIGRATION_DATABASE_URL (schema owner role) to run migrations")
    return url


config = context.config
# Role names are available to migrations for GRANT/REVOKE statements.
config.attributes["app_role"] = _role("BM_DB_APP_ROLE", "bm_app")
config.attributes["ro_role"] = _role("BM_DB_READONLY_ROLE", "bm_readonly")


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        connection.execute(text(f"SET search_path TO {SCHEMA}"))
        connection.commit()  # SQLAlchemy 2 autobegins; close that transaction before Alembic opens its own
        context.configure(
            connection=connection,
            target_metadata=Base.metadata,
            version_table_schema=SCHEMA,
            include_schemas=True,
            compare_type=True,
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("Offline (SQL script) migrations are not supported; run against a database.")
run_migrations_online()
