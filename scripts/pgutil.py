"""Helpers for invoking PostgreSQL client tools without leaking passwords on the command line."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from urllib.parse import unquote, urlparse


@dataclass(frozen=True)
class PgConn:
    host: str
    port: int
    user: str
    password: str
    dbname: str

    def args(self, dbname: str | None = None) -> list[str]:
        return ["-h", self.host, "-p", str(self.port), "-U", self.user, "-d", dbname or self.dbname]

    def env(self) -> dict[str, str]:
        # The password travels via the environment, never argv (visible in `ps`).
        return {**os.environ, "PGPASSWORD": self.password, "PGCONNECT_TIMEOUT": "10"}

    def sqlalchemy_url(self, dbname: str | None = None) -> str:
        from urllib.parse import quote

        return (
            f"postgresql+psycopg://{quote(self.user, safe='')}:{quote(self.password, safe='')}"
            f"@{self.host}:{self.port}/{dbname or self.dbname}"
        )


def parse(url: str) -> PgConn:
    u = urlparse(url.replace("postgresql+psycopg://", "postgresql://", 1))
    if u.scheme != "postgresql":
        raise ValueError("expected a postgresql:// URL")
    return PgConn(
        host=u.hostname or "127.0.0.1",
        port=u.port or 5432,
        user=unquote(u.username or ""),
        password=unquote(u.password or ""),
        dbname=(u.path or "/").lstrip("/") or "postgres",
    )


def tool(name: str) -> str:
    """Locate a PostgreSQL client binary (PATH first, then the standard Debian/Ubuntu location)."""
    found = shutil.which(name)
    if found:
        return found
    for version in ("17", "16", "15"):
        candidate = f"/usr/lib/postgresql/{version}/bin/{name}"
        if os.path.exists(candidate):
            return candidate
    raise FileNotFoundError(f"{name} not found; install the PostgreSQL client tools")
