#!/usr/bin/env python3
"""Verify the server is configured for point-in-time recovery (NFR-DR-004).

Checks: wal_level >= replica, archive_mode on, an archive_command set, and no
recent archiving failures. Usage: BM_BACKUP_DATABASE_URL=... python scripts/check_pitr.py
"""

from __future__ import annotations

import os
import sys

import psycopg


def check(url: str) -> list[str]:
    url = url.replace("postgresql+psycopg://", "postgresql://", 1)
    problems = []
    with psycopg.connect(url) as conn:
        settings = dict(conn.execute(
            "SELECT name, setting FROM pg_settings WHERE name IN ('wal_level','archive_mode','archive_command')"
        ).fetchall())
        if settings.get("wal_level") not in ("replica", "logical"):
            problems.append(f"wal_level is {settings.get('wal_level')}, need replica or logical")
        if settings.get("archive_mode") not in ("on", "always"):
            problems.append("archive_mode is off")
        if not settings.get("archive_command") or settings.get("archive_command") == "(disabled)":
            problems.append("archive_command is not set")
        row = conn.execute(
            "SELECT failed_count, last_failed_time, last_archived_time FROM pg_stat_archiver"
        ).fetchone()
        if row and row[1] and (row[2] is None or row[1] > row[2]):
            problems.append(f"WAL archiving is failing (last failure {row[1]})")
    return problems


def main() -> int:
    url = os.environ.get("BM_BACKUP_DATABASE_URL")
    if not url:
        print("Set BM_BACKUP_DATABASE_URL", file=sys.stderr)
        return 2
    problems = check(url)
    print("PITR CHECK:", "PASS" if not problems else "FAIL")
    for p in problems:
        print("  -", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
