#!/usr/bin/env python3
"""Encrypted logical backup of the Bongo Markets database (NFR-007, NFR-DR-004, NFR-M03, SEC-KEY-005).

A daily full dump (pg_dump custom format) is encrypted with AES-256 (OpenSSL, PBKDF2)
before it touches long-term storage. Point-in-time recovery between dumps comes from
PostgreSQL WAL archiving (see docs/operations/backup-and-recovery.md).

Env:
  BM_BACKUP_DATABASE_URL  connection used for pg_dump (schema owner or a backup role)
  BM_BACKUP_KEY_FILE      file holding the encryption passphrase (from the secret manager)
  BM_BACKUP_DIR           output directory (default ./backups)
  BM_BACKUP_RETENTION_DAYS  delete encrypted backups older than this (default 30; NFR-DR-005)

Usage: python scripts/backup.py
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pgutil import parse, tool  # noqa: E402

CIPHER_ARGS = ["-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def current_revision(conn) -> str:
    out = subprocess.run(
        [tool("psql"), *conn.args(), "-tAc", "SELECT version_num FROM bm.alembic_version"],
        env=conn.env(), capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def run_backup(url: str, key_file: Path, out_dir: Path, retention_days: int = 30) -> Path:
    if not key_file.is_file() or key_file.stat().st_size < 32:
        raise SystemExit("backup key file missing or shorter than 32 bytes")
    conn = parse(url)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    base = out_dir / f"{conn.dbname}-{stamp}"
    plain = base.with_suffix(".dump")
    encrypted = base.with_suffix(".dump.enc")

    try:
        subprocess.run(
            [tool("pg_dump"), *conn.args(), "--format=custom", "--compress=6", "--file", str(plain)],
            env=conn.env(), check=True,
        )
        plain_sha = sha256_file(plain)
        subprocess.run(
            ["openssl", "enc", *CIPHER_ARGS, "-pass", f"file:{key_file}", "-in", str(plain), "-out", str(encrypted)],
            check=True,
        )
    finally:
        if plain.exists():
            plain.unlink()  # never leave an unencrypted dump on disk

    manifest = {
        "database": conn.dbname,
        "created_utc": stamp,
        "format": "pg_dump-custom+openssl-aes-256-cbc-pbkdf2",
        "alembic_revision": current_revision(conn),
        "plain_sha256": plain_sha,
        "encrypted_sha256": sha256_file(encrypted),
        "encrypted_bytes": encrypted.stat().st_size,
    }
    base.with_suffix(".json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    prune(out_dir, retention_days)
    return encrypted


def prune(out_dir: Path, retention_days: int) -> list[Path]:
    cutoff = time.time() - retention_days * 86400
    removed = []
    for enc in out_dir.glob("*.dump.enc"):
        if enc.stat().st_mtime < cutoff:
            for p in (enc, enc.with_suffix("").with_suffix(".json")):
                if p.exists():
                    p.unlink()
                    removed.append(p)
    return removed


def main() -> int:
    url = os.environ.get("BM_BACKUP_DATABASE_URL")
    key = os.environ.get("BM_BACKUP_KEY_FILE")
    if not url or not key:
        print("Set BM_BACKUP_DATABASE_URL and BM_BACKUP_KEY_FILE", file=sys.stderr)
        return 2
    out = run_backup(
        url, Path(key), Path(os.environ.get("BM_BACKUP_DIR", "backups")),
        int(os.environ.get("BM_BACKUP_RETENTION_DAYS", "30")),
    )
    print(f"BACKUP OK: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
