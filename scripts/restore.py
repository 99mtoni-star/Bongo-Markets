#!/usr/bin/env python3
"""Restore and restore-testing (NFR-007, NFR-DR-006, NFR-DR-008).

  test     Restore an encrypted backup into a throw-away database, verify it, then drop it.
           Run at least monthly and keep the JSON report as evidence (NFR-DR-006).
  restore  Restore into a fresh, empty target database after a disaster. Afterwards,
           payments are marked NON-authoritative until reconciled with the payment
           provider (NFR-DR-008).

Env:
  BM_RESTORE_ADMIN_URL  role allowed to CREATE/DROP DATABASE (DBA)
  BM_RESTORE_OWNER_URL  schema owner role; pg_restore runs as this role
  BM_BACKUP_KEY_FILE    decryption passphrase file

Usage:
  python scripts/restore.py test    backups/bongomarkets-20261012T010000Z.dump.enc
  python scripts/restore.py restore backups/<file>.dump.enc --target bongomarkets_restored
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backup import CIPHER_ARGS, sha256_file  # noqa: E402
from pgutil import PgConn, parse, tool  # noqa: E402

DB_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
EXPECTED_TABLES = {"alembic_version", "audit_logs", "system_flags"}


def _psql(conn: PgConn, sql: str, db: str | None = None) -> str:
    out = subprocess.run(
        [tool("psql"), *conn.args(db), "-v", "ON_ERROR_STOP=1", "-tAc", sql],
        env=conn.env(), capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def _decrypt_and_verify(enc: Path, key_file: Path, workdir: Path) -> tuple[Path, dict]:
    manifest_path = enc.with_suffix("").with_suffix(".json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if sha256_file(enc) != manifest["encrypted_sha256"]:
        raise SystemExit("REJECTED: encrypted backup checksum does not match its manifest")
    plain = workdir / "restore.dump"
    dec = subprocess.run(
        ["openssl", "enc", "-d", *CIPHER_ARGS, "-pass", f"file:{key_file}", "-in", str(enc), "-out", str(plain)],
        capture_output=True,
    )
    if dec.returncode != 0:
        raise SystemExit("REJECTED: backup could not be decrypted (wrong key or corrupted file)")
    if sha256_file(plain) != manifest["plain_sha256"]:
        raise SystemExit("REJECTED: decrypted dump checksum mismatch (wrong key or corrupted file)")
    return plain, manifest


def _restore_into(admin: PgConn, owner: PgConn, plain: Path, db: str) -> None:
    if not DB_NAME_RE.match(db):
        raise SystemExit("invalid target database name")
    _psql(admin, f'CREATE DATABASE "{db}" OWNER "{owner.user}" TEMPLATE template0')
    _psql(admin, f'REVOKE ALL ON DATABASE "{db}" FROM PUBLIC')
    subprocess.run(
        [tool("pg_restore"), *owner.args(db), "--exit-on-error", "--no-owner", str(plain)],
        env=owner.env(), check=True,
    )


def _verify(owner: PgConn, db: str, manifest: dict) -> dict:
    tables = set(_psql(owner, "SELECT tablename FROM pg_tables WHERE schemaname='bm'", db).split())
    revision = _psql(owner, "SELECT version_num FROM bm.alembic_version", db)
    # Table names come from the catalog and are restricted to plain identifiers before use.
    counts = {
        t: int(_psql(owner, f'SELECT count(*) FROM bm."{t}"', db))  # noqa: S608
        for t in sorted(tables) if DB_NAME_RE.match(t)
    }
    problems = []
    if not EXPECTED_TABLES <= tables:
        problems.append(f"missing tables: {sorted(EXPECTED_TABLES - tables)}")
    if revision != manifest["alembic_revision"]:
        problems.append(f"revision {revision} != manifest {manifest['alembic_revision']}")
    trigger = _psql(owner, "SELECT count(*) FROM pg_trigger WHERE tgname='audit_logs_append_only'", db)
    if trigger != "1":
        problems.append("audit append-only trigger missing after restore")
    return {"tables": sorted(tables), "row_counts": counts, "revision": revision, "problems": problems}


def restore_test(enc: Path, admin_url: str, owner_url: str, key_file: Path) -> dict:
    admin, owner = parse(admin_url), parse(owner_url)
    scratch = f"bm_restore_test_{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
    started = datetime.now(UTC).isoformat(timespec="seconds")
    with tempfile.TemporaryDirectory() as tmp:
        plain, manifest = _decrypt_and_verify(enc, key_file, Path(tmp))
        try:
            _restore_into(admin, owner, plain, scratch)
            result = _verify(owner, scratch, manifest)
        finally:
            _psql(admin, f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)')
    report = {
        "type": "restore-test", "backup": enc.name, "started_utc": started,
        "finished_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "backup_created_utc": manifest["created_utc"], **result,
        "result": "PASS" if not result["problems"] else "FAIL",
    }
    enc.with_name(enc.name.replace(".dump.enc", f".restore-test-{report['finished_utc'][:10]}.json")).write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


def restore(enc: Path, admin_url: str, owner_url: str, key_file: Path, target: str) -> dict:
    admin, owner = parse(admin_url), parse(owner_url)
    with tempfile.TemporaryDirectory() as tmp:
        plain, manifest = _decrypt_and_verify(enc, key_file, Path(tmp))
        _restore_into(admin, owner, plain, target)
    result = _verify(owner, target, manifest)
    # NFR-DR-008: stored payment states may be stale relative to the provider.
    reason = f"restored from {enc.name} at {datetime.now(UTC).isoformat(timespec='seconds')}"
    import psycopg

    with psycopg.connect(host=owner.host, port=owner.port, user=owner.user, password=owner.password,
                         dbname=target) as conn:
        conn.execute(
            "INSERT INTO bm.system_flags(key, value, reason, updated_by) "
            "VALUES ('payments_reconciliation_required', 'true', %s, 'restore') "
            "ON CONFLICT (key) DO UPDATE SET value='true', reason=EXCLUDED.reason, "
            "updated_at=now(), updated_by='restore'",
            (reason,),
        )
        conn.execute(
            "INSERT INTO bm.audit_logs(category, action, actor_type, details) "
            "VALUES ('SECURITY', 'database.restored', 'restore', jsonb_build_object('backup', %s::text))",
            (enc.name,),
        )
    return {"type": "restore", "target": target, **result, "result": "PASS" if not result["problems"] else "FAIL"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["test", "restore"])
    ap.add_argument("backup", type=Path)
    ap.add_argument("--target")
    args = ap.parse_args()
    admin, owner, key = (os.environ.get(k) for k in ("BM_RESTORE_ADMIN_URL", "BM_RESTORE_OWNER_URL",
                                                       "BM_BACKUP_KEY_FILE"))
    if not (admin and owner and key):
        print("Set BM_RESTORE_ADMIN_URL, BM_RESTORE_OWNER_URL and BM_BACKUP_KEY_FILE", file=sys.stderr)
        return 2
    if args.mode == "test":
        report = restore_test(args.backup, admin, owner, Path(key))
    else:
        if not args.target:
            print("--target is required for restore", file=sys.stderr)
            return 2
        report = restore(args.backup, admin, owner, Path(key), args.target)
    print(json.dumps(report, indent=2))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
