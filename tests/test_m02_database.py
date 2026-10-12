"""Module 02 – Database Schema na Migrations (PostgreSQL)."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest
from psycopg import errors

from tests.conftest import ROOT, run_alembic


# --------------------------------------------------------------------------- SEC-005
@pytest.mark.tid("M02-T001")
def test_app_role_has_no_ddl_privileges(app_conn):
    for ddl in ("CREATE TABLE bm.hack(id int)", "DROP TABLE bm.system_flags",
                "ALTER TABLE bm.system_flags ADD COLUMN x int", "CREATE SCHEMA hack",
                "CREATE TABLE public.hack(id int)"):
        with pytest.raises(errors.InsufficientPrivilege):
            app_conn.execute(ddl)


@pytest.mark.tid("M02-T002")
def test_roles_are_not_superusers_and_readonly_cannot_write(pg, owner_conn):
    rows = owner_conn.execute(
        "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = ANY(%s)",
        (list(pg.roles.values()),),
    ).fetchall()
    assert len(rows) == 3 and all(not s and not d and not r for _, s, d, r in rows)
    with psycopg.connect(pg.ro_url.replace("+psycopg", ""), autocommit=True) as ro:
        assert ro.execute("SELECT count(*) FROM bm.system_flags").fetchone()[0] >= 0
        with pytest.raises((errors.ReadOnlySqlTransaction, errors.InsufficientPrivilege)):
            ro.execute("INSERT INTO bm.system_flags(key, value, updated_by) VALUES ('x','y','z')")


# --------------------------------------------------------------------------- SEC-AUD-001
@pytest.mark.tid("M02-T003")
def test_audit_log_is_append_only_for_app(app_conn):
    app_conn.execute("INSERT INTO bm.audit_logs(category, action, actor_type) VALUES ('SECURITY','t.insert','test')")
    with pytest.raises(errors.InsufficientPrivilege):
        app_conn.execute("UPDATE bm.audit_logs SET action = 'tampered'")
    with pytest.raises(errors.InsufficientPrivilege):
        app_conn.execute("DELETE FROM bm.audit_logs")
    with pytest.raises(errors.InsufficientPrivilege):
        app_conn.execute("TRUNCATE bm.audit_logs")


@pytest.mark.tid("M02-T004")
def test_audit_trigger_blocks_even_the_owner(owner_conn):
    owner_conn.execute("INSERT INTO bm.audit_logs(category, action, actor_type) VALUES ('GENERAL','t.own','test')")
    for stmt in ("UPDATE bm.audit_logs SET action='x'", "DELETE FROM bm.audit_logs", "TRUNCATE bm.audit_logs"):
        with pytest.raises(psycopg.Error, match="append-only"):
            owner_conn.execute(stmt)


@pytest.mark.tid("M02-T005")
def test_audit_service_records_and_redacts(pg, make_settings):
    from sqlalchemy import select

    from app.core.logging import request_id_var
    from app.db.models import AuditCategory, AuditLog
    from app.db.session import session_factory
    from app.services.audit import record

    settings = make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url)
    token = request_id_var.set("rid777")
    try:
        with session_factory(settings)() as s:
            record(s, action="test.audit", category=AuditCategory.FINANCIAL, actor_user_id=5,
                   entity_type="order", entity_id=42, details={"amount": "1000.00", "card_token": "tok_secret"})
            s.commit()
            row = s.execute(select(AuditLog).where(AuditLog.action == "test.audit")).scalar_one()
    finally:
        request_id_var.reset(token)
    assert row.category == "FINANCIAL" and row.entity_id == "42" and row.request_id == "rid777"
    assert row.details == {"amount": "1000.00", "card_token": "[REDACTED]"}
    assert row.occurred_at.tzinfo is not None


# --------------------------------------------------------------------------- SEC-006
@pytest.mark.tid("M02-T006")
def test_sql_injection_payload_is_inert(pg, make_settings):
    from sqlalchemy import func, select

    from app.db.models import SystemFlag
    from app.db.session import session_factory

    settings = make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url)
    payload = "x'; DROP TABLE bm.system_flags; --"
    with session_factory(settings)() as s:
        s.add(SystemFlag(key="inj_test", value=payload, updated_by="test"))
        s.commit()
        found = s.execute(select(SystemFlag.value).where(SystemFlag.key == "inj_test")).scalar_one()
        assert found == payload
        assert s.execute(select(func.count()).select_from(SystemFlag)).scalar_one() >= 1


@pytest.mark.tid("M02-T007")
def test_no_string_built_sql_in_app():
    import re

    bad = re.compile(r"""(?:execute|text)\(\s*f["']|(?:execute|text)\([^)]*%\s*\(|(?:execute|text)\([^)]*\.format\(""")
    offenders = [str(p) for p in (ROOT / "app").rglob("*.py") if bad.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


# --------------------------------------------------------------------------- schema / migrations
@pytest.mark.tid("M02-T008")
def test_migrations_upgrade_downgrade_roundtrip(pg):
    assert run_alembic(pg.owner_url, "downgrade", "base").returncode == 0
    res = run_alembic(pg.owner_url, "upgrade", "head")
    assert res.returncode == 0, res.stderr
    assert "0001" in run_alembic(pg.owner_url, "current").stdout


@pytest.mark.tid("M02-T009")
def test_models_match_migrations(pg):
    """The ORM metadata and the migrated schema must not drift."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine

    from app.db import models  # noqa: F401
    from app.db.base import Base

    # Compare with an explicit schema: the owner role defaults to search_path=bm, which would
    # make the dialect treat "bm" as the default (unnamed) schema.
    engine = create_engine(pg.owner_url, connect_args={"options": "-csearch_path=public"})
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"include_schemas": True, "compare_type": True,
                                                     "version_table_schema": "bm",
                                                     "include_name": lambda n, t, p: t != "schema" or n == "bm"})
        diff = [d for d in compare_metadata(ctx, Base.metadata) if "alembic_version" not in str(d)]
    engine.dispose()
    assert diff == []


@pytest.mark.tid("M02-T010")
def test_money_type_is_fixed_precision(owner_conn):
    from app.db.base import Money

    assert Money.precision == 18 and Money.scale == 2 and Money.asdecimal
    value = owner_conn.execute("SELECT (0.1::numeric(18,2) + 0.2::numeric(18,2))").fetchone()[0]
    assert value == Decimal("0.30")


@pytest.mark.tid("M02-T011")
def test_readiness_reports_database(db_client):
    r = db_client.get("/health/ready")
    body = r.json()
    assert r.status_code == 200, body
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["migrations"] == "up-to-date"
    assert body["checks"]["server"].startswith("PostgreSQL")


# --------------------------------------------------------------------------- SEC-SDLC-004
@pytest.mark.tid("M02-T012")
def test_sensitive_migrations_require_review(tmp_path):
    from scripts.check_migrations import check

    assert check() == []
    (tmp_path / "0002_users.py").write_text('"""add users\n\nSensitive-Review: not-applicable\n"""\n'
                                            'op.create_table("users", sa.Column("email"))\n')
    (tmp_path / "0003_misc.py").write_text('"""add colours\n"""\nop.create_table("colours")\n')
    problems = check(tmp_path)
    assert len(problems) == 1 and "0002_users.py" in problems[0]


# --------------------------------------------------------------------------- SEC-CFG-006
@pytest.mark.tid("M02-T013")
def test_release_checksum_verification(tmp_path):
    from scripts.release import make, verify

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "a.py").write_text("print(1)\n")
    (tmp_path / "b.sql").write_text("select 1;\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    make(tmp_path)
    assert verify(tmp_path) == []
    (tmp_path / "b.sql").write_text("drop table users;\n")  # tampered after release
    assert verify(tmp_path) == ["MISMATCH b.sql"]


# --------------------------------------------------------------------------- backups
@pytest.fixture
def backup_key(tmp_path):
    key = tmp_path / "backup.key"
    key.write_text(secrets.token_urlsafe(48))
    key.chmod(0o600)
    return key


@pytest.mark.tid("M02-T014")
def test_backup_is_encrypted_and_restore_test_passes(pg, tmp_path, backup_key):
    from scripts.backup import run_backup
    from scripts.restore import restore_test

    enc = run_backup(pg.owner_url, backup_key, tmp_path / "b")
    assert enc.name.endswith(".dump.enc") and not list((tmp_path / "b").glob("*.dump"))
    assert not enc.read_bytes().startswith(b"PGDMP")  # pg_dump magic must not be visible
    assert enc.read_bytes()[:8] == b"Salted__"
    manifest = json.loads(enc.with_suffix("").with_suffix(".json").read_text())
    assert manifest["alembic_revision"] == "0001"
    report = restore_test(enc, pg.admin_url, pg.owner_url, backup_key)
    assert report["result"] == "PASS", report
    assert {"audit_logs", "system_flags", "alembic_version"} <= set(report["tables"])


@pytest.mark.tid("M02-T015")
def test_restore_rejects_wrong_key_and_tampering(pg, tmp_path, backup_key):
    from scripts.backup import run_backup
    from scripts.restore import restore_test

    enc = run_backup(pg.owner_url, backup_key, tmp_path / "b")
    wrong = tmp_path / "wrong.key"
    wrong.write_text(secrets.token_urlsafe(48))
    with pytest.raises((SystemExit, subprocess.CalledProcessError)):
        restore_test(enc, pg.admin_url, pg.owner_url, wrong)
    data = bytearray(enc.read_bytes())
    data[-1] ^= 0xFF
    enc.write_bytes(bytes(data))
    with pytest.raises(SystemExit, match="checksum"):
        restore_test(enc, pg.admin_url, pg.owner_url, backup_key)


@pytest.mark.tid("M02-T016")
def test_backup_retention_prunes_old_files(tmp_path):
    from scripts.backup import prune

    old = tmp_path / "db-20200101T000000Z.dump.enc"
    old.write_bytes(b"x")
    old.with_suffix("").with_suffix(".json").write_text("{}")
    new = tmp_path / "db-20990101T000000Z.dump.enc"
    new.write_bytes(b"x")
    os.utime(old, (0, 0))
    removed = prune(tmp_path, 30)
    assert old in removed and new.exists() and not old.exists()


@pytest.mark.tid("M02-T017")
def test_disaster_restore_marks_payments_non_authoritative(pg, tmp_path, backup_key, make_settings):
    from scripts.backup import run_backup
    from scripts.pgutil import parse
    from scripts.restore import _psql, restore

    enc = run_backup(pg.owner_url, backup_key, tmp_path / "b")
    target = "bm_dr_drill"
    admin = parse(pg.admin_url)
    _psql(admin, f'DROP DATABASE IF EXISTS "{target}" WITH (FORCE)')
    try:
        report = restore(enc, pg.admin_url, pg.owner_url, backup_key, target)
        assert report["result"] == "PASS"
        from app.db.session import session_factory
        from app.services.audit import payments_authoritative

        app_url = pg.app_url.rsplit("/", 1)[0] + f"/{target}"
        _psql(admin, f'GRANT CONNECT ON DATABASE "{target}" TO "{pg.roles["app"]}"')
        with session_factory(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=app_url))() as s:
            assert payments_authoritative(s) is False
    finally:
        from app.db.session import _engine_for

        _engine_for.cache_clear()
        _psql(admin, f'DROP DATABASE IF EXISTS "{target}" WITH (FORCE)')


@pytest.mark.tid("M02-T018")
def test_pitr_configuration_check(pg):
    from scripts.check_pitr import check

    # The test cluster is configured with WAL archiving; production must pass the same check.
    assert check(pg.admin_url) == []


# --------------------------------------------------------------------------- SEC-KEY-002 / SEC-CFG-005
@pytest.mark.tid("M02-T019")
def test_secrets_can_be_loaded_from_secret_files(tmp_path, monkeypatch):
    (tmp_path / "bm_database_url").write_text("postgresql+psycopg://u:filepw@db/x")
    (tmp_path / "bm_secret_key").write_text("k" * 40)
    script = (
        "from app.core.config import Settings;"
        "s=Settings(_env_file=None);"
        "print(s.database_url.get_secret_value()); print(len(s.secret_key.get_secret_value()))"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("BM_")}
    env["BM_SECRETS_DIR"] = str(tmp_path)
    out = subprocess.run([sys.executable, "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["postgresql+psycopg://u:filepw@db/x", "40"]


@pytest.mark.tid("M02-T020")
def test_single_authoritative_deployment_order():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "operations" / "deployment.md").read_text(encoding="utf-8")
    steps = ["release.py verify", "backup.py", "alembic upgrade head", "/health/ready"]
    sections = (readme[readme.index("## Deployment order"):], runbook[runbook.index("## Every release"):])
    for doc in sections:
        positions = [doc.find(s) for s in steps]
        assert all(p >= 0 for p in positions) and positions == sorted(positions), positions
    assert Path(ROOT / "db" / "bootstrap.sql").exists()
