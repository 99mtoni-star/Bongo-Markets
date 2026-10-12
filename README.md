# Bongo Markets

A multi-shop marketplace: sellers open shops, buyers purchase across shops, and the platform takes a commission.
Built module by module (M01–M20) against **KAR-PROJ-SA-RTM-006 v1.3**, which covers 393 requirements.

**Stack:** Python 3.11+, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 15+ (every environment, including tests).

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env        # then set BM_SECRET_KEY and BM_DATABASE_URL
# one-time database setup: see docs/operations/deployment.md (db/bootstrap.sql)
BM_MIGRATION_DATABASE_URL=postgresql+psycopg://bm_owner:...@127.0.0.1:5432/bongomarkets alembic upgrade head
uvicorn app.main:app --reload
```

Open http://localhost:8000 for the system status page, and http://localhost:8000/docs for the API (the API docs are disabled in staging and production).

## Deployment order (single authoritative order — SEC-CFG-005)

Full runbook: `docs/operations/deployment.md`.

1. Verify release checksums: `python scripts/release.py verify` (SEC-CFG-006).
2. Back up: `python scripts/backup.py` (encrypted).
3. Migrate as the schema owner: `alembic upgrade head`.
4. Start the app as the least-privilege role `bm_app`.
5. Confirm that `/health/ready` returns 200 with `migrations: up-to-date`.

## Quality gate

```bash
export BM_TEST_ADMIN_URL=postgresql://postgres:<pw>@127.0.0.1:5432/postgres   # DB tests need a superuser
python scripts/gate.py M02                                   # lint → catalogue → migration review → focused → protected → full
python scripts/evidence.py --module M01 -- "python -m pytest -q"   # evidence bundle
```

Every test carries a Test ID (`@pytest.mark.tid("M01-T001")`), and each Test ID must exist exactly once in `tests/catalogue.yaml`.

## Layout

```
app/core     config, logging, module register
app/api      JSON API routers
app/web      server-rendered pages
app/db       SQLAlchemy base, session, foundation models
app/services domain services (audit, ...)
db/          bootstrap.sql (roles, schema, privileges)
migrations/  Alembic migrations (run as schema owner)
docs/        standards (STD-001..003), process, per-module design and completion notes
scripts/     quality gate, catalogue/migration checks, evidence, backup/restore, release checksums
tests/       pytest suite + authoritative Test Catalogue
```

## Module progress

See `/` in the running app, or `GET /api/v1/system/modules`.

## Decisions

- **2026-10-12 — Product name:** the system is called **Bongo Markets** (formerly "Kariakoo"). Source requirement IDs such as `KAR-PROJ-SA-RTM-006` keep their original names.
- **2026-10-12 — Database:** **PostgreSQL** replaces MariaDB/MySQL. The MariaDB-specific requirements map to these PostgreSQL equivalents:
  - NFR-DR-004 "binary logs": WAL archiving with point-in-time recovery.
  - SEC-DB-006 "dedicated MariaDB instance": a dedicated PostgreSQL instance.
  - Financial amounts use `NUMERIC(18,2)`.
