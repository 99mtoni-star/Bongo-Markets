# Kariakoo Sokoni

A multi-shop marketplace: sellers open shops, buyers purchase across shops, and the platform takes a commission.
Built module by module (M01–M20) against **KAR-PROJ-SA-RTM-006 v1.3**, which covers 393 requirements.

**Stack:** Python 3.11+, FastAPI, SQLAlchemy 2, Alembic, MariaDB (SQLite is allowed only for local development and tests).

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env        # then set KAR_SECRET_KEY
uvicorn app.main:app --reload
```

Open http://localhost:8000 for the system status page, and http://localhost:8000/docs for the API (the API docs are disabled in staging and production).

## Deployment order (single authoritative order — SEC-CFG-005)

1. Verify the release SHA-256 checksum (SEC-CFG-006).
2. Provision configuration and secrets through environment variables. The app refuses to start in staging or production with unsafe values.
3. Take a database backup.
4. Run migrations (`alembic upgrade head`, from M02).
5. Start the app and confirm that `/health/ready` returns `ok`.

## Quality gate

```bash
python scripts/gate.py M01                                   # lint → catalogue → focused → protected → full
python scripts/evidence.py --module M01 -- "python -m pytest -q"   # evidence bundle
```

Every test carries a Test ID (`@pytest.mark.tid("M01-T001")`), and each Test ID must exist exactly once in `tests/catalogue.yaml`.

## Layout

```
app/core     config, logging, module register
app/api      JSON API routers
app/web      server-rendered pages
docs/        standards (STD-001..003), process, per-module design and completion notes
scripts/     quality gate, catalogue check, evidence bundle
tests/       pytest suite + authoritative Test Catalogue
```

## Module progress

See `/` in the running app, or `GET /api/v1/system/modules`.
