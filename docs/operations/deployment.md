# Deployment Runbook (authoritative order: SEC-CFG-005)

This is the one deployment order. The README repeats it verbatim, and test M02-T020 keeps the two in sync.

## First-time database setup (DBA, once per environment)

```bash
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -v db_name=bongomarkets \
  -v owner_role=bm_owner -v owner_pw="$OWNER_PW" \
  -v app_role=bm_app -v app_pw="$APP_PW" \
  -v ro_role=bm_readonly -v ro_pw="$RO_PW" -f db/bootstrap.sql
```

Production runs on a dedicated PostgreSQL instance used only by Bongo Markets (SEC-DB-006). Passwords come from the secret manager and are never typed into shell history.

## Every release

1. **Verify release checksums.** Run `python scripts/release.py verify`. Stop on any MISMATCH, MISSING or UNLISTED file (SEC-CFG-006).
2. **Back up.** Run `python scripts/backup.py`. This takes an encrypted full dump and records the current migration revision.
3. **Migrate.** As the schema owner, run `BM_MIGRATION_DATABASE_URL=... alembic upgrade head`. Migrations flagged as sensitive must already carry `Sensitive-Review: approved by ...` (SEC-SDLC-004). `python scripts/check_migrations.py` enforces this in the gate.
4. **Start the application** as the least-privilege app role (`BM_DATABASE_URL` uses `bm_app`).
5. **Confirm readiness.** `GET /health/ready` must return `200` with `database: ok` and `migrations: up-to-date`.

## Rollback

Restore the dump taken in step 2 (see backup-and-recovery.md), then redeploy the previous release.
