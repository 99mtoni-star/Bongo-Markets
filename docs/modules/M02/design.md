# M02 — Database Schema na Migrations: Design

Change request (2026-10-12): **PostgreSQL** replaces MariaDB. MariaDB-specific requirements map to their PostgreSQL equivalents (see README "Decisions").

## Scope

| Req | Summary | Control |
|-----|---------|---------|
| NFR-007 | Scheduled, encrypted backups with restore testing | `scripts/backup.py`, `scripts/restore.py test` |
| NFR-DR-004 | Daily full backup + PITR (MariaDB binlogs) | daily `pg_dump`; WAL archiving; `scripts/check_pitr.py` |
| NFR-DR-008 | Reconcile payments after recovery | `restore` sets `payments_reconciliation_required`; `payments_authoritative()` |
| NFR-M03 | Automated daily backup | cron example in the runbook |
| SEC-005 | Least-privilege DB account | `db/bootstrap.sql`: owner / app / read-only roles |
| SEC-006 | Validation + parameterized queries | SQLAlchemy ORM only; source scan test |
| SEC-AUD-001 | Audit append-only; app has no UPDATE/DELETE | REVOKE + trigger (blocks every role) |
| SEC-CFG-005 | One authoritative deployment order | `docs/operations/deployment.md` = README |
| SEC-CFG-006 | Verify release SHA-256 before deploy | `scripts/release.py make/verify` |
| SEC-DB-006 | Dedicated DB instance in production | **Deferred to M20** (infrastructure); documented in the runbook |
| SEC-KEY-002 | Secrets in an approved secret manager | **Partial**: `BM_SECRETS_DIR` file-mounted secrets supported; choice of secret manager in M20 |
| SEC-KEY-005 | Encrypted backups/volumes/exports | AES-256 backups; volume encryption is **deferred to M20** (infrastructure) |
| SEC-SDLC-004 | Explicit review of sensitive migrations | `Sensitive-Review:` line enforced by `scripts/check_migrations.py` in the gate |

## Data model

- Schema `bm`, owned by `bm_owner`. Stable constraint naming convention.
- `audit_logs`: identity PK, `occurred_at timestamptz`, `category` check (SECURITY/FINANCIAL/GENERAL), action, actor, entity, shop, request_id, `details jsonb`. Indexed by entity, time and actor. Triggers reject UPDATE, DELETE and TRUNCATE.
- `system_flags`: key/value operational switches.
- Money type `NUMERIC(18,2)` is defined for every later module (FIN-LED-006).
- Sessions are UTC, with a `statement_timeout` of 15 s.

## Threats → controls

| Threat | Control |
|---|---|
| App compromise used to alter schema | App role has no DDL; `public` schema locked down |
| Tampering with audit history | REVOKE + trigger; tests cover the app and the owner |
| SQL injection | ORM with bound parameters; scan for f-string/format SQL |
| Stolen backup | AES-256 encryption; plaintext never left on disk; checksums |
| Corrupted or wrong-key restore | Checksum verified before and after decryption; restore aborts |
| Stale payment state after DR | Reconciliation flag; payments non-authoritative |
| Tampered release | SHA-256 manifest verified before migrate/deploy |
| Credential leaks via `ps` | DB passwords passed to CLI tools through the environment, never argv |

Design Ready: YES — Claude (developer), 2026-10-12 UTC
