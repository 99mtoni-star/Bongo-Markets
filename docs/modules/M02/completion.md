# M02 — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py M02` → PASS (lint, catalogue, migration review, 20 focused, 28 protected, 37 full), run against PostgreSQL 16.15
**Evidence bundle:** `evidence/M02/20261012T130056Z`, digest `f7800569e7a78818093a593e6a7de4b40870924f668245f2a751697464deaa8d`. Demo output: `evidence/M02/demo-output.txt`

| Req | Result | Tests / notes |
|-----|--------|---------------|
| NFR-007 | Implemented | M02-T014, T015 |
| NFR-DR-004 | Implemented (PostgreSQL WAL = MariaDB binlog equivalent) | M02-T014, T018 |
| NFR-DR-008 | Implemented (flag + `payments_authoritative()`; M13 must consult it) | M02-T017 |
| NFR-M03 | Implemented (script + schedule; the scheduler itself is installed in M20) | M02-T014 |
| SEC-005 | Implemented | M02-T001, T002 |
| SEC-006 | Implemented | M02-T006, T007 |
| SEC-AUD-001 | Implemented | M02-T003, T004, T005 |
| SEC-CFG-005 | Implemented | M02-T020 |
| SEC-CFG-006 | Implemented | M02-T013 |
| SEC-DB-006 | **Deferred → M20** (production infrastructure) | runbook |
| SEC-KEY-002 | **Partial**: file-mounted secrets supported; secret-manager product chosen in M20 | M02-T019 |
| SEC-KEY-005 | **Partial**: backups encrypted; volume/export encryption in M20 | M02-T014, T015 |
| SEC-SDLC-004 | Implemented | M02-T008, T009, T012 |

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
| F-M02-001 | High | IMP | Migrations reported success but did not persist: the SQLAlchemy 2 autobegin transaction from `SET search_path` was never committed | Commit before Alembic opens its own transaction | M02-T008, T001 | Fixed |
| F-M02-002 | Low | TST | The drift test compared against the wrong default schema (owner's `search_path=bm`) | Connect with `search_path=public` during comparison | M02-T009 | Fixed |
| F-M02-003 | Low | DES | A wrong backup key surfaced as a raw OpenSSL traceback | Clear "REJECTED" message | M02-T015 | Fixed |
| F-M02-004 | Medium | DES | Post-restore inserts were first built with string quoting | Replaced with parameterized psycopg queries | M02-T017 | Fixed |

## Change request

- PostgreSQL is now mandatory in every environment, including tests. SQLite support has been removed (the schema uses PostgreSQL features: schemas, JSONB, triggers).
