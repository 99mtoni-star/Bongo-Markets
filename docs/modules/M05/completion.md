# M05 — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py M05` → PASS (focused 17, protected 88, full 100), run against PostgreSQL 16
**Evidence bundle:** `evidence/M05/20261012T135832Z`, digest `a67abfbe58e6f8df1a79361854558a225eeaee39e4ccdc0f8ab9ca5404e4121a`. Walkthrough: `evidence/M05/screenshots/`.

| Req | Result | Tests (M05-T…) |
|-----|--------|-------|
| SEC-003 | Implemented | T001 |
| SEC-004 | Implemented (engine reads shop_users; shop tables and IDOR tests in M07) | T011 |
| SEC-AUD-004 | Implemented | T012 |
| SEC-COM-004 | Implemented | T013 |
| AUTH-001 | Implemented | T001 |
| AUTH-004 | Implemented | T017 |
| ACT-001 | Implemented | T009 |
| ACT-002 | Implemented | T009 |
| ACT-006 | Implemented | T009 |
| ACT-003 | Implemented | T007 |
| ACT-004 | Implemented | T009 |
| ACT-005 | **Deferred** to service-provider modules (catalogue tables designed in the data model) | — |
| ACT-008 | **Deferred**: object-level assignment authorization arrives with M07 shop objects and service jobs | — |
| ACT-009 | Implemented | T007 |
| ACT-010 | Implemented | T016 |
| AUTH-010 | Implemented | T008 |
| AUTH-011 | Implemented | T008 |
| AUTH-012 | Implemented | T004, T015 |
| AUTH-013 | Implemented | T011 |
| AUTH-014 | Implemented | T004 |
| AUTH-016 | Implemented | T004 |
| AUTH-015 | Implemented | T005 |
| AUTH-017 | Implemented | T005 |
| ID-003 | Process control: Design Ready gate + this module's design note | — |
| ID-009 | Implemented | T014 |
| AUTH-002 | Implemented | T002 |
| AUTH-003 | Implemented | T003 |
| AUTH-006 | Implemented | T007 |
| SEC-INV-002 | Implemented | T003, T017 |
| ACT-007 | Implemented | T010 |
| V13-REQ-007 | Implemented | T009 |
| V13-SEC-003 | Implemented | T006 |

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
| F-M05-001 | Low | IMP | RBAC role-table lookup used an f-string SQL query (caught by M02-T007) | Two literal queries | M02-T007 | Fixed |
| F-M05-002 | Low | TST | TOTP test clock was local to the M04 test module | Moved to shared conftest fixture | M05-T004..T015 | Fixed |
