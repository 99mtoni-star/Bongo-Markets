# M09 — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py M09` → PASS (focused 8, protected 124, full 145), run against PostgreSQL 16
**Evidence bundle:** `evidence/M09/20261012T144112Z`, digest `e7a7994ff86252db3ddcae90389ffaf0b6127e67935f6344fa3e962fe879a0cb`. Walkthrough: `evidence/M09/screenshots/`.

| Req | Result | Tests (M09-T…) |
|-----|--------|-------|
| MKT-001 | Implemented (cross-shop listing; region/location filter — street-level discovery awaits approved location data) | T001, T002, T006 |
| MKT-002 | Implemented | T002 |
| MKT-003 | Implemented | T003, T007 |
| MKT-004 | Implemented | T005 |
| MKT-005 | Implemented | T005 |
| MKT-006 | Implemented | T004 |
| CAP-B2C-001 | **Deferred** (recorded in design note) | T008 |
| CAP-MOQ-001 | **Deferred** (recorded) | T008 |
| CAP-RFQ-001 | **Deferred** (recorded) | T008 |
| CAP-BRD-001 | Design recorded; implementation later under a contract | T008 |
| CAP-SPON-001 | **Deferred** (recorded; featured is editorial only) | T008 |
| CAP-UX-001 | **Deferred** (recorded) | T008 |
| V13-REQ-004 | **Deferred**: search seam + trigram/keyset indexes now; dedicated index later | T008 |

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
| F-M09-001 | Low | TST | ORM drift test flagged SQL-only expression/partial indexes | Explicit allow-list of reviewed SQL indexes | M02-T009 | Fixed |
