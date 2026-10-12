# M12 — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py M12` → PASS (focused 12, protected 147, full 171), run against PostgreSQL 16
**Evidence bundle:** `evidence/M12/20261012T151936Z`, digest `82c4cdc5d161c9082909b6644ac42a0d9e479c7fbf8f642197e5d5adda6b2917`. Walkthrough: `evidence/M12/screenshots/`.

| Req | Result | Tests (M12-T…) |
|-----|--------|-------|
| BR-014 | Implemented | T003 |
| BR-017 | Implemented | T010 |
| ORD-001 | Implemented | T004, T011 |
| ORD-002 | Implemented | T009 |
| ORD-003 | Implemented | T009 |
| ORD-004 | Implemented | T001 |
| ORD-005 | Implemented | T002 |
| ORD-006 | Implemented | T004 |
| ORD-LC-001 | Implemented | T007 |
| ORD-LC-002 | Implemented | T005, T011 |
| ORD-LC-004 | Implemented | T003 |
| ORD-LC-005 | Implemented | T004, T008 |
| ORD-LC-006 | Implemented | T007, T008 |
| ORD-LC-008 | Implemented | T004 |
| CAP-DEL-ADV-001 | Deferred by design (advanced courier matching/consolidation) | T012 |
| DEL-001 | Implemented | T005, T011 |
| DEL-002 | Implemented | T006, T012 |
| V13-TRUST-002 | Implemented | T006, T012 |

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
| Payment confirmation uses a dev/test-only simulator until M13 provides verified provider callbacks; refunds are flagged (refund_required) for M17. |
