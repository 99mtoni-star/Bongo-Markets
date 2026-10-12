# M07 — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py M07` → PASS (focused 13, protected 106, full 123), run against PostgreSQL 16
**Evidence bundle:** `evidence/M07/20261012T142009Z`, digest `8b6d0b588b8b2e3354fdb4a09ccf006c1e65fe4f28a6aa3b9efca5a50f7e01cf`. Walkthrough: `evidence/M07/screenshots/`.

| Req | Result | Tests (M07-T…) |
|-----|--------|-------|
| BR-001 | Implemented | T001 |
| BR-003 | Implemented | T003 |
| BR-004 | Implemented | T001, T003 |
| BR-005 | Implemented | T007, T008 |
| BR-006 | Implemented | T004 |
| BR-007 | Implemented | T006 |
| BR-008 | Implemented | T005, T006 |
| BR-009 | Implemented (shop page scoped to the shop; product-level tests in M08) | T011 |
| BR-010 | Implemented in M08 (shop categories derived from the shop's products; tests M08) | — |
| BR-013 | Implemented | T002, T012 |
| BR-015 | Implemented (no API can set payment state; enforced further in M13) | T012 |
| SHOP-001 | Implemented | T001, T013 |
| SHOP-002 | Implemented | T001, T005, T007 |
| SHOP-003 | Implemented | T001 |
| SHOP-004 | Implemented | T004, T013 |
| SHOP-006 | Implemented | T009 |
| SHOP-007 | Implemented | T011 |
| SHOP-008 | Implemented | T011 |
| CAP-VER-001 | Implemented | T010 |

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
| F-M07-001 | Low | IMP | Ownership trigger initializer referenced a column absent on one table | Initializer removed | M07-T003 | Fixed |
| F-M07-002 | Low | TST | Catalogue YAML broke on a colon in a title | All titles quoted | M01-T009 | Fixed |
| F-M07-003 | Low | DES | Unstyled selects and stacked inline admin buttons (visual review) | CSS rules for select and inline forms | visual | Fixed |
| F-M07-004 | Low | PRC | Finish script ignored a failing evidence step (lint) and still committed | pipefail + stop on non-zero; evidence re-run clean | this bundle | Fixed |
