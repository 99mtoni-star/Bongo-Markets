# M11 — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py M11` → PASS (focused 8, protected 147, full 171), run against PostgreSQL 16
**Evidence bundle:** `evidence/M11/20261012T151001Z`, digest `276fadee0f91598c3b74be1fc20bc69a9668767c168064c974491f88a7acd9b4`. Walkthrough: `evidence/M11/screenshots/`.

| Req | Result | Tests (M11-T…) |
|-----|--------|-------|
| BR-018 | Implemented | T001 |
| CART-001 | Implemented | T001, T003, T006, T008 |
| CART-002 | Implemented | T001 |
| CART-003 | Implemented | T002, T003, T005 |

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
| Checkout also creates the M12 orders (one per shop); COD is disabled until M14. |
