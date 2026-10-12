# M04 — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py M04` → PASS (lint, catalogue, migration review, 21 focused, 71 protected, 83 full), run against PostgreSQL 16.15
**Evidence bundle:** `evidence/M04/20261012T134408Z`, digest `def39b3934e0199f0a38f7c7b85db8df72f3f809685ba6ee43562df77fa25abe`. Walkthrough: `evidence/M04/screenshots/`

| Req | Result | Tests |
|-----|--------|-------|
| AUTH-004 | Implemented | T003, T007 |
| AUTH-005 (v1.11) | Implemented | T007 |
| AUTH-008 (v1.11) | Implemented | T013 |
| SEC-002 | Implemented | T007 |
| SEC-IR-003 | **Partial**: accounts, sessions and payments covered; shop suspension in M07; provider key rotation in M13/M20 | T015, T017 |
| SEC-MFA-002 | Implemented (actions owned by later modules use the same step-up) | T005, T006, T008, T020, T021 |
| SEC-MFA-004 | Implemented | T001, T002, T004, T014, T019 |
| ID-004 | Implemented | T003, T009 |
| ID-007 | Implemented | T013, T014 |
| AUTH-008 (v1.12.2) | Implemented | T005 |
| AUTH-009 (v1.12.2) | Implemented | T007, T018 |
| ID-005 | Implemented | T008, T009 |
| ID-008 | Implemented | T008, T010 |
| ID-010 | Implemented | T002, T008, T018 |
| ID-011 | Implemented | T011 |
| ID-012 | Implemented | T012 |
| AUTH-005 (v1.12.2) | Implemented | T013 |
| V13-SEC-002 | **Partial**: replay guard and TOTP step replay done; webhook signature verification in M13 | T001, T016 |

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
| F-M04-001 | Low | TST | The test TOTP helper waited for real 30 s windows (4 min suite) | Server-side TOTP clock injectable in tests | all M04 tests | Fixed |
| F-M04-002 | Low | TST | Duplicate session cookies in the test jar when switching devices | `switch()` helper | M04-T018 | Fixed |
| F-M04-003 | Info | PRC | Partial M04 work from an interrupted session was found uncommitted; it was reviewed line by line before use | Reviewed, tested, committed | full suite | Closed |
