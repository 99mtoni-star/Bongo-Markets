# M03 — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py M03` → PASS (lint, catalogue, migration review, 25 focused, 51 protected, 62 full), run against PostgreSQL 16.15
**Evidence bundle:** `evidence/M03/20261012T131607Z`, digest `f651c1e65fc197f23e11ec29f98f1c37e0aee67ab6d94334af83970b3ffbf123`. Browser walkthrough: `evidence/M03/screenshots/`

| Req | Result | Tests |
|-----|--------|-------|
| AUTH-001 | Implemented | T001, T015, T019 |
| AUTH-002 | Implemented | T002 |
| AUTH-003 | Implemented | T001 |
| AUTH-006 | Implemented | T003, T004, T011, T021 |
| AUTH-007 (v1.11) | Implemented | T007 |
| AUTH-007 (v1.12.2) | Implemented (gate enforces Design Ready for every module, including M05) | T023 |
| SEC-001, SEC-PWD-001 | Implemented (parameters in `docs/security/password-hashing.md`) | T001 |
| SEC-009 | Implemented | T008, T009 |
| SEC-010 | Implemented | T014, T024 |
| SEC-014 | Implemented | T012, T013 |
| SEC-PWD-003 | **Partial**: offline common-password list; breach-corpus lookup in M20 | T010 |
| SEC-PWD-004 | Implemented | T010 |
| SEC-PWD-005 | Implemented | T006, T007, T011 |
| SEC-PWD-006 | Implemented | T011 |
| SEC-WEB-002 | Implemented | T003, T020 |
| SEC-WEB-003 | Implemented | T016 |
| ID-001 | Implemented | T017, T022 |
| ID-002 | Implemented | T018 |
| ID-006 | Implemented | T005, T006, T011, T025 |
| SEC-INV-007 | Implemented | T017 |

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
| F-M03-001 | Low | TST | The M01 secret scanner flagged the enum label `RESET_PASSWORD = "RESET_PASSWORD"` | Pattern ignores uppercase enum labels; still catches real values | M01-T011 | Fixed |
| F-M03-002 | Low | TST | The immutable-id test expected only a privilege error; PostgreSQL rejects `GENERATED ALWAYS` identity updates even earlier | Test accepts either refusal | M03-T017 | Fixed |

## Open items for later modules

- **M04:** MFA, a list of active sessions with per-device revocation, and step-up authentication.
- **M06:** site-wide navigation and the final CSRF policy (form tokens and the Origin guard are already in place).
- **M20:** a real SMS/email provider adapter (production refuses to start with the dev notifier), trusted proxy IP handling, a breach-password API, and tuning of the Argon2 cost on production hardware.
