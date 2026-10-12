# M06 — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py M06` → PASS (focused 10, protected 94, full 110), run against PostgreSQL 16
**Evidence bundle:** `evidence/M06/20261012T140747Z`, digest `6e773070241f52df43e0ce110f77a24f6a235be4965db3eb037d33a2dc37af1f`. Walkthrough: `evidence/M06/screenshots/`.

| Req | Result | Tests (M06-T…) |
|-----|--------|-------|
| NFR-004 | Implemented | T001, T010 |
| NFR-M07 | **Partial**: automated Chromium checks; Firefox/Safari/Edge manual check per release (M20) | T010 |
| NFR-M09 | Implemented | T007 |
| SEC-007 | Implemented | T002, T003, T006 |
| SEC-008 | Implemented | T004 |
| SEC-COM-005 | Documented procedure; legal deadlines to be confirmed before go-live (M20) | T009 |
| SEC-COM-007 | Documented rule + processor register; approvals required before go-live (M20) | T009 |
| SEC-SDLC-002 | Implemented | T008 |
| SEC-WEB-004 | Implemented | T004, T005 |
| SEC-INV-003 | Implemented | T004 |
| CAP-CHAT-001 | Gated (contract requirements recorded, no chat code) | T009 |

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
| F-M06-001 | High | DES | Header container reused CSS class 'bar' (progress bar), collapsing the header to 10 px | Renamed to 'topbar'; removed legacy rule | M06-T010 (brand visible) | Fixed |
| F-M06-002 | Medium | DES | Desktop nav still visible on phones (more specific legacy selector) | Media query uses equal specificity | M06-T010 (nav visibility per width) | Fixed |
