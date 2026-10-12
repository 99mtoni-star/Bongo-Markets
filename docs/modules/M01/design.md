# M01 — Project Setup na Configuration: Design

## Scope (allocated requirements)

| Req | Summary | Planned control |
|-----|---------|-----------------|
| DEV-001 | Design Ready before coding | STD-001 + this note |
| DEV-002 | Developer Complete per STD-002 | `scripts/gate.py`, STD-002 |
| DEV-003 | Findings classified | STD-003 log format |
| DEV-004 | Test ID unique in catalogue | `tests/catalogue.yaml`, `scripts/check_catalogue.py`, conftest enforcement |
| DEV-005 | Focused tests, then full regression | gate order; `protected` marker derived from catalogue |
| DEV-006 | Evidence bundle | `scripts/evidence.py` (UTC timestamps, versions, exit codes, SHA-256, bundle digest) |
| DEV-007 | Developer complete ≠ closure | status lifecycle in `app/core/modules.py`, STD-002 |
| DEV-008 | Controlled parallel work | `docs/process/workflow.md` |

Cross-cutting foundations laid here and finalized in M20: environment-based configuration with no hard-coded secrets (NFR-005), controlled error handling and health probes (NFR-003), log redaction (NFR-008), and security headers.

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/health/live` | none | Liveness |
| GET | `/health/ready` | none | Readiness (a DB check is added in M02) |
| GET | `/api/v1/system/info` | none | Name, version, environment (no secrets) |
| GET | `/api/v1/system/modules` | none | Module progress |
| GET | `/` | none | Status page (Swahili, no JavaScript) |

## Threats → controls

- **Secret leakage:** `SecretStr`, redacted logs, info endpoint omits DB URL, and a source scan test (M01-T011).
- **Unsafe production config:** the validator refuses weak secret, debug mode, non-MariaDB DB and wildcard hosts.
- **Information disclosure through errors:** a generic 500 body; details go only to the logs.
- **Host-header attacks:** `TrustedHostMiddleware`.
- **Clickjacking/XSS:** CSP, `X-Frame-Options: DENY`, every value escaped, no scripts on the page.
- **Log injection via request ID:** only alphanumeric IDs of 64 characters or fewer are accepted.

## Dependencies

None. M02 adds the database session and the readiness DB check.

Design Ready: YES — Claude (developer), 2026-10-12 UTC
