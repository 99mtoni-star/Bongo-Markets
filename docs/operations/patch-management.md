# Patch Management (SEC-SDLC-005)

Sources: `pip-audit` in CI (every push), GitHub security advisories, PostgreSQL and OS security announcements, and supplier notices (SMS and payment providers).

| Severity (CVSS / impact) | Remediation deadline in production | Notes |
|---|---|---|
| **Critical** (≥ 9.0, or actively exploited) | **72 hours** | Emergency release allowed; incident record opened |
| **High** (7.0–8.9) | **7 days** | Next patch release |
| **Medium** (4.0–6.9) | **30 days** | Regular release |
| **Low** (< 4.0) | **90 days** | Batched with routine upgrades |

## Process

1. CI fails on any known-vulnerable dependency (`pip-audit --strict`). The owner triages within 1 business day.
2. Classify severity with the table above. Log it as a finding (STD-003, root cause `DEP`).
3. Patch, run the full gate, verify release checksums, deploy (`docs/operations/deployment.md`).
4. If no patch exists yet, record a time-limited exception with compensating controls (WAF rule, feature off), approved by the Platform Admin, and re-review weekly.
5. OS and PostgreSQL minor updates are applied monthly in a maintenance window. Security updates follow the deadlines above.
