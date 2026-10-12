# M03 — Registration na Login: Design

## Scope

| Req | Summary | Control |
|-----|---------|---------|
| AUTH-001 | Users can register | `/api/v1/auth/register` + `/jisajili` page; phone verification activates the account |
| AUTH-002 | Normalized email; E.164 phone | `identifiers.py` (phonenumbers library, default region TZ); DB check constraints |
| AUTH-003, SEC-001, SEC-PWD-001 | Argon2id, no plaintext | `passwords.py`: m=64 MiB, t=3, p=2; rehash on login when parameters change |
| AUTH-006 | Phone/email verification + reset codes with expiry and attempt limits | `auth_codes`: HMAC-hashed 6-digit codes, 10/15 min TTL, 5 attempts, one-time |
| AUTH-007 (v1.11) | Temporary lock after repeated failures | 5 failures → 15 min lock, SMS notice, lock not revealed |
| AUTH-007 (v1.12.2) | M05 needs Design Ready & Security Closure Contract | `scripts/gate.py` refuses any module without `Design Ready: YES` |
| SEC-009 | Rate limits | DB-backed windows (see `docs/security/rate-limits.md`) |
| SEC-010 | Audit without secrets | `audit.record` + redaction; test scans audit rows for secrets |
| SEC-014 | Revoke sessions after password change/reset | `revoke_all_sessions` |
| SEC-PWD-003 | Compromised-password check | **Partial**: offline list of common/global and local passwords; breach API in M20 |
| SEC-PWD-004 | No silent truncation | 256-character ceiling with explicit error; Argon2 has no 72-byte limit |
| SEC-PWD-005, ID-006 | Generic responses | identical bodies for unknown/wrong/locked; decoy IDs for register/forgot |
| SEC-PWD-006 | Reset tokens one-time, hashed, short-lived, rate-limited | as above |
| SEC-WEB-002 | Cookie hardening | `bm_session`: HttpOnly, Secure, SameSite=Lax, Path=/, Max-Age 7 days; idle 48 h |
| SEC-WEB-003 | CORS approved origins only | `*` rejected at startup; Origin guard on state-changing requests |
| ID-001 | Immutable internal userId | identity ALWAYS + column-level grants; API exposes only `public_id` |
| ID-002 | Mobile-number-first; email optional/secondary | phone required; email login only after verification |
| SEC-INV-007 | History not alterable by app credentials | app cannot delete users/sessions or touch audit (tested) |

## Data model (migration 0002, sensitive review)

`users`, `auth_codes`, `user_sessions` and `rate_limit_buckets`, as in `app/auth/models.py`. The app role has UPDATE only on mutable columns, and no DELETE on users or sessions.

## API

| Method | Path | Auth |
|---|---|---|
| POST | /api/v1/auth/register, /verify-phone, /resend-code, /login, /password/forgot, /password/reset | none (rate limited) |
| POST | /api/v1/auth/logout, /password/change, /email/verify-request, /email/verify | session |
| GET | /api/v1/auth/me | session |
| GET/POST | /jisajili, /thibitisha, /ingia, /toka, /akaunti, /umesahau-nenosiri, /weka-nenosiri-upya | HTML + CSRF |
| GET | /dev/sms | development/test only |

## Threats → controls

| Threat | Control |
|---|---|
| Account enumeration | Generic messages, decoy IDs, equal hashing work, owner alerted by SMS instead |
| Credential stuffing / brute force | Per-IP and per-identifier rate limits; account lock |
| OTP brute force | 5 attempts per code, newest code only, HMAC at rest, rate limits |
| Session theft | Random 256-bit tokens, SHA-256 at rest, HttpOnly/Secure/SameSite, idle+absolute expiry, revocation |
| CSRF | Form tokens (double-submit, SameSite=Strict cookie); Origin guard; JSON-only API |
| Number squatting | Unverified sign-ups can be replaced; only verified accounts are protected |
| Secret leakage | No secrets in audit/logs; codes appear only in the SMS (or the dev inbox in development) |

## Dependencies

Uses M01 (config, logging) and M02 (DB, audit). M04 adds MFA, the session list UI and step-up authentication. M05 adds roles and permissions. M06 finalizes the header, navigation and site-wide CSRF policy.

Design Ready: YES — Claude (developer), 2026-10-12 UTC
