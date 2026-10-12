# M04 — MFA, Sessions na Password Recovery: Design

## Scope

| Req | Summary | Control |
|-----|---------|---------|
| AUTH-004 | Secure login and session management | Server-side sessions; MFA login challenge; session list and revocation |
| AUTH-005 (v1.11) | Real token only in a secure cookie; DB stores tokenHash | SHA-256 of a 256-bit token; cookie hardening from M03 |
| SEC-002 | Secure session lifecycle, HttpOnly/Secure/SameSite | Idle + absolute expiry, rotation on login/MFA, revocation on trust changes |
| AUTH-008 (v1.11) | Roles only via backend/authorized admins | Strict request models reject unknown fields; roles granted only through the admin API or bootstrap CLI |
| AUTH-008 (v1.12.2) | Privileged mutation step-up ≤300 s, bound, single-use | `step_up_grants` bound to user+session+action; DB check `≤ 300 s`; consumed on use |
| AUTH-005 (v1.12.2) | Privileged role changes: authz + audit + step-up/MFA | `grant_role`/`revoke_role`: role check, aal2 session, ROLE_ASSIGN step-up with TOTP, audit |
| AUTH-009 (v1.12.2) | Revocation semantics | Every request re-reads the session from the DB (no cache); role/status/factor changes revoke sessions at once |
| SEC-MFA-002 | Step-up for high-risk operations | `StepUpAction`: ownership transfer, refunds, commission, role assignment, payment config, MFA disable, phone/email change, incident response |
| SEC-MFA-004, ID-007 | Privileged accounts: TOTP minimum; SMS not enough | Privileged role requires enrolled TOTP; admin APIs need an aal2 session; privileged users cannot disable MFA |
| SEC-IR-003 | Revoke sessions, suspend accounts, suspend payments, rotate secrets | Admin incident API + `scripts/admin_cli.py` break-glass; secret rotation runbook. **Partial**: shop suspension arrives in M07, provider key rotation in M13/M20 |
| ID-004 | OTP bound to purpose/identifier/challenge, one-time | Code HMAC binds purpose + challenge id + user + destination |
| ID-005 | Registration OTP not reusable for recovery or phone change | Purpose-bound lookup + bound HMAC |
| ID-008 | Risk-based high-risk recovery; no SMS-only privileged recovery | Reset of MFA accounts requires TOTP/recovery code; phone change requires step-up and a code to the new number; old number warned |
| ID-010 | Identity security events revoke/rotate trust | Password change/reset, MFA on/off, phone change, role grant/revoke, suspension |
| ID-011 | OTP guessing / SMS pumping limits | Per destination, per IP, global SMS caps; per-code attempt limits; per-challenge limits |
| ID-012 | Secrets never in logs/evidence | Redaction + test scanning captured logs for every secret type |
| V13-SEC-002 | Timestamp, event ID, replay window | `services/replay.py` (5-minute window, unique `source+event_id`); TOTP time-step replay guard |

## Data model (migration 0003, sensitive review)

- `users`: `totp_secret_enc` (AES-256-GCM, key derived via HKDF from the server secret, AAD = user id), `totp_enabled_at`, `totp_last_step`.
- `user_sessions.aal`: 1 = password only, 2 = password + TOTP or recovery code.
- New tables: `mfa_recovery_codes` (SHA-256, single use), `login_challenges`, `step_up_grants`, `platform_roles` (seeded: SUPER_ADMIN, PLATFORM_ADMIN, FINANCE, SUPPORT, MODERATOR), `user_platform_roles` (grant/revoke history kept), `processed_events`.
- The app role gets column-level UPDATE only. It cannot modify the role catalogue or delete grant history.

## Decisions

- **TOTP implemented in-house** (about 30 lines, RFC 6238 test vector plus `pyotp` as an independent test oracle). This avoids a runtime dependency on a small package.
- **The TOTP key is derived from `BM_SECRET_KEY`.** Rotating that key requires re-enrolling MFA. A dedicated data-encryption key with a key-id prefix (`v1:`) is ready for M20.
- **Web forms do step-up and the action in one request.** The grant never leaves the server. The JSON API uses the two-step `X-Step-Up-Token` flow.

Design Ready: YES — Claude (developer), 2026-10-12 UTC
