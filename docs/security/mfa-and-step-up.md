# MFA and Step-up

## Assurance levels

| Level | How | Can do |
|---|---|---|
| aal1 | Password (phone verified by SMS at sign-up) | Normal buyer/seller activity |
| aal2 | Password + TOTP (or a single-use recovery code) | Required for every admin API; set on the session at MFA login |

Privileged platform roles (SUPER_ADMIN, PLATFORM_ADMIN, FINANCE, SUPPORT, MODERATOR) can only be granted to users who already have TOTP. Those users can never disable it. SMS/email OTP is never accepted as their second factor (SEC-MFA-004, ID-007).

## Step-up

`POST /api/v1/auth/step-up {action, password, mfa_code?}` returns a token valid for **300 seconds**. The token is valid for **one action**, from **this session**, **once**. Send it in the `X-Step-Up-Token` header. The TOTP factor is mandatory when the user has MFA enabled, and always for ROLE_ASSIGN, INCIDENT_RESPONSE, PAYMENT_CONFIG_CHANGE, COMMISSION_CHANGE, REFUND_APPROVE and OWNERSHIP_TRANSFER.

## Recovery

- A lost phone means signing in with a recovery code (10 per enrolment, each usable once), then re-enrolling.
- Password reset for an MFA account needs the SMS code **and** a TOTP or recovery code (ID-008).
- An account with no recovery codes left needs manual identity verification by support. This procedure is defined in M19 and is never SMS-only.
