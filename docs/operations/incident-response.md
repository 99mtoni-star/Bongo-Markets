# Incident Response (SEC-IR-003)

Normal path: an authenticated responder (PLATFORM_ADMIN or SUPER_ADMIN) with an aal2 session performs an INCIDENT_RESPONSE step-up, then uses:

| Action | API |
|---|---|
| Suspend an account (revokes all its sessions) | `POST /api/v1/admin/incident/users/{id}/suspend` |
| Reinstate | `POST /api/v1/admin/incident/users/{id}/reinstate` |
| Force sign-out | `POST /api/v1/admin/incident/users/{id}/sign-out` |
| Suspend / resume payments | `POST /api/v1/admin/incident/payments {suspended, reason}` |
| Suspend a shop | M07 |

Break-glass path (when the admin API is unavailable): `scripts/admin_cli.py` on the server, using the app's DB credentials, with a mandatory `--operator` and `--reason`. Every action is audited with `actor_type=cli`.

```
python scripts/admin_cli.py suspend-user --phone 0754123456 --operator "Ndegetai" --reason "account takeover"
python scripts/admin_cli.py revoke-all-sessions --operator "Ndegetai" --reason "secret key rotation"
python scripts/admin_cli.py payments --suspend --operator "Ndegetai" --reason "provider breach"
```

## Rotating secrets

1. **`BM_SECRET_KEY` compromised:** set a new value and restart. All OTP/reset codes and pseudonymous keys become invalid. Run `revoke-all-sessions`. Users with MFA must re-enrol, because TOTP secrets are encrypted with a key derived from it. A dedicated data key is planned for M20.
2. **Database passwords:** `ALTER ROLE bm_app PASSWORD ...` through the secret manager, then restart the app.
3. **Payment provider keys:** rotate at the provider and suspend payments while switching (M13).
