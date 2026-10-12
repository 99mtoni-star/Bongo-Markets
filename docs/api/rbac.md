# RBAC API Contract (authoritative, AUTH-012)

All paths are under `/api/v1`. Errors use the format `{"error": {"code", "message", "field"?}}` with generic wording (SEC-INV-002).

## Rules for every privileged mutation

1. Session cookie `bm_session` of a user whose role grants the permission (deny by default).
2. The session must be **aal2** (signed in with TOTP).
3. A single-use step-up token in `X-Step-Up-Token` (from `POST /auth/step-up`, valid 300 s, bound to the action).
4. `X-CSRF-Token` equal to the `bm_csrf` cookie, **and** an allowed `Origin` (or `Referer`). Both are required (AUTH-013).

## Endpoints

| Method | Path | Permission | Step-up action | Notes |
|---|---|---|---|---|
| GET | `/admin/rbac` | platform.rbac.manage | none | `{policy_version, permissions[], platform_roles{}, shop_roles{}}` |
| PUT | `/admin/rbac/{PLATFORM\|SHOP}/roles/{role}` | platform.rbac.manage | RBAC_CHANGE | Body `{permissions: [...]}` (complete set). **`If-Match: <policy_version>` required**; a stale version gives `409 policy_version_conflict` (AUTH-014/016). Holders' `authz_version` is bumped (AUTH-015/017). |
| POST | `/admin/users/{id}/roles` | platform.roles.assign | ROLE_ASSIGN | `409 role_conflict` (SoD), `409 exists` (also on a concurrent duplicate), `409 target_mfa_required` |
| DELETE | `/admin/users/{id}/roles/{role}` | platform.roles.assign | ROLE_ASSIGN | Target sessions revoked at once |
| GET | `/admin/audit?limit=` | platform.audit.view | none | Latest events, no details payload |
| POST | `/admin/audit/export` | platform.audit.export | AUDIT_EXPORT | CSV, maximum 50 000 rows; the export itself is audited |
| POST/DELETE | `/admin/users/{id}/legal-hold` | platform.legal_hold.manage | LEGAL_HOLD | Suspends anonymization and audit purge for the user |
| PUT | `/admin/users/{id}/capabilities/{cap}` | platform.shops.verify | none | Participation status; never grants permissions |
| GET | `/auth/me/permissions` | session | none | The caller's own platform permissions and capabilities |
| POST | `/auth/account/close` | session | ACCOUNT_CLOSE | Personal data anonymized after the retention period |

## Compatibility (ACT-010)

Permission codes are stable identifiers. They are never renamed or reused. New permissions are added. Removing a permission requires a migration that first removes it from every role, together with a release note. Responses only gain fields; they never lose them within `/api/v1`.
