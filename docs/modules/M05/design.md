# M05 — Users, Roles na Permissions: Design

## Model

- **Identity:** `users`, with an immutable id.
- **Authorization:** `permissions` (PLATFORM or SHOP scope, `high_risk` flag), `platform_roles`→`platform_role_permissions`, `shop_roles` (OWNER/MANAGER/STAFF)→`shop_role_permissions`.
- **Participation:** `user_capabilities` (BUYER, SELLER, SERVICE_PROVIDER, DELIVERY_AGENT). These never grant permissions (ACT-001/004, V13-REQ-007).
- **Policy versioning:** `authz_policy.version`, plus `users.authz_version` for each user.

## Scope

| Req | Control |
|---|---|
| SEC-003, AUTH-001 | `Authorizer.can/require`: deny by default, server-side, on every protected request |
| SEC-004 | Shop permissions resolved only from `shop_users` in the DB (tables arrive in M07; deny until then) |
| AUTH-002 | Separate PLATFORM/SHOP scopes; a shop permission without a shop id is always denied |
| AUTH-003 | Every admin route is mapped to an explicit permission, with negative tests (M05-T003) |
| AUTH-004, SEC-INV-002 | Generic 403/404; objects outside scope look missing (shop IDOR tests in M07) |
| ACT-002/006 | Roles and permissions are data (tables), editable through the RBAC API |
| ACT-003 | Multiple compatible role assignments |
| ACT-005, ACT-008 | **Deferred** (provider/service catalogues and object assignment arrive with service modules) |
| ACT-007 | Capability status changes are permission-checked and audited |
| ACT-009, AUTH-006 | `role_conflicts` (FINANCE⟂SUPPORT, FINANCE⟂MODERATOR); least-privilege role design |
| ACT-010 | Stable permission codes; additive API (docs/api/rbac.md) |
| AUTH-010/011 | Unique partial index + savepoint ⇒ concurrent duplicate grants are safe; policy rows locked `FOR UPDATE` |
| AUTH-012 | `docs/api/rbac.md` + OpenAPI |
| AUTH-013 | `privileged_mutation`: double-submit CSRF header **and** an allowed Origin/Referer on every admin mutation |
| AUTH-014/016 | `If-Match: <policy_version>`; stale ⇒ 409 |
| AUTH-015/017 | Role-permission change bumps `authz_version` of every holder; cache keyed by both versions; audited |
| V13-SEC-003 | High-risk permissions are always resolved from the DB; any error ⇒ deny |
| SEC-AUD-004 | Audit view/export need permissions (export also needs step-up and is audited); purge only via the owner-only `bm.purge_audit_logs`, which enforces retention and legal holds |
| SEC-COM-004 | Account closure, `scripts/retention.py` anonymization after 365 days, `legal_holds` suspend it |
| ID-003 | Process gate: identity change requests (CR-IDENTITY-001) need System Analyst authorization before coding; recorded in this note and enforced by the Design Ready gate |
| ID-009 | Dormant accounts (no sign-in for 180 days) are never reset by SMS alone: verified email or support |

Design Ready: YES — Claude (developer), 2026-10-12 UTC
