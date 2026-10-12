"""Module 05 – Users, Roles na Permissions."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest
from psycopg import errors

from tests.test_m03_auth import STRONG, e164, last_code, register_and_verify, user_row
from tests.test_m04_security import enable_mfa, make_admin, public_id, step_up, switch


@pytest.fixture(autouse=True)
def _reset(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    from app.authz.engine import CACHE

    CACHE.clear()
    yield


def uid_of(owner_conn, phone):
    return user_row(owner_conn, phone)[0]


def authorizer(pg, make_settings):
    from app.authz.engine import Authorizer
    from app.db.session import session_factory

    s = session_factory(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url))()
    return Authorizer(s), s


ALL_PERMS_SQL = "SELECT code FROM bm.permissions"


# --------------------------------------------------------------------------- AUTH-001, SEC-003
@pytest.mark.tid("M05-T001")
def test_deny_by_default(db_client, owner_conn, pg, make_settings):
    phone = register_and_verify(db_client)
    uid = uid_of(owner_conn, phone)
    az, s = authorizer(pg, make_settings)
    with s:
        for (code,) in owner_conn.execute(ALL_PERMS_SQL):
            assert az.can(uid, code, shop_id=1) is False
        assert az.can(uid, "made.up.permission") is False


# --------------------------------------------------------------------------- AUTH-002
@pytest.mark.tid("M05-T002")
def test_platform_and_shop_scopes_are_separate(db_client, owner_conn, pg, make_settings):
    phone, _ = make_admin(db_client, owner_conn)
    uid = uid_of(owner_conn, phone)
    az, s = authorizer(pg, make_settings)
    with s:
        assert az.can(uid, "platform.roles.assign")
        assert not az.can(uid, "shop.products.manage", shop_id=1)  # super admin is not a shop member
        assert not az.can(uid, "shop.products.manage")  # shop permission without a shop is always denied


# --------------------------------------------------------------------------- AUTH-003, SEC-INV-002
ADMIN_ROUTES = [
    ("GET", "/api/v1/admin/rbac", None), ("GET", "/api/v1/admin/audit", None),
    ("POST", "/api/v1/admin/audit/export", {"since": "2026-01-01T00:00:00Z", "until": "2026-12-31T00:00:00Z"}),
    ("PUT", "/api/v1/admin/rbac/PLATFORM/roles/SUPPORT", {"permissions": []}),
    ("POST", "/api/v1/admin/users/00000000-0000-0000-0000-000000000000/roles", {"role": "SUPPORT"}),
    ("POST", "/api/v1/admin/users/00000000-0000-0000-0000-000000000000/legal-hold", {"reason": "court order"}),
    ("POST", "/api/v1/admin/incident/payments", {"suspended": True, "reason": "test"}),
]


@pytest.mark.tid("M05-T003")
def test_every_admin_route_denies_plain_users_generically(db_client):
    for method, path, body in ADMIN_ROUTES:
        anon = db_client.request(method, path, json=body)
        assert anon.status_code == 401, path
    register_and_verify(db_client)
    for method, path, body in ADMIN_ROUTES:
        r = db_client.request(method, path, json=body)
        assert r.status_code == 403, (path, r.text)
        text = r.text.lower()
        assert "traceback" not in text and "select" not in text and "bm." not in text


@pytest.mark.tid("M05-T004")
def test_policy_version_optimistic_concurrency(db_client, owner_conn):
    _, totp = make_admin(db_client, owner_conn)
    cat = db_client.get("/api/v1/admin/rbac").json()
    v = cat["policy_version"]
    current = cat["platform_roles"]["SUPPORT"]
    url = "/api/v1/admin/rbac/PLATFORM/roles/SUPPORT"
    body = {"permissions": current + ["platform.audit.view"]}
    no_match = db_client.put(url, json=body, headers={"X-Step-Up-Token": step_up(db_client, "RBAC_CHANGE", totp)})
    assert no_match.status_code == 409
    ok = db_client.put(url, json=body, headers={"X-Step-Up-Token": step_up(db_client, "RBAC_CHANGE", totp),
                                                 "If-Match": str(v)})
    assert ok.status_code == 200 and ok.json()["policy_version"] == v + 1
    stale = db_client.put(url, json={"permissions": current},
                          headers={"X-Step-Up-Token": step_up(db_client, "RBAC_CHANGE", totp), "If-Match": str(v)})
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "policy_version_conflict"
    restore = db_client.put(url, json={"permissions": current},
                            headers={"X-Step-Up-Token": step_up(db_client, "RBAC_CHANGE", totp),
                                     "If-Match": str(v + 1)})
    assert restore.status_code == 200


@pytest.mark.tid("M05-T005")
def test_permission_change_fans_out_to_holders_immediately(db_client, owner_conn, pg, make_settings):
    _, totp = make_admin(db_client, owner_conn)
    admin_cookie = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    support_phone = register_and_verify(db_client)
    sid = uid_of(owner_conn, support_phone)
    owner_conn.execute("INSERT INTO bm.user_platform_roles(user_id, role_code) VALUES (%s,'SUPPORT')", (sid,))
    az, s = authorizer(pg, make_settings)
    with s:
        assert not az.can(sid, "platform.audit.view")  # cached as denied
        before = owner_conn.execute("SELECT authz_version FROM bm.users WHERE id=%s", (sid,)).fetchone()[0]
        switch(db_client, admin_cookie)
        v = db_client.get("/api/v1/admin/rbac").json()["policy_version"]
        r = db_client.put("/api/v1/admin/rbac/PLATFORM/roles/SUPPORT",
                          json={"permissions": ["platform.users.view", "platform.audit.view"]},
                          headers={"X-Step-Up-Token": step_up(db_client, "RBAC_CHANGE", totp), "If-Match": str(v)})
        assert r.status_code == 200
        after = owner_conn.execute("SELECT authz_version FROM bm.users WHERE id=%s", (sid,)).fetchone()[0]
        assert after == before + 1
        s.rollback()  # new transaction sees the committed change
        assert az.can(sid, "platform.audit.view")  # old cache entry is unreachable
    detail = owner_conn.execute("SELECT details FROM bm.audit_logs WHERE action='rbac.role_permissions_changed' "
                                "ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert detail["added"] == ["platform.audit.view"] and detail["affected_users"] >= 1
    v2 = db_client.get("/api/v1/admin/rbac").json()["policy_version"]
    db_client.put("/api/v1/admin/rbac/PLATFORM/roles/SUPPORT", json={"permissions": ["platform.users.view"]},
                  headers={"X-Step-Up-Token": step_up(db_client, "RBAC_CHANGE", totp), "If-Match": str(v2)})


@pytest.mark.tid("M05-T006")
def test_high_risk_checks_bypass_cache_and_fail_closed(db_client, owner_conn, pg, make_settings, monkeypatch):
    from app.authz import engine

    phone = register_and_verify(db_client)
    uid = uid_of(owner_conn, phone)
    az, s = authorizer(pg, make_settings)
    with s:
        uv, pv = az._versions(uid)
        engine.CACHE.put(("p", uid, uv, pv), frozenset({"platform.roles.assign", "platform.users.view"}))
        assert az.can(uid, "platform.users.view")          # low-risk: cache may answer
        assert not az.can(uid, "platform.roles.assign")    # high-risk: always re-read from the DB
        monkeypatch.setattr(az, "_versions", lambda _uid: (_ for _ in ()).throw(RuntimeError("db down")))
        assert not az.can(uid, "platform.users.view")      # any error -> deny


@pytest.mark.tid("M05-T007")
def test_segregation_of_duties_blocks_conflicting_roles(db_client, owner_conn):
    _, admin_totp = make_admin(db_client, owner_conn)
    admin_cookie = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    register_and_verify(db_client)
    enable_mfa(db_client)
    target = public_id(db_client)
    switch(db_client, admin_cookie)

    def grant(role):
        return db_client.post(f"/api/v1/admin/users/{target}/roles", json={"role": role},
                              headers={"X-Step-Up-Token": step_up(db_client, "ROLE_ASSIGN", admin_totp)})

    assert grant("SUPPORT").status_code == 201
    r = grant("FINANCE")
    assert r.status_code == 409 and r.json()["error"]["code"] == "role_conflict"
    # ACT-003: compatible roles can be combined
    assert grant("MODERATOR").status_code == 201


@pytest.mark.tid("M05-T008")
def test_concurrent_duplicate_grant_is_safe(db_client, owner_conn, pg, make_settings):
    """AUTH-010/011: two simultaneous identical grants -> exactly one active row."""
    phone = register_and_verify(db_client)
    uid = uid_of(owner_conn, phone)
    results = []

    def worker():
        import psycopg

        with psycopg.connect(pg.app_url.replace("+psycopg", "")) as c:
            try:
                c.execute("INSERT INTO bm.user_platform_roles(user_id, role_code) VALUES (%s,'SUPPORT')", (uid,))
                c.commit()
                results.append("ok")
            except errors.UniqueViolation:
                results.append("dup")

    threads = [threading.Thread(target=worker) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count("ok") == 1
    n = owner_conn.execute("SELECT count(*) FROM bm.user_platform_roles WHERE user_id=%s AND revoked_at IS NULL",
                           (uid,)).fetchone()[0]
    assert n == 1


# --------------------------------------------------------------------------- ACT-001/004, V13-REQ-007, ACT-007
@pytest.mark.tid("M05-T009")
def test_capabilities_never_imply_privilege(db_client, owner_conn, pg, make_settings):
    phone = register_and_verify(db_client)
    uid = uid_of(owner_conn, phone)
    for cap in ("BUYER", "SELLER", "SERVICE_PROVIDER"):
        owner_conn.execute("INSERT INTO bm.user_capabilities(user_id, capability, status) VALUES (%s,%s,'ACTIVE')",
                           (uid, cap))
    me = db_client.get("/api/v1/auth/me/permissions").json()
    assert me["platform"] == [] and {c["capability"] for c in me["capabilities"]} == {"BUYER", "SELLER",
                                                                                       "SERVICE_PROVIDER"}
    az, s = authorizer(pg, make_settings)
    with s:
        assert az.platform_permissions(uid) == frozenset()


@pytest.mark.tid("M05-T010")
def test_capability_status_changes_are_authorized_and_audited(db_client, owner_conn):
    register_and_verify(db_client)
    target = public_id(db_client)
    r = db_client.put(f"/api/v1/admin/users/{target}/capabilities/SELLER", json={"status": "ACTIVE"})
    assert r.status_code == 403
    db_client.cookies.clear()
    make_admin(db_client, owner_conn, role="PLATFORM_ADMIN")
    r = db_client.put(f"/api/v1/admin/users/{target}/capabilities/SELLER", json={"status": "ACTIVE"})
    assert r.status_code == 200
    row = owner_conn.execute("SELECT details FROM bm.audit_logs WHERE action='capability.status_changed' "
                             "ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert row["capability"] == "SELLER" and row["to"] == "ACTIVE"


# --------------------------------------------------------------------------- AUTH-013
@pytest.mark.tid("M05-T011")
def test_privileged_mutations_need_explicit_csrf_and_origin(db_client, owner_conn):
    _, totp = make_admin(db_client, owner_conn)
    url = "/api/v1/admin/incident/payments"
    body = {"suspended": False, "reason": "csrf test"}
    tok = step_up(db_client, "INCIDENT_RESPONSE", totp)
    assert db_client.post(url, json=body, headers={"X-Step-Up-Token": tok, "X-CSRF-Token": "wrong"}).status_code == 403
    assert db_client.post(url, json=body, headers={"X-Step-Up-Token": tok,
                                                   "Origin": "https://evil.example"}).status_code == 403
    ok = db_client.post(url, json=body, headers={"X-Step-Up-Token": tok})
    assert ok.status_code == 200  # token still unused: CSRF/Origin were rejected before step-up was consumed


# --------------------------------------------------------------------------- SEC-AUD-004
@pytest.mark.tid("M05-T012")
def test_audit_export_and_purge_are_controlled(db_client, owner_conn, app_conn):
    register_and_verify(db_client)
    body = {"since": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
            "until": (datetime.now(UTC) + timedelta(days=1)).isoformat()}
    assert db_client.post("/api/v1/admin/audit/export", json=body).status_code == 403
    db_client.cookies.clear()
    _, totp = make_admin(db_client, owner_conn)
    assert db_client.post("/api/v1/admin/audit/export", json=body).status_code == 403  # needs step-up
    r = db_client.post("/api/v1/admin/audit/export", json=body,
                       headers={"X-Step-Up-Token": step_up(db_client, "AUDIT_EXPORT", totp)})
    assert r.status_code == 200 and r.text.startswith("id,occurred_at,category,action")
    assert "attachment" in r.headers["content-disposition"]
    assert owner_conn.execute("SELECT count(*) FROM bm.audit_logs WHERE action='audit.exported'").fetchone()[0] >= 1
    with pytest.raises(errors.InsufficientPrivilege):
        app_conn.execute("SELECT bm.purge_audit_logs('GENERAL', now() - interval '8 years')")
    with pytest.raises(Exception, match="retention period"):
        owner_conn.execute("SELECT bm.purge_audit_logs('FINANCIAL', now() - interval '1 year')")
    assert owner_conn.execute("SELECT bm.purge_audit_logs('GENERAL', now() - interval '8 years')").fetchone()[0] >= 0
    assert owner_conn.execute("SELECT count(*) FROM bm.audit_logs WHERE action='audit.retention_purge'") \
        .fetchone()[0] >= 1


# --------------------------------------------------------------------------- SEC-COM-004
@pytest.mark.tid("M05-T013")
def test_closed_accounts_are_anonymized_unless_on_legal_hold(db_client, owner_conn, pg, make_settings):
    from scripts.retention import run

    phones = []
    for _ in range(2):
        db_client.cookies.clear()
        phone = register_and_verify(db_client)
        tok = step_up(db_client, "ACCOUNT_CLOSE")
        assert db_client.post("/api/v1/auth/account/close", headers={"X-Step-Up-Token": tok}).status_code == 200
        assert db_client.get("/api/v1/auth/me").status_code == 401
        phones.append(phone)
    keep, wipe = (uid_of(owner_conn, p) for p in phones)
    owner_conn.execute("INSERT INTO bm.legal_holds(user_id, reason, created_by) VALUES (%s,'court order','test')",
                       (keep,))
    owner_conn.execute("UPDATE bm.users SET closed_at = now() - interval '400 days' WHERE id IN (%s,%s)", (keep, wipe))
    report = run(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url))
    assert report["anonymized"] >= 1 and report["held"] >= 1
    w = owner_conn.execute("SELECT full_name, phone_e164, email, anonymized_at FROM bm.users WHERE id=%s",
                           (wipe,)).fetchone()
    assert w[0] == "Mtumiaji aliyefutwa" and w[1].startswith("+9") and w[2] is None and w[3] is not None
    k = owner_conn.execute("SELECT anonymized_at, phone_e164 FROM bm.users WHERE id=%s", (keep,)).fetchone()
    assert k[0] is None and k[1] == e164(phones[0])


# --------------------------------------------------------------------------- ID-009
@pytest.mark.tid("M05-T014")
def test_dormant_account_reset_never_relies_on_recycled_number(db_client, owner_conn):
    phone = register_and_verify(db_client)
    uid = uid_of(owner_conn, phone)
    owner_conn.execute("UPDATE bm.users SET last_login_at = now() - interval '400 days' WHERE id=%s", (uid,))
    before = db_client.app.state.notifier.last_to(e164(phone))
    r = db_client.post("/api/v1/auth/password/forgot", json={"identifier": phone})
    assert r.status_code == 202  # same generic answer
    assert db_client.app.state.notifier.last_to(e164(phone)) is before  # no SMS to the (possibly new) holder
    assert owner_conn.execute("SELECT count(*) FROM bm.audit_logs WHERE action='auth.reset_blocked_dormant' "
                              "AND entity_id=%s", (str(uid),)).fetchone()[0] == 1
    # With a verified email the code goes to the email instead.
    owner_conn.execute("UPDATE bm.users SET email=%s, email_verified_at=now() WHERE id=%s",
                       (f"dormant{uid}@example.com", uid))
    db_client.post("/api/v1/auth/password/forgot", json={"identifier": phone})
    assert last_code(db_client, f"dormant{uid}@example.com")


@pytest.mark.tid("M05-T015")
def test_super_admin_lockout_protection_and_contract(db_client, owner_conn):
    _, totp = make_admin(db_client, owner_conn)
    cat = db_client.get("/api/v1/admin/rbac").json()
    assert set(cat) == {"policy_version", "permissions", "platform_roles", "shop_roles"}
    assert set(cat["shop_roles"]) == {"OWNER", "MANAGER", "STAFF"}
    r = db_client.put("/api/v1/admin/rbac/PLATFORM/roles/SUPER_ADMIN", json={"permissions": ["platform.users.view"]},
                      headers={"X-Step-Up-Token": step_up(db_client, "RBAC_CHANGE", totp),
                               "If-Match": str(cat["policy_version"])})
    assert r.status_code == 409 and r.json()["error"]["code"] == "protected"
    paths = db_client.get("/openapi.json").json()["paths"]
    assert "/api/v1/admin/rbac/{scope}/roles/{role}" in paths and "/api/v1/auth/me/permissions" in paths


@pytest.mark.tid("M05-T016")
def test_permission_codes_are_backward_compatible(owner_conn):
    """ACT-010: codes published in policy v1 must keep existing."""
    v1 = {"platform.roles.assign", "platform.rbac.manage", "platform.incident.respond", "platform.users.view",
          "platform.shops.verify", "platform.settings.manage", "platform.audit.view", "platform.audit.export",
          "platform.legal_hold.manage", "platform.content.moderate", "finance.payments.view",
          "finance.refunds.approve", "finance.reports.view", "shop.admin.view", "shop.profile.update",
          "shop.managers.manage", "shop.staff.manage", "shop.ownership.transfer", "shop.products.manage",
          "shop.products.price", "shop.orders.view", "shop.orders.fulfil", "shop.payments.configure",
          "shop.commission.configure", "shop.analytics.view"}
    assert v1 <= {c for (c,) in owner_conn.execute(ALL_PERMS_SQL)}


@pytest.mark.tid("M05-T017")
def test_unknown_target_is_generic_404(db_client, owner_conn):
    _, totp = make_admin(db_client, owner_conn)
    r = db_client.post("/api/v1/admin/users/00000000-0000-0000-0000-000000000000/roles", json={"role": "SUPPORT"},
                       headers={"X-Step-Up-Token": step_up(db_client, "ROLE_ASSIGN", totp)})
    assert r.status_code == 404 and r.json()["error"]["message"] == "Mtumiaji hapatikani."
    assert STRONG
