"""Module 07 – Shops, Ownership na Staff."""

from __future__ import annotations

import re

import pytest
from psycopg import errors

from tests.test_m03_auth import e164, last_code, new_phone, register_and_verify, user_row
from tests.test_m04_security import enable_mfa, make_admin, public_id, step_up, switch


@pytest.fixture(autouse=True)
def _reset(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    from app.authz.engine import CACHE

    CACHE.clear()
    yield


def new_shop(client, name="Kuku wa Kienyeji Arusha", **extra) -> dict:
    r = client.post("/api/v1/shops", json={"name": name, "region": "Arusha", **extra})
    assert r.status_code == 201, r.text
    return r.json()


class People:
    """Owner, manager, staff and an outsider, each with their own session cookie."""

    def __init__(self, client):
        self.client = client
        self.phone, self.cookie, self.pid = {}, {}, {}
        for who in ("owner", "manager", "staff", "outsider"):
            client.cookies.clear()
            self.phone[who] = register_and_verify(client, name=f"{who.title()} Mtu")
            self.cookie[who] = client.cookies.get("bm_session")
            self.pid[who] = public_id(client)

    def act(self, who):
        switch(self.client, self.cookie[who])
        return self.client


@pytest.fixture
def team(db_client):
    p = People(db_client)
    c = p.act("owner")
    p.shop = new_shop(c)
    slug = p.shop["slug"]
    assert c.post(f"/api/v1/shops/{slug}/members", json={"phone": p.phone["manager"], "role": "MANAGER"}) \
        .status_code == 201
    assert c.post(f"/api/v1/shops/{slug}/members", json={"phone": p.phone["staff"], "role": "STAFF"}) \
        .status_code == 201
    return p


# --------------------------------------------------------------------------- SHOP-001/002/003, BR-001/002/004
@pytest.mark.tid("M07-T001")
def test_any_user_can_open_several_shops_and_becomes_owner(db_client, owner_conn):
    phone = register_and_verify(db_client)
    a, b = new_shop(db_client, "Mayai Fresh"), new_shop(db_client, "Mayai Fresh")
    assert a["slug"] == "mayai-fresh" and b["slug"] == "mayai-fresh-2"
    assert a["status"] == "PENDING_VERIFICATION" and a["my_role"] == "OWNER"
    uid = user_row(owner_conn, phone)[0]
    rows = owner_conn.execute("SELECT s.owner_user_id, su.user_id, su.role_code FROM bm.shops s JOIN bm.shop_users su "
                              "ON su.shop_id=s.id AND su.removed_at IS NULL WHERE s.slug=%s", (a["slug"],)).fetchall()
    assert rows == [(uid, uid, "OWNER")]
    caps = dict(owner_conn.execute("SELECT capability, status FROM bm.user_capabilities WHERE user_id=%s", (uid,)))
    assert caps == {"BUYER": "ACTIVE", "SELLER": "PENDING"}  # buyer and seller on one account
    hist = owner_conn.execute("SELECT from_status, to_status FROM bm.shop_status_history h JOIN bm.shops s "
                              "ON s.id=h.shop_id WHERE s.slug=%s", (a["slug"],)).fetchall()
    assert hist == [(None, "PENDING_VERIFICATION")]
    assert len(db_client.get("/api/v1/shops/mine").json()["shops"]) == 2


@pytest.mark.tid("M07-T002")
def test_client_cannot_set_owner_status_or_bad_slug(db_client):
    register_and_verify(db_client)
    for extra in ({"owner_user_id": 1}, {"status": "ACTIVE"}, {"role": "OWNER"}):
        assert db_client.post("/api/v1/shops", json={"name": "Duka Langu", **extra}).status_code == 422
    for slug in ("admin", "a", "Bad Slug!", "-x-"):
        r = db_client.post("/api/v1/shops", json={"name": "Duka Langu", "slug": slug})
        assert r.status_code == 422, slug


@pytest.mark.tid("M07-T003")
def test_database_enforces_single_consistent_owner(db_client, owner_conn):
    phone = register_and_verify(db_client)
    slug = new_shop(db_client)["slug"]
    uid = user_row(owner_conn, phone)[0]
    sid = owner_conn.execute("SELECT id FROM bm.shops WHERE slug=%s", (slug,)).fetchone()[0]
    other = register_and_verify(db_client)
    oid = user_row(owner_conn, other)[0]
    with pytest.raises(errors.UniqueViolation):
        owner_conn.execute("INSERT INTO bm.shop_users(shop_id,user_id,role_code) VALUES (%s,%s,'OWNER')", (sid, oid))
    with pytest.raises(errors.IntegrityConstraintViolation):  # deferred check at commit
        owner_conn.execute("UPDATE bm.shops SET owner_user_id=%s WHERE id=%s", (oid, sid))
    assert owner_conn.execute("SELECT owner_user_id FROM bm.shops WHERE id=%s", (sid,)).fetchone()[0] == uid


# --------------------------------------------------------------------------- SHOP-004, BR-006, BR-008
@pytest.mark.tid("M07-T004")
def test_staff_management_rules(team):
    slug = team.shop["slug"]
    extra = new_phone()
    c = team.act("manager")
    assert c.post(f"/api/v1/shops/{slug}/members", json={"phone": team.phone["outsider"], "role": "MANAGER"}) \
        .status_code == 403  # managers cannot add managers
    c = team.act("staff")
    assert c.post(f"/api/v1/shops/{slug}/members", json={"phone": team.phone["outsider"], "role": "STAFF"}) \
        .status_code == 403  # staff cannot add anyone
    for who in ("owner", "manager", "staff"):
        c = team.act(who)
        r = c.post(f"/api/v1/shops/{slug}/members", json={"phone": team.phone[who], "role": "OWNER"})
        assert r.status_code == 403 and r.json()["error"]["code"] == "owner_not_assignable"  # BR-006
    c = team.act("manager")
    assert c.post(f"/api/v1/shops/{slug}/members", json={"phone": team.phone["outsider"], "role": "STAFF"}) \
        .status_code == 201
    assert c.post(f"/api/v1/shops/{slug}/members", json={"phone": extra, "role": "STAFF"}).status_code == 404


@pytest.mark.tid("M07-T005")
def test_permissions_come_from_membership_and_removal_is_immediate(team, pg, make_settings, owner_conn):
    from app.authz.engine import Authorizer
    from app.db.session import session_factory

    slug = team.shop["slug"]
    sid = owner_conn.execute("SELECT id FROM bm.shops WHERE slug=%s", (slug,)).fetchone()[0]
    staff_id = user_row(owner_conn, team.phone["staff"])[0]
    with session_factory(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url))() as s:
        az = Authorizer(s)
        assert az.can(staff_id, "shop.products.manage", shop_id=sid)
        assert not az.can(staff_id, "shop.profile.update", shop_id=sid)
        assert not az.can(staff_id, "shop.ownership.transfer", shop_id=sid)
    c = team.act("staff")
    assert c.patch(f"/api/v1/shops/{slug}", json={"name": "Jina Jipya"}).status_code == 403
    assert c.get(f"/api/v1/shops/{slug}/members").status_code == 200
    c = team.act("manager")
    assert c.delete(f"/api/v1/shops/{slug}/members/{team.pid['staff']}").status_code == 200
    c = team.act("staff")
    assert c.get(f"/api/v1/shops/{slug}/members").status_code == 404  # access gone at once, shop now invisible


@pytest.mark.tid("M07-T006")
def test_non_members_cannot_probe_or_act_on_other_shops(team):
    slug = team.shop["slug"]
    c = team.act("outsider")
    other = new_shop(c, "Duka la Mwingine")["slug"]
    for method, path, body in (("GET", f"/api/v1/shops/{slug}/members", None),
                               ("PATCH", f"/api/v1/shops/{slug}", {"name": "Hacked Shop"}),
                               ("POST", f"/api/v1/shops/{slug}/members", {"phone": team.phone["outsider"],
                                                                          "role": "STAFF"}),
                               ("GET", f"/api/v1/shops/{slug}/history", None),
                               ("GET", "/api/v1/shops/does-not-exist/members", None)):
        r = c.request(method, path, json=body)
        assert r.status_code == 404 and r.json()["error"]["message"] == "Duka halipatikani.", path
    c = team.act("owner")  # owner of shop A has no rights in shop B
    assert c.get(f"/api/v1/shops/{other}/members").status_code == 404
    assert c.get(f"/api/v1/shops/{slug}").json()["slug"] == slug


# --------------------------------------------------------------------------- BR-005, SHOP-002 (v1.12.2)
@pytest.mark.tid("M07-T007")
def test_ownership_transfer_is_step_up_protected_and_audited(team, owner_conn):
    slug = team.shop["slug"]
    c = team.act("owner")
    r = c.post(f"/api/v1/shops/{slug}/transfer-ownership", json={"new_owner_id": team.pid["manager"]})
    assert r.status_code == 403  # no step-up
    pw_only = c.post("/api/v1/auth/step-up", json={"action": "OWNERSHIP_TRANSFER", "password": "Mchele-Mzuri-2026"})
    assert pw_only.status_code == 403 and pw_only.json()["error"]["code"] == "mfa_enrollment_required"
    totp, _ = enable_mfa(c)
    r = c.post(f"/api/v1/shops/{slug}/transfer-ownership", json={"new_owner_id": team.pid["outsider"]},
               headers={"X-Step-Up-Token": step_up(c, "OWNERSHIP_TRANSFER", totp)})
    assert r.status_code == 409  # new owner must already be a member
    r = c.post(f"/api/v1/shops/{slug}/transfer-ownership", json={"new_owner_id": team.pid["manager"]},
               headers={"X-Step-Up-Token": step_up(c, "OWNERSHIP_TRANSFER", totp)})
    assert r.status_code == 200, r.text
    roles = {r["name"]: r["role"] for r in c.get(f"/api/v1/shops/{slug}/members").json()["members"]}
    assert roles["Manager Mtu"] == "OWNER" and roles["Owner Mtu"] == "MANAGER"
    mgr = user_row(owner_conn, team.phone["manager"])[0]
    assert owner_conn.execute("SELECT owner_user_id FROM bm.shops WHERE slug=%s", (slug,)).fetchone()[0] == mgr
    assert owner_conn.execute("SELECT count(*) FROM bm.audit_logs WHERE action='shop.ownership_transferred'") \
        .fetchone()[0] >= 1
    # The former owner can no longer transfer.
    r = c.post(f"/api/v1/shops/{slug}/transfer-ownership", json={"new_owner_id": team.pid["staff"]},
               headers={"X-Step-Up-Token": step_up(c, "OWNERSHIP_TRANSFER", totp)})
    assert r.status_code == 403


@pytest.mark.tid("M07-T008")
def test_ownership_transfer_is_atomic(team, owner_conn, monkeypatch):
    from app.shops import service

    slug = team.shop["slug"]
    c = team.act("owner")
    totp, _ = enable_mfa(c)
    token = step_up(c, "OWNERSHIP_TRANSFER", totp)
    real = service.audit.record

    def boom(db, **kw):
        if kw.get("action") == "shop.ownership_transferred":
            raise RuntimeError("simulated crash after membership rows changed")
        return real(db, **kw)

    monkeypatch.setattr(service.audit, "record", boom)
    r = c.post(f"/api/v1/shops/{slug}/transfer-ownership", json={"new_owner_id": team.pid["manager"]},
               headers={"X-Step-Up-Token": token})
    assert r.status_code == 500
    owner = user_row(owner_conn, team.phone["owner"])[0]
    assert owner_conn.execute("SELECT owner_user_id FROM bm.shops WHERE slug=%s", (slug,)).fetchone()[0] == owner
    active = owner_conn.execute("SELECT su.role_code FROM bm.shop_users su JOIN bm.shops s ON s.id=su.shop_id "
                                "WHERE s.slug=%s AND su.removed_at IS NULL ORDER BY su.role_code", (slug,)).fetchall()
    assert [r for (r,) in active] == ["MANAGER", "OWNER", "STAFF"]  # unchanged


# --------------------------------------------------------------------------- SHOP-006, CAP-VER-001, SEC-IR-003
@pytest.mark.tid("M07-T009")
def test_verification_lifecycle_with_history(team, owner_conn):
    slug = team.shop["slug"]
    c = team.act("owner")
    assert c.post(f"/api/v1/admin/shops/{slug}/status", json={"status": "ACTIVE", "reason": "looks good"}).status_code == 403
    c.cookies.clear()
    make_admin(c, owner_conn, role="PLATFORM_ADMIN")
    assert c.get("/api/v1/admin/shops/pending").status_code == 200
    bad = c.post(f"/api/v1/admin/shops/{slug}/status", json={"status": "SUSPENDED", "reason": "test"})
    assert bad.status_code == 409  # PENDING -> SUSPENDED is not a valid transition
    for to in ("ACTIVE", "SUSPENDED", "ACTIVE"):
        r = c.post(f"/api/v1/admin/shops/{slug}/status", json={"status": to, "reason": f"step {to}"})
        assert r.status_code == 200 and r.json()["status"] == to
    hist = owner_conn.execute("SELECT from_status, to_status FROM bm.shop_status_history h JOIN bm.shops s "
                              "ON s.id=h.shop_id WHERE s.slug=%s ORDER BY h.id", (slug,)).fetchall()
    assert hist == [(None, "PENDING_VERIFICATION"), ("PENDING_VERIFICATION", "ACTIVE"), ("ACTIVE", "SUSPENDED"),
                    ("SUSPENDED", "ACTIVE")]
    assert "limethibitishwa" in c.app.state.notifier.last_to(e164(team.phone["owner"])).body
    owner = user_row(owner_conn, team.phone["owner"])[0]
    assert owner_conn.execute("SELECT status FROM bm.user_capabilities WHERE user_id=%s AND capability='SELLER'",
                              (owner,)).fetchone()[0] == "ACTIVE"


@pytest.mark.tid("M07-T010")
def test_verification_never_grants_platform_privilege(team, owner_conn, pg, make_settings):
    from app.authz.engine import Authorizer
    from app.db.session import session_factory

    owner_conn.execute("UPDATE bm.shops SET status='ACTIVE' WHERE slug=%s", (team.shop["slug"],))
    owner = user_row(owner_conn, team.phone["owner"])[0]
    owner_conn.execute("UPDATE bm.user_capabilities SET status='ACTIVE', verified_at=now() WHERE user_id=%s", (owner,))
    with session_factory(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url))() as s:
        assert Authorizer(s).platform_permissions(owner) == frozenset()
    c = team.act("owner")
    assert c.get("/api/v1/admin/shops/pending").status_code == 403


# --------------------------------------------------------------------------- SHOP-007/008
@pytest.mark.tid("M07-T011")
def test_shop_page_shows_controls_only_to_members(team, owner_conn):
    slug = team.shop["slug"]
    c = team.act("outsider")
    assert c.get(f"/duka/{slug}").status_code == 404  # not verified yet: customers cannot see it
    assert c.get(f"/api/v1/shops/{slug}").status_code == 404
    owner_conn.execute("UPDATE bm.shops SET status='ACTIVE' WHERE slug=%s", (slug,))
    page = c.get(f"/duka/{slug}").text
    assert "Kuku wa Kienyeji Arusha" in page and "Simamia Duka" not in page and f"/maduka/{slug}" not in page
    assert "status" not in c.get(f"/api/v1/shops/{slug}").json()
    c = team.act("owner")
    page = c.get(f"/duka/{slug}").text
    assert "Simamia Duka" in page and 'href="/soko"' in page and "Mmiliki" in page


@pytest.mark.tid("M07-T012")
def test_no_endpoint_accepts_client_supplied_payment_or_ownership_state(db_client):
    """BR-013/BR-015: request bodies never carry authoritative payment, ownership, price-paid or role state."""
    spec = db_client.get("/openapi.json").json()
    forbidden = {"payment_status", "paid", "is_paid", "owner_user_id", "total", "order_total", "amount_paid"}
    found = []
    for name, schema in spec.get("components", {}).get("schemas", {}).items():
        if name.endswith("In"):
            found += [f"{name}.{p}" for p in schema.get("properties", {}) if p in forbidden]
    assert found == []


@pytest.mark.tid("M07-T013")
def test_web_shop_creation_and_staff_flow(db_client, owner_conn):
    register_and_verify(db_client, name="Neema Duka")
    staff_phone = None
    page = db_client.get("/maduka")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = db_client.post("/maduka", data={"csrf": csrf, "name": "Mayai ya Neema", "region": "Moshi",
                                        "description": "Mayai ya kienyeji"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/maduka/mayai-ya-neema")
    manage = db_client.get("/maduka/mayai-ya-neema").text
    assert "Linasubiri uthibitisho" in manage and "Mmiliki" in manage
    me = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    staff_phone = register_and_verify(db_client, name="Baraka Kazi")
    switch(db_client, me)
    r = db_client.post("/maduka/mayai-ya-neema/wanachama", data={"csrf": csrf, "phone": staff_phone,
                                                                 "role": "STAFF"}, follow_redirects=False)
    assert r.status_code == 303
    assert "Baraka Kazi" in db_client.get("/maduka/mayai-ya-neema").text
    assert "Umeongezwa" in db_client.app.state.notifier.last_to(e164(staff_phone)).body
    assert last_code  # imported helper kept for symmetry with other suites
