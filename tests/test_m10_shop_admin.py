"""Module 10 – Shop Page na Shop Admin (SHOP-005)."""

from __future__ import annotations

import pytest

from tests.test_m07_shops import People, new_shop


@pytest.fixture(autouse=True)
def _reset(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    from app.authz.engine import CACHE

    CACHE.clear()
    yield


@pytest.fixture
def team(db_client):
    p = People(db_client)
    c = p.act("owner")
    p.slug = new_shop(c, "Duka la Timu")["slug"]
    c.post(f"/api/v1/shops/{p.slug}/members", json={"phone": p.phone["manager"], "role": "MANAGER"})
    c.post(f"/api/v1/shops/{p.slug}/members", json={"phone": p.phone["staff"], "role": "STAFF"})
    c = p.act("outsider")
    p.other = new_shop(c, "Duka la Mgeni")["slug"]
    return p


@pytest.mark.tid("M10-T001")
def test_shop_admin_lists_only_authorized_shops(team):
    for who, expected in (("owner", {team.slug}), ("manager", {team.slug}), ("staff", {team.slug}),
                          ("outsider", {team.other})):
        c = team.act(who)
        assert {s["slug"] for s in c.get("/api/v1/shops/mine").json()["shops"]} == expected, who
        page = c.get("/maduka").text
        assert (f"/maduka/{team.slug}'" in page) == (team.slug in expected)
    c = team.act("owner")
    c.delete(f"/api/v1/shops/{team.slug}/members/{team.pid['staff']}")
    c = team.act("staff")
    assert c.get("/api/v1/shops/mine").json()["shops"] == []


@pytest.mark.tid("M10-T002")
def test_dashboard_only_for_members_and_scoped_by_permission(team, owner_conn):
    sid = owner_conn.execute("SELECT id FROM bm.shops WHERE slug=%s", (team.slug,)).fetchone()[0]
    cid = owner_conn.execute("SELECT id FROM bm.categories WHERE slug='mayai'").fetchone()[0]
    owner_conn.execute("INSERT INTO bm.products(shop_id, category_id, sku, name, unit, price, stock, reserved, status, "
                       "marketplace, featured) VALUES (%s,%s,'LOW1','Mayai karibu kuisha','trei',9000,2,0,'ACTIVE',"
                       "true,false)", (sid, cid))
    c = team.act("owner")
    d = c.get(f"/api/v1/shops/{team.slug}/dashboard").json()
    assert d["my_role"] == "OWNER" and d["products"]["active"] == 1 and d["team_size"] == 3
    assert d["low_stock"] == [{"name": "Mayai karibu kuisha", "available": 2}]
    assert "shop.ownership.transfer" in d["permissions"]
    c = team.act("staff")
    d = c.get(f"/api/v1/shops/{team.slug}/dashboard").json()
    assert d["my_role"] == "STAFF" and "shop.ownership.transfer" not in d["permissions"]
    page = c.get(f"/maduka/{team.slug}").text
    assert "Hamisha umiliki" not in page and "Taarifa za duka" not in page and "Stock inakaribia kuisha" in page
    c = team.act("outsider")
    assert c.get(f"/api/v1/shops/{team.slug}/dashboard").status_code == 404
    assert c.get(f"/maduka/{team.slug}").status_code == 404


ROLE_MATRIX = [
    # (method, path template, body, {role: expected status})
    ("PATCH", "/api/v1/shops/{slug}", {"name": "Jina Jipya la Duka"},
     {"owner": 200, "manager": 200, "staff": 403, "outsider": 404}),
    ("POST", "/api/v1/shops/{slug}/members", {"phone": "{outsider_phone}", "role": "MANAGER"},
     {"owner": 201, "manager": 403, "staff": 403, "outsider": 404}),
    ("POST", "/api/v1/shops/{slug}/products", {"name": "Bidhaa ya majaribio", "category": "mayai"},
     {"owner": 201, "manager": 201, "staff": 201, "outsider": 404}),
    ("GET", "/api/v1/shops/{slug}/history", None, {"owner": 200, "manager": 200, "staff": 200, "outsider": 404}),
]


@pytest.mark.tid("M10-T003")
@pytest.mark.parametrize("method,path,body,expected", ROLE_MATRIX)
def test_shop_admin_operation_matrix(team, owner_conn, method, path, body, expected):
    for who in ("outsider", "staff", "manager", "owner"):  # least privileged first
        c = team.act(who)
        b = None
        if body:
            b = {k: (v.replace("{outsider_phone}", team.phone["outsider"]) if isinstance(v, str) else v)
                 for k, v in body.items()}
            if "name" in b and path.endswith("/products"):
                b["name"] = f"{b['name']} {who}"
        r = c.request(method, path.format(slug=team.slug), json=b)
        assert r.status_code == expected[who], (who, path, r.text)
