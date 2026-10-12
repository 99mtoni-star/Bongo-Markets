"""Module 09 – Bongo Markets Sokoni, Search na Filtering."""

from __future__ import annotations

import itertools
import re

import pytest

from tests.conftest import ROOT
from tests.test_m03_auth import register_and_verify
from tests.test_m04_security import make_admin
from tests.test_m07_shops import new_shop

_n = itertools.count(1)


@pytest.fixture(autouse=True)
def _reset(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    # Isolate the marketplace: park every product created by earlier tests.
    owner_conn.execute("UPDATE bm.products SET marketplace = false, featured = false")
    yield


def seed_shop(owner_conn, client, name, region="Arusha", status="ACTIVE") -> tuple[str, int]:
    client.cookies.clear()
    register_and_verify(client)
    slug = new_shop(client, name, region=region)["slug"]
    owner_conn.execute("UPDATE bm.shops SET status=%s WHERE slug=%s", (status, slug))
    sid = owner_conn.execute("SELECT id FROM bm.shops WHERE slug=%s", (slug,)).fetchone()[0]
    return slug, sid


def add(owner_conn, sid, name, price, category="kuku-na-ndege", status="ACTIVE", marketplace=True,
        description=None, featured=False) -> str:
    cid = owner_conn.execute("SELECT id FROM bm.categories WHERE slug=%s", (category,)).fetchone()[0]
    return str(owner_conn.execute(
        "INSERT INTO bm.products(shop_id, category_id, sku, name, description, unit, price, stock, reserved, status, "
        "marketplace, featured) VALUES (%s,%s,%s,%s,%s,'kipande',%s,10,0,%s,%s,%s) RETURNING public_id",
        (sid, cid, f"T{next(_n)}", name, description, price, status, marketplace, featured)).fetchone()[0])


def names(resp) -> list[str]:
    return [p["name"] for p in resp.json()["products"]]


@pytest.mark.tid("M09-T001")
def test_marketplace_lists_only_visible_products_across_shops(db_client, owner_conn):
    _, a = seed_shop(owner_conn, db_client, "Kuku Arusha")
    _, b = seed_shop(owner_conn, db_client, "Mayai Moshi", region="Moshi")
    _, pending = seed_shop(owner_conn, db_client, "Duka Jipya", status="PENDING_VERIFICATION")
    _, suspended = seed_shop(owner_conn, db_client, "Duka Lililosimamishwa", status="SUSPENDED")
    add(owner_conn, a, "Jogoo", 18000)
    add(owner_conn, b, "Trei ya mayai", 12000, "mayai")
    add(owner_conn, a, "Rasimu", 1000, status="DRAFT")
    add(owner_conn, a, "Nje ya soko", 1000, marketplace=False)
    add(owner_conn, pending, "Duka halijathibitishwa", 1000)
    add(owner_conn, suspended, "Duka limesimamishwa", 1000)
    got = names(db_client.get("/api/v1/marketplace/products"))
    assert sorted(got) == ["Jogoo", "Trei ya mayai"]
    shops = {p["shop"]["name"] for p in db_client.get("/api/v1/marketplace/products").json()["products"]}
    assert shops == {"Kuku Arusha", "Mayai Moshi"}


@pytest.mark.tid("M09-T002")
def test_search_and_filters(db_client, owner_conn):
    _, a = seed_shop(owner_conn, db_client, "Kuku wa Kienyeji Arusha", region="Arusha")
    _, b = seed_shop(owner_conn, db_client, "Mama Neema Dar", region="Dar es Salaam")
    add(owner_conn, a, "Jogoo mkubwa", 18000)
    add(owner_conn, a, "Tetea", 15000, description="kuku jike wa kienyeji")
    add(owner_conn, b, "Mayai trei 30", 12000, "mayai")
    add(owner_conn, b, "Kuku wa nyama (broiler)", 9000)
    g = db_client.get
    assert sorted(names(g("/api/v1/marketplace/products?q=jogoo"))) == ["Jogoo mkubwa"]
    assert "Tetea" in names(g("/api/v1/marketplace/products?q=JIKE"))            # description, case-insensitive
    assert set(names(g("/api/v1/marketplace/products?q=neema"))) == {"Mayai trei 30", "Kuku wa nyama (broiler)"}
    assert names(g("/api/v1/marketplace/products?category=mayai")) == ["Mayai trei 30"]
    assert set(names(g("/api/v1/marketplace/products?min_price=10000&max_price=16000"))) == {"Tetea",
                                                                                            "Mayai trei 30"}
    assert set(names(g("/api/v1/marketplace/products?region=dar"))) == {"Mayai trei 30", "Kuku wa nyama (broiler)"}
    assert names(g("/api/v1/marketplace/products?q=%25")) == []                    # wildcard is literal
    assert names(g("/api/v1/marketplace/products?q=' OR 1=1 --")) == []            # inert
    assert g("/api/v1/marketplace/products?min_price=abc").status_code == 200       # bad input ignored safely


@pytest.mark.tid("M09-T003")
def test_batches_of_24_until_exhausted_without_gaps(db_client, owner_conn):
    _, sid = seed_shop(owner_conn, db_client, "Duka Kubwa")
    expected = {add(owner_conn, sid, f"Bidhaa {i:02d}", 1000 + (i % 7) * 500) for i in range(60)}
    for sort in ("newest", "price_asc", "price_desc"):
        seen, cursor, batches = [], "", 0
        while True:
            r = db_client.get(f"/api/v1/marketplace/products?sort={sort}&cursor={cursor}").json()
            batches += 1
            assert len(r["products"]) <= 24
            seen += [p["id"] for p in r["products"]]
            if batches == 1:
                add(owner_conn, sid, "Imeongezwa katikati", 1200)  # inserts must not cause duplicates
            if not r["next_cursor"]:
                break
            cursor = r["next_cursor"]
        assert len(seen) == len(set(seen))
        assert expected <= set(seen) and batches >= 3, sort
        prices = [float(p["price"]) for p in db_client.get(f"/api/v1/marketplace/products?sort={sort}")
                  .json()["products"]]
        if sort == "price_asc":
            assert prices == sorted(prices)
        if sort == "price_desc":
            assert prices == sorted(prices, reverse=True)
        owner_conn.execute("UPDATE bm.products SET marketplace=false WHERE name='Imeongezwa katikati'")


@pytest.mark.tid("M09-T004")
def test_featured_is_a_highlight_not_a_condition(db_client, owner_conn):
    _, sid = seed_shop(owner_conn, db_client, "Duka la Maalum")
    star = add(owner_conn, sid, "Kuku maalum", 20000)
    add(owner_conn, sid, "Kuku wa kawaida", 15000)
    assert set(names(db_client.get("/api/v1/marketplace/products"))) == {"Kuku maalum", "Kuku wa kawaida"}
    assert names(db_client.get("/api/v1/marketplace/featured")) == []
    slug = owner_conn.execute("SELECT slug FROM bm.shops WHERE id=%s", (sid,)).fetchone()[0]
    r = db_client.patch(f"/api/v1/shops/{slug}/products/{star}", json={"featured": True})
    assert r.status_code == 422  # sellers cannot self-feature
    assert db_client.patch(f"/api/v1/admin/products/{star}/featured",
                           json={"featured": True, "reason": "promo"}).status_code == 403
    db_client.cookies.clear()
    make_admin(db_client, owner_conn, role="MODERATOR")
    r = db_client.patch(f"/api/v1/admin/products/{star}/featured", json={"featured": True, "reason": "promo"})
    assert r.status_code == 200
    assert names(db_client.get("/api/v1/marketplace/featured")) == ["Kuku maalum"]
    assert set(names(db_client.get("/api/v1/marketplace/products"))) == {"Kuku maalum", "Kuku wa kawaida"}
    page = db_client.get("/soko").text
    assert "Bidhaa maalum" in page and page.count("Kuku maalum") == 2


@pytest.mark.tid("M09-T005")
def test_shop_scoped_listing_and_dynamic_categories(db_client, owner_conn):
    slug, a = seed_shop(owner_conn, db_client, "Duka la Kuku")
    _, b = seed_shop(owner_conn, db_client, "Duka la Vinywaji")
    add(owner_conn, a, "Jogoo", 18000)
    add(owner_conn, a, "Mayai", 12000, "mayai")
    add(owner_conn, b, "Soda", 1000, "vinywaji")
    assert set(names(db_client.get(f"/api/v1/marketplace/products?shop={slug}"))) == {"Jogoo", "Mayai"}
    page = db_client.get(f"/duka/{slug}").text
    assert "Soda" not in page and ">Vinywaji</h2>" not in page
    assert ">Kuku na ndege</h2>" in page and ">Mayai</h2>" in page


@pytest.mark.tid("M09-T006")
def test_product_page_only_for_visible_products(db_client, owner_conn):
    _, sid = seed_shop(owner_conn, db_client, "Duka la Detail")
    ok = add(owner_conn, sid, "Jogoo wa detail", 18000, description="Jogoo freshi")
    draft = add(owner_conn, sid, "Siri", 1000, status="DRAFT")
    page = db_client.get(f"/bidhaa/{ok}")
    assert page.status_code == 200 and "Jogoo freshi" in page.text and "TZS 18,000" in page.text
    assert db_client.get(f"/bidhaa/{draft}").status_code == 404
    assert db_client.get("/api/v1/marketplace/products/not-a-uuid").status_code == 404


@pytest.mark.tid("M09-T007")
def test_web_marketplace_pages_through_batches(db_client, owner_conn):
    _, sid = seed_shop(owner_conn, db_client, "Duka la Ukurasa")
    for i in range(30):
        add(owner_conn, sid, f"Kitu {i:02d}", 2000)
    first = db_client.get("/soko")
    assert first.status_code == 200 and first.text.count("class='pcard'") == 24
    nxt = re.search(r"href='/soko\?([^']*cursor=[^']+)'", first.text).group(1).replace("&amp;", "&")
    second = db_client.get(f"/soko?{nxt}")
    assert second.text.count("class='pcard'") == 6 and "Umeona bidhaa zote" in second.text
    assert "<script" not in first.text.lower()


@pytest.mark.tid("M09-T008")
def test_deferred_capabilities_and_search_scaling_are_recorded():
    doc = (ROOT / "docs" / "modules" / "M09" / "design.md").read_text()
    for cap in ("CAP-B2C-001", "CAP-MOQ-001", "CAP-RFQ-001", "CAP-BRD-001", "CAP-SPON-001", "CAP-UX-001",
                "V13-REQ-004"):
        assert cap in doc
