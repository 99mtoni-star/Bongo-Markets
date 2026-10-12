"""Module 08 – Categories, Products, Images na Stock."""

from __future__ import annotations

import io
import threading
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from PIL import Image
from psycopg import errors

from tests.conftest import ROOT
from tests.test_m03_auth import register_and_verify
from tests.test_m04_security import make_admin, step_up, switch
from tests.test_m07_shops import People, new_shop


@pytest.fixture(autouse=True)
def _reset(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    from app.authz.engine import CACHE

    CACHE.clear()
    yield


@pytest.fixture
def shop(db_client, owner_conn):
    p = People(db_client)
    c = p.act("owner")
    p.shop = new_shop(c)
    slug = p.shop["slug"]
    c.post(f"/api/v1/shops/{slug}/members", json={"phone": p.phone["staff"], "role": "STAFF"})
    owner_conn.execute("UPDATE bm.shops SET status='ACTIVE' WHERE slug=%s", (slug,))
    return p


def product(client, slug, **kw):
    body = {"name": "Kuku wa kienyeji (jogoo)", "category": "kuku-na-ndege", "price": "18000", "stock": 5, **kw}
    r = client.post(f"/api/v1/shops/{slug}/products", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def png_bytes(size=(400, 300), color=(200, 120, 40)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "PNG")
    return buf.getvalue()


def jpeg_with_gps() -> bytes:
    img = Image.new("RGB", (400, 400), (10, 120, 60))
    exif = Image.Exif()
    exif[0x8825] = {1: "S", 2: (3.0, 22.0, 0.0), 3: "E", 4: (36.0, 41.0, 0.0)}  # GPS near Arusha
    exif[0x010F] = "SecretPhoneMaker"
    buf = io.BytesIO()
    img.save(buf, "JPEG", exif=exif)
    return buf.getvalue()


def upload(client, slug, pid, data: bytes, name="p.png", ctype="image/png"):
    return client.post(f"/api/v1/shops/{slug}/products/{pid}/images", files={"image": (name, data, ctype)})


# --------------------------------------------------------------------------- PRD-001/002, BR-007
@pytest.mark.tid("M08-T001")
def test_product_belongs_to_one_shop_and_staff_cannot_price(shop, owner_conn):
    slug = shop.shop["slug"]
    c = shop.act("owner")
    p = product(c, slug)
    assert p["status"] == "DRAFT" and p["category"] == "kuku-na-ndege" and p["price"] == "18000.00"
    sid, cid = owner_conn.execute("SELECT shop_id, category_id FROM bm.products WHERE public_id=%s",
                                  (p["id"],)).fetchone()
    assert sid and cid
    assert c.post(f"/api/v1/shops/{slug}/products", json={"name": "Bila kundi", "category": "hakuna"}) \
        .status_code == 422
    c = shop.act("staff")
    assert c.post(f"/api/v1/shops/{slug}/products", json={"name": "Mayai trei", "category": "mayai",
                                                          "price": "9000"}).status_code == 403
    draft = product(c, slug, name="Mayai trei", category="mayai", price="0")
    assert draft["status"] == "DRAFT"
    assert c.patch(f"/api/v1/shops/{slug}/products/{draft['id']}", json={"price": "9000"}).status_code == 403
    assert c.patch(f"/api/v1/shops/{slug}/products/{draft['id']}", json={"stock": 30}).json()["stock"] == 30
    c = shop.act("outsider")
    other = new_shop(c, "Duka Jingine")["slug"]
    assert c.patch(f"/api/v1/shops/{other}/products/{p['id']}", json={"name": "x" * 5}).status_code == 404
    assert c.patch(f"/api/v1/shops/{slug}/products/{p['id']}", json={"name": "Hacked"}).status_code == 404


@pytest.mark.tid("M08-T002")
def test_sku_unique_within_shop_only(shop):
    slug = shop.shop["slug"]
    c = shop.act("owner")
    product(c, slug, sku="KUKU-001")
    r = c.post(f"/api/v1/shops/{slug}/products", json={"name": "Nyingine", "category": "mayai", "sku": "kuku-001"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "sku_exists"
    c = shop.act("outsider")
    other = new_shop(c, "Duka la Pili")["slug"]
    assert product(c, other, sku="KUKU-001")["sku"] == "KUKU-001"


@pytest.mark.tid("M08-T003")
def test_price_and_stock_never_negative(shop, owner_conn):
    slug = shop.shop["slug"]
    c = shop.act("owner")
    p = product(c, slug)
    for bad in ({"price": "-1"}, {"price": "10.005"}, {"price": "abc"}):
        assert c.patch(f"/api/v1/shops/{slug}/products/{p['id']}", json=bad).status_code == 422, bad
    assert c.patch(f"/api/v1/shops/{slug}/products/{p['id']}", json={"stock": -1}).status_code == 422
    free = product(c, slug, name="Bure", price="0")
    r = c.patch(f"/api/v1/shops/{slug}/products/{free['id']}", json={"status": "ACTIVE"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "needs_price"
    for stmt in ("UPDATE bm.products SET price = -5 WHERE public_id=%s",
                 "UPDATE bm.products SET stock = -1 WHERE public_id=%s",
                 "UPDATE bm.products SET reserved = stock + 1 WHERE public_id=%s"):
        with pytest.raises(errors.CheckViolation):
            owner_conn.execute(stmt, (p["id"],))
    assert owner_conn.execute("SELECT pg_typeof(price)::text FROM bm.products LIMIT 1").fetchone()[0] == "numeric"


@pytest.mark.tid("M08-T004")
def test_marketplace_visibility_rule(shop, owner_conn, pg, make_settings):
    from app.catalog.models import Product
    from app.catalog.service import CatalogService
    from app.db.session import session_factory
    from app.shops.models import Shop

    slug = shop.shop["slug"]
    c = shop.act("owner")
    p = product(c, slug)
    with session_factory(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url))() as s:
        def visible():
            s.expire_all()
            prod = s.query(Product).filter_by(public_id=p["id"]).one()
            return CatalogService.is_publicly_visible(prod, s.get(Shop, prod.shop_id))

        assert not visible()  # draft
        c.patch(f"/api/v1/shops/{slug}/products/{p['id']}", json={"status": "ACTIVE"})
        assert visible()
        c.patch(f"/api/v1/shops/{slug}/products/{p['id']}", json={"marketplace": False})
        assert not visible()
        c.patch(f"/api/v1/shops/{slug}/products/{p['id']}", json={"marketplace": True})
        owner_conn.execute("UPDATE bm.shops SET status='SUSPENDED' WHERE slug=%s", (slug,))
        assert not visible()


# --------------------------------------------------------------------------- PRD-005, V13-SEC-004, V13-REQ-005
@pytest.mark.tid("M08-T005")
def test_image_validation_reencoding_and_serving(shop, db_client):
    slug = shop.shop["slug"]
    c = shop.act("owner")
    p = product(c, slug)
    ok = upload(c, slug, p["id"], png_bytes())
    assert ok.status_code == 201, ok.text
    served = c.get(ok.json()["url"])
    assert served.status_code == 200 and served.headers["content-type"] == "image/webp"
    assert served.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in served.headers["content-security-policy"]
    gps = upload(c, slug, p["id"], jpeg_with_gps(), "gps.jpg", "image/jpeg")
    assert gps.status_code == 201
    stored = Image.open(io.BytesIO(c.get(gps.json()["url"]).content))
    assert not stored.getexif() and b"SecretPhoneMaker" not in c.get(gps.json()["url"]).content
    rejects = [
        (b"this is not an image" * 10, "fake.jpg", "image/jpeg"),                    # wrong magic
        (b"\x89PNG\r\n\x1a\n" + b"\x00" * 500, "broken.png", "image/png"),           # corrupt
        (png_bytes((50, 50)), "tiny.png", "image/png"),                               # too small
        (b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", "x.svg", "image/svg+xml"),
    ]
    for data, name, ctype in rejects:
        r = upload(c, slug, p["id"], data, name, ctype)
        assert r.status_code == 422 and r.json()["error"]["code"] == "image_rejected", name
    big = upload(c, slug, p["id"], b"\xff\xd8\xff" + b"\x00" * (5 * 1024 * 1024 + 10), "big.jpg", "image/jpeg")
    assert big.status_code == 413
    c = shop.act("outsider")
    assert upload(c, slug, p["id"], png_bytes()).status_code == 404


@pytest.mark.tid("M08-T006")
def test_decompression_bomb_is_rejected():
    from app.catalog.media import ImageRejected, clean_image

    buf = io.BytesIO()
    Image.new("1", (12000, 12000)).save(buf, "PNG")  # tiny file, 144 MP when decoded
    assert len(buf.getvalue()) < 5 * 1024 * 1024
    with pytest.raises(ImageRejected):
        clean_image(buf.getvalue())


# --------------------------------------------------------------------------- STK-001..004
def _svc_session(pg, make_settings):
    from app.db.session import session_factory

    return session_factory(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url))


def _pid(owner_conn, public_id):
    return owner_conn.execute("SELECT id FROM bm.products WHERE public_id=%s", (public_id,)).fetchone()[0]


@pytest.mark.tid("M08-T007")
def test_reserve_commit_release_with_default_15_minutes(shop, owner_conn, pg, make_settings):
    from app.catalog import stock

    owner_conn.execute("UPDATE bm.system_flags SET value='15' WHERE key='stock_reservation_minutes'")
    c = shop.act("owner")
    p = product(c, shop.shop["slug"], stock=5)
    c.patch(f"/api/v1/shops/{shop.shop['slug']}/products/{p['id']}", json={"status": "ACTIVE"})
    pid = _pid(owner_conn, p["id"])
    factory = _svc_session(pg, make_settings)
    with factory() as s:
        r1 = stock.reserve(s, pid, 2, "order:a")
        assert timedelta(minutes=14, seconds=50) < r1.expires_at - datetime.now(UTC) <= timedelta(minutes=15)
        r2 = stock.reserve(s, pid, 3, "order:b")
        s.commit()
        with pytest.raises(stock.StockError) as e:
            stock.reserve(s, pid, 1, "order:c")
        assert e.value.code == "insufficient_stock"
        s.rollback()
        stock.commit(s, r1.id)
        stock.release(s, r2.id, note="payment failed")
        s.commit()
    assert owner_conn.execute("SELECT stock, reserved FROM bm.products WHERE id=%s", (pid,)).fetchone() == (3, 0)


@pytest.mark.tid("M08-T008")
def test_only_one_buyer_gets_the_last_unit(shop, owner_conn, pg, make_settings):
    from app.catalog import stock

    c = shop.act("owner")
    p = product(c, shop.shop["slug"], stock=1)
    c.patch(f"/api/v1/shops/{shop.shop['slug']}/products/{p['id']}", json={"status": "ACTIVE"})
    pid = _pid(owner_conn, p["id"])
    factory = _svc_session(pg, make_settings)
    results, barrier = [], threading.Barrier(10)

    def buyer(n):
        with factory() as s:
            barrier.wait()
            try:
                stock.reserve(s, pid, 1, f"order:{n}")
                s.commit()
                results.append("won")
            except stock.StockError:
                s.rollback()
                results.append("sold-out")

    threads = [threading.Thread(target=buyer, args=(i,)) for i in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count("won") == 1 and results.count("sold-out") == 9
    assert owner_conn.execute("SELECT stock, reserved FROM bm.products WHERE id=%s", (pid,)).fetchone() == (1, 1)


@pytest.mark.tid("M08-T009")
def test_expired_reservations_release_stock_and_cannot_commit(shop, owner_conn, pg, make_settings):
    from app.catalog import stock

    c = shop.act("owner")
    p = product(c, shop.shop["slug"], stock=2)
    c.patch(f"/api/v1/shops/{shop.shop['slug']}/products/{p['id']}", json={"status": "ACTIVE"})
    pid = _pid(owner_conn, p["id"])
    factory = _svc_session(pg, make_settings)
    with factory() as s:
        r = stock.reserve(s, pid, 2, "order:late")
        s.commit()
        later = datetime.now(UTC) + timedelta(minutes=16)
        with pytest.raises(stock.StockError) as e:
            stock.commit(s, r.id, now=later)
        assert e.value.code == "reservation_expired"
        s.commit()
    assert owner_conn.execute("SELECT stock, reserved FROM bm.products WHERE id=%s", (pid,)).fetchone() == (2, 0)
    with factory() as s:
        stock.reserve(s, pid, 1, "order:x")
        s.commit()
        assert stock.expire_all(s, now=datetime.now(UTC) + timedelta(hours=1)) >= 1  # global sweep
        s.commit()
    assert owner_conn.execute("SELECT reserved FROM bm.products WHERE id=%s", (pid,)).fetchone()[0] == 0


@pytest.mark.tid("M08-T010")
def test_reservation_timeout_is_admin_configurable(db_client, owner_conn, pg, make_settings):
    from app.catalog import stock

    register_and_verify(db_client)
    url = "/api/v1/admin/settings/stock-reservation-minutes"
    assert db_client.put(url, json={"minutes": 20}).status_code == 403
    db_client.cookies.clear()
    _, totp = make_admin(db_client, owner_conn, role="PLATFORM_ADMIN")
    assert db_client.put(url, json={"minutes": 20}).status_code == 403  # step-up required
    bad = db_client.put(url, json={"minutes": 500},
                        headers={"X-Step-Up-Token": step_up(db_client, "SETTINGS_CHANGE", totp)})
    assert bad.status_code == 422
    ok = db_client.put(url, json={"minutes": 20},
                       headers={"X-Step-Up-Token": step_up(db_client, "SETTINGS_CHANGE", totp)})
    assert ok.status_code == 200 and ok.json()["minutes"] == 20
    with _svc_session(pg, make_settings)() as s:
        assert stock.reservation_minutes(s) == 20
    owner_conn.execute("UPDATE bm.system_flags SET value='15' WHERE key='stock_reservation_minutes'")


@pytest.mark.tid("M08-T011")
def test_stock_cannot_drop_below_reserved(shop, owner_conn, pg, make_settings):
    from app.catalog import stock

    slug = shop.shop["slug"]
    c = shop.act("owner")
    p = product(c, slug, stock=4)
    c.patch(f"/api/v1/shops/{slug}/products/{p['id']}", json={"status": "ACTIVE"})
    with _svc_session(pg, make_settings)() as s:
        stock.reserve(s, _pid(owner_conn, p["id"]), 3, "order:hold")
        s.commit()
    r = c.patch(f"/api/v1/shops/{slug}/products/{p['id']}", json={"stock": 2})
    assert r.status_code == 409 and r.json()["error"]["code"] == "below_reserved"


# --------------------------------------------------------------------------- BR-009 / BR-010 (M07 rules)
@pytest.mark.tid("M08-T012")
def test_shop_page_lists_only_its_products_and_categories(shop, owner_conn):
    slug = shop.shop["slug"]
    c = shop.act("owner")
    for kw in ({"name": "Jogoo mkubwa", "category": "kuku-na-ndege"}, {"name": "Mayai trei 30", "category": "mayai"}):
        p = product(c, slug, **kw)
        c.patch(f"/api/v1/shops/{slug}/products/{p['id']}", json={"status": "ACTIVE"})
    product(c, slug, name="Rasimu siri", category="vinywaji")  # draft: hidden
    c = shop.act("outsider")
    other = new_shop(c, "Duka la Simu")["slug"]
    owner_conn.execute("UPDATE bm.shops SET status='ACTIVE' WHERE slug=%s", (other,))
    q = product(c, other, name="Simu ndogo", category="simu-na-elektroniki", price="45000")
    c.patch(f"/api/v1/shops/{other}/products/{q['id']}", json={"status": "ACTIVE"})
    page = c.get(f"/duka/{slug}").text
    assert "Jogoo mkubwa" in page and "Mayai trei 30" in page
    assert "Simu ndogo" not in page and "Rasimu siri" not in page
    headings = [h for h in ("Kuku na ndege", "Mayai", "Vinywaji", "Simu na elektroniki") if f">{h}</h2>" in page]
    assert headings == ["Kuku na ndege", "Mayai"]
    api = c.get(f"/api/v1/shops/{slug}/products").json()["products"]
    assert {p["name"] for p in api} == {"Jogoo mkubwa", "Mayai trei 30"} and "stock" not in api[0]


@pytest.mark.tid("M08-T013")
def test_patch_management_process_documented():
    doc = (ROOT / "docs" / "operations" / "patch-management.md").read_text()
    for sev in ("Critical", "High", "Medium", "Low"):
        assert sev in doc
    assert "days" in doc


@pytest.mark.tid("M08-T014")
def test_web_product_flow_with_image(shop):
    import re

    slug = shop.shop["slug"]
    c = shop.act("owner")
    page = c.get(f"/maduka/{slug}/bidhaa")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = c.post(f"/maduka/{slug}/bidhaa", data={"csrf": csrf, "name": "Kuku wa kienyeji", "category": "kuku-na-ndege",
                                               "price": "18000", "stock": "12", "unit": "kipande",
                                               "description": "Freshi"}, follow_redirects=False)
    assert r.status_code == 303
    edit = r.headers["location"].split("?")[0]
    r = c.post(f"{edit}/picha", data={"csrf": csrf}, files={"image": ("k.png", png_bytes(), "image/png")},
               follow_redirects=False)
    assert r.status_code == 303
    r = c.post(edit, data={"csrf": csrf, "name": "Kuku wa kienyeji", "category": "kuku-na-ndege", "price": "18000",
                           "stock": "12", "unit": "kipande", "description": "Freshi", "status": "ACTIVE"},
               follow_redirects=False)
    assert r.status_code == 303
    public = shop.act("outsider").get(f"/duka/{slug}").text
    assert "Kuku wa kienyeji" in public and "TZS 18,000" in public and "/media/" in public
    assert Decimal("18000") and switch
