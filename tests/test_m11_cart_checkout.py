"""Module 11 – Cart, Checkout na Stock Reservation (BR-018, CART-001/002/003, CART-001 v1.12)."""

from __future__ import annotations

import re
import threading
import uuid

import psycopg
import pytest

from tests.conftest import TEST_CSRF, _browser_like_client
from tests.test_m03_auth import e164, register_and_verify
from tests.test_m04_security import switch
from tests.test_m07_shops import People, new_shop
from tests.test_m09_market import add

ADDR = {"name": "Amina Juma", "phone": "0754 000 111", "region": "Dar es Salaam", "area": "Kariakoo",
        "street": "Mtaa wa Congo", "notes": "Piga simu ukifika"}


@pytest.fixture(autouse=True)
def _reset(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    from app.authz.engine import CACHE

    CACHE.clear()
    yield


class Market:
    """Two active shops with products, a seller team and two buyers."""

    def __init__(self, client, owner_conn):
        self.client, self.db = client, owner_conn
        self.p = People(client)  # owner, manager, staff, outsider (outsider owns the second shop)
        c = self.p.act("owner")
        self.slug = new_shop(c, "Duka la Kuku")["slug"]
        c.post(f"/api/v1/shops/{self.slug}/members", json={"phone": self.p.phone["manager"], "role": "MANAGER"})
        c.post(f"/api/v1/shops/{self.slug}/members", json={"phone": self.p.phone["staff"], "role": "STAFF"})
        c = self.p.act("outsider")
        self.slug2 = new_shop(c, "Duka la Mayai")["slug"]
        owner_conn.execute("UPDATE bm.shops SET status='ACTIVE' WHERE slug IN (%s,%s)", (self.slug, self.slug2))
        self.sid = self.shop_id(self.slug)
        self.sid2 = self.shop_id(self.slug2)
        self.kuku = add(owner_conn, self.sid, "Jogoo wa kienyeji", 18000)
        self.bata = add(owner_conn, self.sid, "Bata mzinga", 45000)
        self.mayai = add(owner_conn, self.sid2, "Trei ya mayai", 12000, "mayai")
        for who in ("buyer", "buyer2"):
            client.cookies.clear()
            self.p.phone[who] = register_and_verify(client, name=f"{who.title()} Mnunuzi")
            self.p.cookie[who] = client.cookies.get("bm_session")

    def uid(self, who):
        return self.db.execute("SELECT id FROM bm.users WHERE phone_e164=%s", (e164(self.p.phone[who]),)).fetchone()[0]

    def shop_id(self, slug):
        return self.db.execute("SELECT id FROM bm.shops WHERE slug=%s", (slug,)).fetchone()[0]

    def act(self, who):
        switch(self.client, self.p.cookie[who])
        return self.client

    def stock(self, public_id):
        return self.db.execute("SELECT stock, reserved FROM bm.products WHERE public_id=%s", (public_id,)).fetchone()


@pytest.fixture
def mk(db_client, owner_conn):
    return Market(db_client, owner_conn)


def put(c, pid, qty=1):
    return c.post("/api/v1/cart/items", json={"product_id": pid, "quantity": qty})


def checkout(c, key=None, **kw):
    return c.post("/api/v1/checkout", json={**ADDR, **kw}, headers={"Idempotency-Key": key or uuid.uuid4().hex})


def pay(c, number):
    r = c.post(f"/dev/lipa/{number}", data={"csrf": TEST_CSRF}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return r


def place(mk, who="buyer", items=None, **kw):
    """Put items in the buyer's cart and check out; return the checkout response JSON."""
    c = mk.act(who)
    for pid, q in (items or [(mk.kuku, 1)]):
        assert put(c, pid, q).status_code == 201
    r = checkout(c, **kw)
    assert r.status_code == 201, r.text
    return r.json()


# --------------------------------------------------------------------------- BR-018, CART-001, CART-002
@pytest.mark.tid("M11-T001")
def test_one_active_cart_and_one_row_per_product(mk, owner_conn):
    c = mk.act("buyer")
    assert put(c, mk.kuku, 2).status_code == 201
    r = put(c, mk.kuku, 3)
    assert r.status_code == 201
    cart = r.json()
    assert cart["count"] == 1 and cart["groups"][0]["items"][0]["quantity"] == 5
    uid = mk.uid("buyer")
    cart_id = owner_conn.execute("SELECT id FROM bm.carts WHERE user_id=%s AND status='ACTIVE'", (uid,)).fetchone()[0]
    with pytest.raises(psycopg.errors.UniqueViolation):  # BR-018 enforced by the database
        owner_conn.execute("INSERT INTO bm.carts(user_id, status) VALUES (%s, 'ACTIVE')", (uid,))
    pid = owner_conn.execute("SELECT id FROM bm.products WHERE public_id=%s", (mk.kuku,)).fetchone()[0]
    with pytest.raises(psycopg.errors.UniqueViolation):  # CART-002 enforced by the database
        owner_conn.execute("INSERT INTO bm.cart_items(cart_id, product_id, quantity) VALUES (%s,%s,1)", (cart_id, pid))
    # concurrent first-adds from the same user still produce one active cart
    mk.act("buyer2")
    clients = []
    for _ in range(5):
        cl = _browser_like_client(mk.client.app)
        cl.cookies.set("bm_session", mk.p.cookie["buyer2"])
        clients.append(cl)
    barrier, codes = threading.Barrier(5), []

    def go(cl):
        barrier.wait()
        codes.append(put(cl, mk.mayai, 1).status_code)

    ts = [threading.Thread(target=go, args=(cl,)) for cl in clients]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert codes == [201] * 5
    assert owner_conn.execute("SELECT count(*) FROM bm.carts WHERE user_id=%s AND status='ACTIVE'",
                              (mk.uid("buyer2"),)).fetchone()[0] == 1
    assert mk.act("buyer2").get("/api/v1/cart").json()["groups"][0]["items"][0]["quantity"] == 5
    assert owner_conn.execute("SELECT max(n) FROM (SELECT count(*) n FROM bm.carts WHERE status='ACTIVE' "
                              "GROUP BY user_id) x").fetchone()[0] == 1


@pytest.mark.tid("M11-T002")
def test_cart_never_takes_prices_or_hidden_products_from_the_client(mk, owner_conn):
    c = mk.act("buyer")
    r = c.post("/api/v1/cart/items", json={"product_id": mk.kuku, "quantity": 1, "price": "1"})
    assert r.status_code == 422  # unknown field rejected
    draft = add(owner_conn, mk.sid, "Rasimu", 1000, status="DRAFT")
    hidden = add(owner_conn, mk.sid, "Nje ya soko", 1000, marketplace=False)
    for pid in (draft, hidden, str(uuid.uuid4()), "si-uuid"):
        assert put(c, pid).status_code == 404
    assert put(c, mk.kuku, 11).status_code == 409  # only 10 in stock
    assert put(c, mk.kuku, 1000).status_code == 422
    cols = {r[0] for r in owner_conn.execute("SELECT column_name FROM information_schema.columns "
                                             "WHERE table_schema='bm' AND table_name='cart_items'")}
    assert not cols & {"price", "unit_price", "total"}  # the cart stores quantities only


# --------------------------------------------------------------------------- CART-003, CART-001 v1.12, BR-014
@pytest.mark.tid("M11-T003")
def test_checkout_revalidates_price_from_the_database(mk, owner_conn):
    c = mk.act("buyer")
    put(c, mk.kuku, 2)
    assert c.get("/api/v1/cart").json()["total"] == "36000.00"
    owner_conn.execute("UPDATE bm.products SET price=20000 WHERE public_id=%s", (mk.kuku,))  # seller changed price
    r = checkout(c, expected_total="36000.00")
    assert r.status_code == 409 and r.json()["error"]["code"] == "price_changed"
    assert r.json()["error"]["cart"]["total"] == "40000.00"
    assert owner_conn.execute("SELECT count(*) FROM bm.orders WHERE buyer_user_id=%s",
                              (mk.uid("buyer"),)).fetchone()[0] == 0
    assert mk.stock(mk.kuku) == (10, 0)
    r = checkout(c, expected_total="40000.00")
    assert r.status_code == 201, r.text
    order = r.json()["orders"][0]
    assert order["total"] == "40000.00"
    assert owner_conn.execute("SELECT unit_price, line_total FROM bm.order_items oi JOIN bm.orders o "
                              "ON o.id=oi.order_id WHERE o.number=%s", (order["number"],)).fetchone() == (20000, 40000)


@pytest.mark.tid("M11-T004")
def test_checkout_is_idempotent_per_key(mk, owner_conn):
    c = mk.act("buyer")
    put(c, mk.kuku, 1)
    key = uuid.uuid4().hex
    first = checkout(c, key=key)
    again = checkout(c, key=key)
    assert first.status_code == 201 and again.status_code == 200
    assert again.json()["replayed"] is True and again.json()["orders"] == first.json()["orders"]
    assert owner_conn.execute("SELECT count(*) FROM bm.checkouts WHERE idempotency_key=%s", (key,)).fetchone()[0] == 1
    assert mk.stock(mk.kuku) == (10, 1)  # reserved once, not twice
    put(c, mk.kuku, 1)
    other = checkout(c, key=key, region="Arusha")
    assert other.status_code == 409 and other.json()["error"]["code"] == "idempotency_conflict"
    assert checkout(c, key="short").status_code == 422
    r = c.post("/api/v1/checkout", json=ADDR)
    assert r.status_code == 422  # no Idempotency-Key


@pytest.mark.tid("M11-T005")
def test_checkout_reserves_stock_and_creates_one_order_per_shop(mk, owner_conn):
    res = place(mk, items=[(mk.kuku, 2), (mk.bata, 1), (mk.mayai, 3)], expected_total="117000.00")
    assert len(res["orders"]) == 2
    totals = sorted(o["total"] for o in res["orders"])
    assert totals == ["36000.00", "81000.00"]
    assert all(re.fullmatch(r"BM\d{4}-\d{6}", o["number"]) and o["status"] == "PENDING_PAYMENT"
               for o in res["orders"])
    assert mk.stock(mk.kuku) == (10, 2) and mk.stock(mk.bata) == (10, 1) and mk.stock(mk.mayai) == (10, 3)
    holders = owner_conn.execute("SELECT DISTINCT holder FROM bm.stock_reservations sr JOIN bm.products p "
                                 "ON p.id=sr.product_id WHERE p.public_id IN (%s,%s,%s)",
                                 (mk.kuku, mk.bata, mk.mayai)).fetchall()
    assert len(holders) == 2 and all(h[0].startswith("order:") for h in holders)
    c = mk.act("buyer")
    assert c.get("/api/v1/cart").json()["count"] == 0  # cart was checked out; a new one starts empty
    assert checkout(c).json()["error"]["code"] == "empty_cart"


@pytest.mark.tid("M11-T006")
def test_checkout_is_all_or_nothing(mk, owner_conn):
    c = mk.act("buyer")
    put(c, mk.kuku, 2)
    put(c, mk.mayai, 5)
    owner_conn.execute("UPDATE bm.products SET stock=3 WHERE public_id=%s", (mk.mayai,))  # sold elsewhere meanwhile
    r = checkout(c)
    assert r.status_code == 409 and r.json()["error"]["code"] == "insufficient_stock"
    assert mk.stock(mk.kuku) == (10, 0) and mk.stock(mk.mayai) == (3, 0)
    assert owner_conn.execute("SELECT count(*) FROM bm.orders WHERE buyer_user_id=%s",
                              (mk.uid("buyer"),)).fetchone()[0] == 0
    assert c.get("/api/v1/cart").json()["count"] == 2  # cart untouched, buyer can fix it
    owner_conn.execute("UPDATE bm.products SET status='SUSPENDED' WHERE public_id=%s", (mk.mayai,))
    r = checkout(c)
    assert r.status_code == 409 and r.json()["error"]["code"] == "product_unavailable"
    assert c.get("/api/v1/cart").json()["groups"][-1]["items"][0]["problem"] == "Haipatikani tena"


@pytest.mark.tid("M11-T007")
def test_concurrent_checkouts_for_the_last_unit_only_one_wins(mk, owner_conn):
    owner_conn.execute("UPDATE bm.products SET stock=1 WHERE public_id=%s", (mk.bata,))
    buyers = []
    for _ in range(6):
        owner_conn.execute("DELETE FROM bm.rate_limit_buckets")  # registration rate limit is per client IP
        cl = _browser_like_client(mk.client.app)
        register_and_verify(cl)
        assert put(cl, mk.bata, 1).status_code == 201
        buyers.append(cl)
    barrier, codes = threading.Barrier(len(buyers)), []

    def go(cl):
        barrier.wait()
        codes.append(checkout(cl).status_code)

    ts = [threading.Thread(target=go, args=(cl,)) for cl in buyers]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(codes) == [201, 409, 409, 409, 409, 409]
    assert mk.stock(mk.bata) == (1, 1)
    assert owner_conn.execute("SELECT count(*) FROM bm.order_items oi JOIN bm.products p ON p.id=oi.product_id "
                              "WHERE p.public_id=%s", (mk.bata,)).fetchone()[0] == 1


@pytest.mark.tid("M11-T008")
def test_cart_and_checkout_pages_work_without_javascript(mk):
    c = mk.act("buyer")
    page = c.get(f"/bidhaa/{mk.kuku}").text
    assert 'action="/kikapu/ongeza"' in page and "Weka kwenye kikapu" in page
    r = c.post("/kikapu/ongeza", data={"csrf": TEST_CSRF, "product_id": mk.kuku, "quantity": "2"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/kikapu")
    page = c.get("/kikapu").text
    assert "Jogoo wa kienyeji" in page and "Kikapu (1)" in page and 'name="idempotency_key"' in page
    assert 'value="COD" disabled' in page
    key = re.search(r'name="idempotency_key" value="([0-9a-f]+)"', page).group(1)
    form = {"csrf": TEST_CSRF, "idempotency_key": key, "expected_total": "36000.00", **ADDR,
            "payment_method": "ONLINE"}
    r = c.post("/kikapu/lipa", data=form, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/oda/BM")
    again = c.post("/kikapu/lipa", data=form, follow_redirects=False)  # double click
    assert again.headers["location"] == r.headers["location"]
    assert "Inasubiri malipo" in c.get(r.headers["location"]).text
    r = c.post("/kikapu/lipa", data={**form, "csrf": "wrong"}, follow_redirects=False)
    assert r.status_code == 403
    put(c, mk.kuku, 1)
    r = checkout(c, payment_method="COD")
    assert r.status_code == 422 and r.json()["error"]["code"] == "cod_unavailable"
    c.cookies.clear()
    assert "Ingia ili kununua" in c.get(f"/bidhaa/{mk.kuku}").text
    assert c.get("/api/v1/cart").status_code == 401
