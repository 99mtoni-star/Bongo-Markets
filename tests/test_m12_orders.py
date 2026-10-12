"""Module 12 – Orders, Fulfilment na Delivery PIN.

BR-014, BR-017, ORD-001..006, ORD-LC-001/002/004/005/006/008, ORD-001/002 (v1.12), DEL-001, DEL-002,
CAP-DEL-ADV-001, V13-TRUST-002.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

from tests.conftest import TEST_CSRF
from tests.test_m11_cart_checkout import Market, pay, place, put

ROOT = Path(__file__).resolve().parents[1]
COURIER = {"courier_name": "Juma Bodaboda", "courier_phone": "0715 222 333"}


@pytest.fixture(autouse=True)
def _reset(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    from app.authz.engine import CACHE

    CACHE.clear()
    yield


@pytest.fixture
def mk(db_client, owner_conn):
    return Market(db_client, owner_conn)


def paid_order(mk, qty=2, who="buyer") -> str:
    number = place(mk, who, items=[(mk.kuku, qty)])["orders"][0]["number"]
    pay(mk.act(who), number)
    return number


def seller(mk, who, number, action, **body):
    c = mk.act(who)
    path = f"/api/v1/shops/{mk.slug}/orders/{number}"
    if action == "status":
        return c.post(f"{path}/status", json=body)
    return c.post(f"{path}/{action}", json=body)


def ship(mk, number, who="staff"):
    assert seller(mk, who, number, "status", status="PROCESSING").status_code == 200
    r = seller(mk, who, number, "status", status="SHIPPED", **COURIER)
    assert r.status_code == 200, r.text
    return r


def last_pin(mk, who="buyer") -> str:
    from tests.test_m03_auth import e164

    msg = mk.client.app.state.notifier.last_to(e164(mk.p.phone[who]))
    return re.search(r"PIN ya kupokea oda \S+ ni (\d{6})", msg.body).group(1)


def order_row(owner_conn, number, cols="status, payment_status"):
    return owner_conn.execute(f"SELECT {cols} FROM bm.orders WHERE number=%s", (number,)).fetchone()  # noqa: S608


# --------------------------------------------------------------------------- ORD-004
@pytest.mark.tid("M12-T001")
def test_buyer_sees_only_own_orders(mk):
    mine = place(mk, "buyer")["orders"][0]["number"]
    theirs = place(mk, "buyer2", items=[(mk.mayai, 1)])["orders"][0]["number"]
    c = mk.act("buyer")
    assert [o["number"] for o in c.get("/api/v1/orders").json()["orders"]] == [mine]
    assert c.get(f"/api/v1/orders/{mine}").status_code == 200
    for path in (f"/api/v1/orders/{theirs}", "/api/v1/orders/BM0000-000000", f"/oda/{theirs}"):
        assert c.get(path).status_code == 404, path
    assert c.post(f"/api/v1/orders/{theirs}/cancel", json={"reason": ""}).status_code == 404
    assert theirs not in c.get("/oda").text and mine in c.get("/oda").text
    c.cookies.clear()
    assert c.get("/api/v1/orders").status_code == 401


# --------------------------------------------------------------------------- ORD-005
@pytest.mark.tid("M12-T002")
def test_shop_members_see_only_their_shops_orders(mk):
    kuku = place(mk, "buyer")["orders"][0]["number"]
    mayai = place(mk, "buyer2", items=[(mk.mayai, 1)])["orders"][0]["number"]
    for who in ("owner", "manager", "staff"):
        c = mk.act(who)
        got = [o["number"] for o in c.get(f"/api/v1/shops/{mk.slug}/orders").json()["orders"]]
        assert got == [kuku], who
        assert c.get(f"/api/v1/shops/{mk.slug}/orders/{kuku}").status_code == 200
        assert c.get(f"/api/v1/shops/{mk.slug}/orders/{mayai}").status_code == 404  # other shop's order
        assert c.get(f"/api/v1/shops/{mk.slug2}/orders").status_code == 404  # not a member there
    c = mk.act("outsider")  # owns the other shop
    assert c.get(f"/api/v1/shops/{mk.slug}/orders").status_code == 404
    assert c.get(f"/api/v1/shops/{mk.slug}/orders/{kuku}").status_code == 404
    assert c.get(f"/maduka/{mk.slug}/oda/{kuku}").status_code == 404
    assert [o["number"] for o in c.get(f"/api/v1/shops/{mk.slug2}/orders").json()["orders"]] == [mayai]
    c = mk.act("buyer")  # a customer is not a shop member
    assert c.get(f"/api/v1/shops/{mk.slug}/orders/{kuku}").status_code == 404


# --------------------------------------------------------------------------- BR-014, ORD-LC-004
@pytest.mark.tid("M12-T003")
def test_payment_and_fulfilment_states_cannot_be_set_by_customers(mk, app_conn, owner_conn):
    number = place(mk)["orders"][0]["number"]
    c = mk.act("buyer")
    for path, body in ((f"/api/v1/orders/{number}/status", {"status": "DELIVERED"}),
                       (f"/api/v1/orders/{number}", {"status": "DELIVERED"})):
        assert c.post(path, json=body).status_code in (404, 405)
    assert c.post(f"/api/v1/orders/{number}/cancel", json={"status": "DELIVERED"}).status_code == 422
    assert seller(mk, "buyer", number, "status", status="PROCESSING").status_code == 404
    assert seller(mk, "buyer", number, "deliver", pin="000000").status_code == 404
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="verified payment confirmation"):
        app_conn.execute("UPDATE bm.orders SET payment_status='PAID' WHERE number=%s", (number,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="verified payment confirmation"):
        owner_conn.execute("UPDATE bm.orders SET payment_status='PAID' WHERE number=%s", (number,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):  # totals are frozen for the app role
        app_conn.execute("UPDATE bm.orders SET total=1, subtotal=1 WHERE number=%s", (number,))
    assert order_row(owner_conn, number) == ("PENDING_PAYMENT", "UNPAID")
    assert c.post("/dev/lipa/" + number, data={"csrf": "wrong"}).status_code == 403


# --------------------------------------------------------------------------- STK-003 via orders, ORD-006
@pytest.mark.tid("M12-T004")
def test_verified_payment_confirms_order_and_consumes_stock_once(mk, owner_conn, pg, make_settings):
    from app.db.session import session_factory
    from app.orders.payments import confirm_payment

    number = place(mk, items=[(mk.kuku, 3)])["orders"][0]["number"]
    assert mk.stock(mk.kuku) == (10, 3)
    pay(mk.act("buyer"), number)
    assert order_row(owner_conn, number) == ("CONFIRMED", "PAID")
    assert mk.stock(mk.kuku) == (7, 0)
    with session_factory(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url))() as s:
        assert confirm_payment(s, number, "DUPLICATE-EVENT") == "CONFIRMED"  # duplicate callback: no change
    assert mk.stock(mk.kuku) == (7, 0)
    hist = [r[0] for r in owner_conn.execute("SELECT to_status FROM bm.order_status_history h JOIN bm.orders o "
                                             "ON o.id=h.order_id WHERE o.number=%s ORDER BY h.id", (number,))]
    assert hist == ["PENDING_PAYMENT", "CONFIRMED"]
    assert owner_conn.execute("SELECT count(*) FROM bm.audit_logs WHERE action='order.payment_confirmed' "
                              "AND details->>'number'=%s", (number,)).fetchone()[0] == 1
    # ORD-LC-008: once the last unit is held by one order, another buyer's checkout cannot take it
    owner_conn.execute("UPDATE bm.products SET stock=1, reserved=0 WHERE public_id=%s", (mk.kuku,))
    place(mk, "buyer", items=[(mk.kuku, 1)])
    c2 = mk.act("buyer2")
    assert put(c2, mk.kuku, 1).status_code == 409  # nothing available to add
    assert mk.stock(mk.kuku) == (1, 1)


# --------------------------------------------------------------------------- ORD-LC-002, DEL-001
@pytest.mark.tid("M12-T005")
def test_fulfilment_transitions_are_permissioned_ordered_and_audited(mk, owner_conn):
    number = paid_order(mk)
    r = seller(mk, "staff", number, "status", status="SHIPPED", **COURIER)
    assert r.status_code == 409 and r.json()["error"]["code"] == "invalid_transition"  # cannot skip PROCESSING
    assert seller(mk, "staff", number, "status", status="PROCESSING").status_code == 200
    r = seller(mk, "manager", number, "status", status="SHIPPED")
    assert r.status_code == 422 and r.json()["error"]["field"] == "courier_name"  # courier is mandatory
    r = seller(mk, "manager", number, "status", status="SHIPPED", **COURIER)
    assert r.status_code == 200 and r.json()["courier"] == {"name": "Juma Bodaboda", "phone": "+255715222333"}
    assert seller(mk, "staff", number, "status", status="DELIVERED").status_code == 409  # only via PIN
    r = seller(mk, "owner", number, "courier", courier_name="Neema Usafiri", courier_phone="0716 444 555")
    assert r.status_code == 200
    actions = [a for (a,) in owner_conn.execute("SELECT action FROM bm.audit_logs WHERE details->>'number'=%s "
                                                "ORDER BY id", (number,))]
    assert actions == ["order.created", "order.payment_confirmed", "order.status_changed", "order.status_changed",
                       "order.courier_reassigned"]
    shipped = owner_conn.execute("SELECT details FROM bm.audit_logs WHERE action='order.status_changed' "
                                 "AND details->>'number'=%s AND details->>'to'='SHIPPED'", (number,)).fetchone()[0]
    assert shipped["courier"]["name"] == "Juma Bodaboda"
    # without shop.orders.fulfil the transition is refused even for a member
    owner_conn.execute("DELETE FROM bm.shop_role_permissions WHERE role_code='STAFF' AND "
                       "permission_code='shop.orders.fulfil'")
    owner_conn.execute("UPDATE bm.authz_policy SET version = version + 1")
    try:
        other = paid_order(mk, qty=1, who="buyer2")
        assert seller(mk, "staff", other, "status", status="PROCESSING").status_code == 403
        assert mk.act("staff").get(f"/api/v1/shops/{mk.slug}/orders/{other}").status_code == 200  # can still view
    finally:
        owner_conn.execute("INSERT INTO bm.shop_role_permissions(role_code, permission_code) "
                           "VALUES ('STAFF','shop.orders.fulfil') ON CONFLICT DO NOTHING")
        owner_conn.execute("UPDATE bm.authz_policy SET version = version + 1")


# --------------------------------------------------------------------------- DEL-002, V13-TRUST-002
@pytest.mark.tid("M12-T006")
def test_delivery_pin_is_order_bound_single_use_and_attempt_limited(mk, owner_conn):
    a = paid_order(mk, qty=1)
    ship(mk, a)
    pin_a = last_pin(mk)
    stored = order_row(owner_conn, a, "delivery_pin_hash")[0]
    assert pin_a not in stored and len(stored) == 64  # only an HMAC is stored
    b = paid_order(mk, qty=1, who="buyer2")
    ship(mk, b)
    pin_b = last_pin(mk, "buyer2")
    if pin_a != pin_b:  # A's PIN is useless for B (bound to the order)
        r = seller(mk, "staff", b, "deliver", pin=pin_a)
        assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_pin"
    for i in range(4 if pin_a != pin_b else 5):
        r = seller(mk, "staff", b, "deliver", pin="000000" if pin_b != "000000" else "111111")
    assert r.status_code == 423 and r.json()["error"]["code"] == "pin_locked"
    assert seller(mk, "staff", b, "deliver", pin=pin_b).status_code == 423  # locked even for the right PIN
    assert mk.act("buyer2").post(f"/api/v1/orders/{b}/resend-pin").status_code == 200
    new_b = last_pin(mk, "buyer2")
    r = seller(mk, "staff", b, "deliver", pin=new_b)
    assert r.status_code == 200 and r.json()["status"] == "DELIVERED"
    assert order_row(owner_conn, b, "delivery_pin_hash")[0] is None
    r = seller(mk, "staff", b, "deliver", pin=new_b)  # replay
    assert r.status_code == 409
    assert seller(mk, "manager", a, "deliver", pin=pin_a).json()["status"] == "DELIVERED"
    assert owner_conn.execute("SELECT count(*) FROM bm.audit_logs WHERE action='order.delivery_pin_failed' "
                              "AND details->>'number'=%s", (b,)).fetchone()[0] == 5


# --------------------------------------------------------------------------- ORD-LC-001, ORD-LC-006
@pytest.mark.tid("M12-T007")
def test_cancellation_rules_and_stock_release(mk, owner_conn):
    pending = place(mk, items=[(mk.kuku, 2)])["orders"][0]["number"]
    assert mk.stock(mk.kuku) == (10, 2)
    c = mk.act("buyer")
    assert c.post(f"/api/v1/orders/{pending}/cancel", json={"reason": ""}).json()["status"] == "CANCELLED"
    assert mk.stock(mk.kuku) == (10, 0)  # reservation released
    assert c.post(f"/api/v1/orders/{pending}/cancel", json={"reason": ""}).status_code == 409

    paid = paid_order(mk, qty=3)
    assert mk.stock(mk.kuku) == (7, 0)
    c = mk.act("buyer")
    r = c.post(f"/api/v1/orders/{paid}/cancel", json={"reason": ""})
    assert r.status_code == 422  # after confirmation the buyer must give a reason and can only request
    r = c.post(f"/api/v1/orders/{paid}/cancel", json={"reason": "Nimebadilisha mawazo"})
    assert r.status_code == 200 and r.json()["status"] == "CONFIRMED" and r.json()["cancel_requested"] is True
    assert mk.stock(mk.kuku) == (7, 0)  # nothing released until the seller decides
    assert seller(mk, "staff", paid, "cancel", reason="x").status_code == 422
    r = seller(mk, "staff", paid, "cancel", reason="Mteja ameomba kughairi")
    assert r.status_code == 200 and r.json()["status"] == "CANCELLED" and r.json()["refund_required"] is True
    assert mk.stock(mk.kuku) == (10, 0)  # sold units returned
    assert order_row(owner_conn, paid) == ("CANCELLED", "PAID")  # refund itself is a Finance step (M13)

    shipped = paid_order(mk, qty=1)
    ship(mk, shipped)
    assert seller(mk, "owner", shipped, "cancel", reason="Kuchelewa").status_code == 409
    assert mk.act("buyer").post(f"/api/v1/orders/{shipped}/cancel", json={"reason": "abc"}).status_code == 409


@pytest.mark.tid("M12-T008")
def test_unpaid_orders_expire_and_late_payment_needs_refund(mk, owner_conn, pg, make_settings):
    from app.db.session import session_factory
    from app.orders.payments import confirm_payment, expire_unpaid

    number = place(mk, items=[(mk.kuku, 4)])["orders"][0]["number"]
    assert mk.stock(mk.kuku) == (10, 4)
    factory = session_factory(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url))
    later = datetime.now(UTC) + timedelta(minutes=16)
    with factory() as s:
        assert expire_unpaid(s, now=later) >= 1
    assert order_row(owner_conn, number) == ("EXPIRED", "UNPAID")
    assert mk.stock(mk.kuku) == (10, 0)
    with factory() as s:
        assert confirm_payment(s, number, "LATE-1") == "EXPIRED"
    assert order_row(owner_conn, number, "status, payment_status, refund_required") == ("EXPIRED", "PAID", True)
    assert mk.stock(mk.kuku) == (10, 0)  # an expired order never takes stock back

    late = place(mk, items=[(mk.kuku, 1)])["orders"][0]["number"]  # paid after the hold, before the sweep
    with factory() as s:
        assert confirm_payment(s, late, "LATE-2", now=later) == "EXPIRED"
    assert order_row(owner_conn, late, "status, refund_required") == ("EXPIRED", True)
    assert mk.stock(mk.kuku) == (10, 0)


# --------------------------------------------------------------------------- ORD-002/003, ORD-002 v1.12
@pytest.mark.tid("M12-T009")
def test_orders_keep_address_and_item_snapshots(mk, owner_conn, app_conn):
    number = place(mk, items=[(mk.kuku, 2)])["orders"][0]["number"]
    owner_conn.execute("UPDATE bm.products SET name='Jina jipya', price=99999, sku='NEW' WHERE public_id=%s",
                       (mk.kuku,))
    o = mk.act("buyer").get(f"/api/v1/orders/{number}").json()
    item = o["items"][0]
    assert (item["name"], item["unit_price"], item["line_total"], item["quantity"]) == \
        ("Jogoo wa kienyeji", "18000.00", "36000.00", 2)
    assert o["total"] == "36000.00"
    assert o["delivery"] == {"name": "Amina Juma", "phone": "+255754000111", "region": "Dar es Salaam",
                             "area": "Kariakoo", "street": "Mtaa wa Congo", "notes": "Piga simu ukifika"}
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("UPDATE bm.order_items SET unit_price=1")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("UPDATE bm.orders SET delivery_region='X' WHERE number=%s", (number,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("DELETE FROM bm.order_status_history")
    with pytest.raises(psycopg.errors.CheckViolation):
        owner_conn.execute("UPDATE bm.order_items SET line_total=1 WHERE order_id=(SELECT id FROM bm.orders "
                           "WHERE number=%s)", (number,))


# --------------------------------------------------------------------------- BR-017
@pytest.mark.tid("M12-T010")
def test_review_allowed_only_for_own_delivered_items(mk):
    number = paid_order(mk, qty=1)
    item = mk.act("buyer").get(f"/api/v1/orders/{number}").json()["items"][0]["id"]

    def eligible(who):
        return mk.act(who).get(f"/api/v1/order-items/{item}/review-eligibility").json()["eligible"]

    assert eligible("buyer") is False  # paid but not delivered
    ship(mk, number)
    assert eligible("buyer") is False
    seller(mk, "staff", number, "deliver", pin=last_pin(mk))
    assert eligible("buyer") is True and eligible("buyer2") is False
    assert mk.act("buyer").get("/api/v1/order-items/not-a-uuid/review-eligibility").json()["eligible"] is False


@pytest.mark.tid("M12-T011")
def test_order_pages_for_buyer_and_seller(mk):
    number = place(mk, items=[(mk.kuku, 1)])["orders"][0]["number"]
    c = mk.act("buyer")
    page = c.get(f"/oda/{number}").text
    assert "Inasubiri malipo" in page and "Lipa sasa" in page and "Ghairi oda" in page
    pay(c, number)
    assert "Imethibitishwa" in c.get(f"/oda/{number}").text
    c = mk.act("staff")
    dash = c.get(f"/maduka/{mk.slug}").text
    assert f"/maduka/{mk.slug}/oda" in dash and "Oda mpya (zimelipwa)" in dash
    assert number in c.get(f"/maduka/{mk.slug}/oda?hali=CONFIRMED").text
    page = c.get(f"/maduka/{mk.slug}/oda/{number}").text
    assert "Anza kuandaa oda" in page
    base = f"/maduka/{mk.slug}/oda/{number}"
    r = c.post(f"{base}/hali", data={"csrf": TEST_CSRF, "status": "PROCESSING"}, follow_redirects=False)
    assert r.status_code == 303
    r = c.post(f"{base}/hali", data={"csrf": TEST_CSRF, "status": "SHIPPED", **COURIER}, follow_redirects=False)
    assert "ujumbe=imesasishwa" in r.headers["location"]
    assert "Tuma PIN mpya" in mk.act("buyer").get(f"/oda/{number}").text
    c = mk.act("staff")
    r = c.post(f"{base}/fika", data={"csrf": TEST_CSRF, "pin": "12"}, follow_redirects=False)
    assert "kosa=" in r.headers["location"]
    r = c.post(f"{base}/fika", data={"csrf": TEST_CSRF, "pin": last_pin(mk)}, follow_redirects=False)
    assert "ujumbe=imefika" in r.headers["location"]
    assert "Imefika" in c.get(base).text
    assert c.post(f"{base}/fika", data={"csrf": "bad", "pin": "1"}).status_code == 403


@pytest.mark.tid("M12-T012")
def test_dev_payment_simulator_absent_outside_dev_and_deferred_delivery_recorded(mk):
    from app.core.config import Environment

    number = place(mk)["orders"][0]["number"]
    app = mk.client.app
    original = app.state.settings
    try:
        for env in (Environment.STAGING, Environment.PRODUCTION):
            app.state.settings = original.model_copy(update={"environment": env})
            c = mk.act("buyer")
            assert c.post(f"/dev/lipa/{number}", data={"csrf": TEST_CSRF}).status_code == 404
            assert "Lipa sasa" not in c.get(f"/oda/{number}").text
    finally:
        app.state.settings = original
    doc = (ROOT / "docs" / "modules" / "M12" / "design.md").read_text()
    for token in ("CAP-DEL-ADV-001", "DEL-002", "V13-TRUST-002", "Design Ready: YES"):
        assert token in doc
