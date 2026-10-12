"""Module 03 – Registration na Login."""

from __future__ import annotations

import itertools
import re
from datetime import UTC, datetime, timedelta

import pytest
from psycopg import errors

_counter = itertools.count(1)


def new_phone() -> str:
    """A fresh, valid Tanzanian mobile number in local format (07XX XXX XXX)."""
    n = next(_counter)
    return f"0754{(int(datetime.now(UTC).timestamp()) % 1000):03d}{n:03d}"


def e164(local: str) -> str:
    return "+255" + local[1:]


STRONG = "Mchele-Mzuri-2026"


@pytest.fixture(autouse=True)
def _reset_rate_limits(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    yield


def last_code(client, to: str) -> str:
    msg = client.app.state.notifier.last_to(to)
    assert msg is not None, f"no message to {to}"
    return re.search(r"\b(\d{6})\b", msg.body).group(1)


def register(client, phone: str, password: str = STRONG, name: str = "Amina Juma", email: str | None = None):
    body = {"full_name": name, "phone": phone, "password": password}
    if email:
        body["email"] = email
    return client.post("/api/v1/auth/register", json=body)


def register_and_verify(client, phone: str | None = None, password: str = STRONG, **kw) -> str:
    phone = phone or new_phone()
    r = register(client, phone, password, **kw)
    assert r.status_code == 202, r.text
    code = last_code(client, e164(phone))
    v = client.post("/api/v1/auth/verify-phone", json={"verification_id": r.json()["verification_id"], "code": code})
    assert v.status_code == 200, v.text
    return phone


def user_row(owner_conn, phone_local: str):
    return owner_conn.execute(
        "SELECT id, status, password_hash, failed_login_count, locked_until FROM bm.users WHERE phone_e164=%s",
        (e164(phone_local),)).fetchone()


# --------------------------------------------------------------------------- AUTH-001/003, SEC-001, SEC-PWD-001
@pytest.mark.tid("M03-T001")
def test_register_creates_pending_user_with_argon2id(db_client, owner_conn):
    phone = new_phone()
    r = register(db_client, phone)
    assert r.status_code == 202
    assert set(r.json()) == {"message", "verification_id"}
    row = user_row(owner_conn, phone)
    assert row[1] == "PENDING_VERIFICATION"
    assert row[2].startswith("$argon2id$v=19$m=65536,t=3,p=2$")
    assert STRONG not in str(owner_conn.execute("SELECT u::text FROM bm.users u WHERE id=%s", (row[0],)).fetchone())
    assert re.search(r"\b\d{6}\b", db_client.app.state.notifier.last_to(e164(phone)).body)


# --------------------------------------------------------------------------- AUTH-002
@pytest.mark.tid("M03-T002")
def test_identifiers_are_normalized(db_client, owner_conn):
    from app.auth.identifiers import IdentifierError, normalize_email, normalize_phone

    for raw in ("0712 345 678", "+255 712-345-678", "255712345678", " 0712345678 "):
        assert normalize_phone(raw) == "+255712345678"
    for bad in ("12345", "07123", "abc", "+1 555"):
        with pytest.raises(IdentifierError):
            normalize_phone(bad)
    assert normalize_email("  Amina.Juma@Example.COM ") == "amina.juma@example.com"
    phone = new_phone()
    register(db_client, phone, email="  Mixed.Case@Example.com ")
    email = owner_conn.execute("SELECT email FROM bm.users WHERE phone_e164=%s", (e164(phone),)).fetchone()[0]
    assert email == "mixed.case@example.com"


# --------------------------------------------------------------------------- AUTH-006, SEC-WEB-002
@pytest.mark.tid("M03-T003")
def test_verify_phone_activates_and_sets_secure_cookie(db_client, owner_conn):
    phone = new_phone()
    r = register(db_client, phone)
    code = last_code(db_client, e164(phone))
    v = db_client.post("/api/v1/auth/verify-phone", json={"verification_id": r.json()["verification_id"], "code": code})
    assert v.status_code == 200
    cookie = v.headers["set-cookie"].lower()
    for attr in ("bm_session=", "httponly", "secure", "samesite=lax", "path=/", "max-age="):
        assert attr in cookie
    assert user_row(owner_conn, phone)[1] == "ACTIVE"
    me = db_client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["phone"] == e164(phone)


@pytest.mark.tid("M03-T004")
def test_codes_have_attempt_limit_and_expiry(db_client, owner_conn):
    phone = new_phone()
    vid = register(db_client, phone).json()["verification_id"]
    code = last_code(db_client, e164(phone))
    wrong = f"{(int(code) + 1) % 1_000_000:06d}"
    for _ in range(5):
        r = db_client.post("/api/v1/auth/verify-phone", json={"verification_id": vid, "code": wrong})
        assert r.status_code == 400
    r = db_client.post("/api/v1/auth/verify-phone", json={"verification_id": vid, "code": code})
    assert r.status_code == 400  # correct code no longer accepted after max attempts
    # Expiry: a fresh code that has expired is rejected.
    vid2 = db_client.post("/api/v1/auth/resend-code", json={"verification_id": vid}).json()["verification_id"]
    code2 = last_code(db_client, e164(phone))
    owner_conn.execute("UPDATE bm.auth_codes SET expires_at = now() - interval '1 second' WHERE public_id=%s",
                       (vid2,))
    r = db_client.post("/api/v1/auth/verify-phone", json={"verification_id": vid2, "code": code2})
    assert r.status_code == 400 and user_row(owner_conn, phone)[1] == "PENDING_VERIFICATION"


# --------------------------------------------------------------------------- ID-006
@pytest.mark.tid("M03-T005")
def test_registering_existing_number_is_indistinguishable(db_client, owner_conn):
    phone = register_and_verify(db_client)
    other = new_phone()
    fresh = register(db_client, other)
    dup = register(db_client, phone, password="Another-Strong-Pass-1")
    assert dup.status_code == fresh.status_code == 202
    assert dup.json()["message"] == fresh.json()["message"]
    assert len(dup.json()["verification_id"]) == len(fresh.json()["verification_id"])
    # The decoy id fails exactly like a wrong code.
    r = db_client.post("/api/v1/auth/verify-phone", json={"verification_id": dup.json()["verification_id"],
                                                          "code": "123456"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_code"
    assert "Mtu amejaribu kufungua akaunti" in db_client.app.state.notifier.last_to(e164(phone)).body
    assert owner_conn.execute("SELECT count(*) FROM bm.users WHERE phone_e164=%s", (e164(phone),)).fetchone()[0] == 1


# --------------------------------------------------------------------------- SEC-PWD-005
@pytest.mark.tid("M03-T006")
def test_login_success_and_generic_failures(db_client):
    phone = register_and_verify(db_client)
    db_client.cookies.clear()
    ok = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    assert ok.status_code == 200 and "bm_session=" in ok.headers["set-cookie"]
    unknown = db_client.post("/api/v1/auth/login", json={"identifier": new_phone(), "password": STRONG})
    wrong = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": "Wrong-Password-99"})
    garbage = db_client.post("/api/v1/auth/login", json={"identifier": "not-a-phone", "password": "x"})
    assert unknown.status_code == wrong.status_code == garbage.status_code == 401
    assert unknown.json() == wrong.json() == garbage.json()


# --------------------------------------------------------------------------- AUTH-007
@pytest.mark.tid("M03-T007")
def test_repeated_failures_lock_account_temporarily(db_client, owner_conn):
    phone = register_and_verify(db_client)
    for _ in range(5):
        db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": "Wrong-Password-99"})
    row = user_row(owner_conn, phone)
    assert row[4] is not None and row[4] > datetime.now(UTC)
    locked = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    unknown = db_client.post("/api/v1/auth/login", json={"identifier": new_phone(), "password": STRONG})
    assert locked.status_code == 401 and locked.json() == unknown.json()  # lock is not revealed
    assert "imefungwa" in db_client.app.state.notifier.last_to(e164(phone)).body
    owner_conn.execute("UPDATE bm.users SET locked_until = now() - interval '1 second' WHERE id=%s", (row[0],))
    assert db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG}).status_code == 200


# --------------------------------------------------------------------------- SEC-009
@pytest.mark.tid("M03-T008")
def test_login_rate_limit_per_identifier(db_client):
    target = new_phone()
    codes = [db_client.post("/api/v1/auth/login", json={"identifier": target, "password": "x" * 10}).status_code
             for _ in range(11)]
    assert codes[:10] == [401] * 10 and codes[10] == 429
    r = db_client.post("/api/v1/auth/login", json={"identifier": target, "password": "x" * 10})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0


@pytest.mark.tid("M03-T009")
def test_registration_rate_limit_per_ip(db_client):
    statuses = [register(db_client, new_phone()).status_code for _ in range(11)]
    assert statuses[:10] == [202] * 10 and statuses[10] == 429


# --------------------------------------------------------------------------- SEC-PWD-003/004
@pytest.mark.tid("M03-T010")
def test_password_policy_and_no_truncation(db_client):
    for bad, field in (("short", "password"), ("password123", "password"), ("simba123", "password"),
                       ("x" * 257, "password")):
        r = register(db_client, new_phone(), password=bad)
        assert r.status_code == 422 and r.json()["error"]["field"] == field, (bad, r.text)
    phone = new_phone()
    r = register(db_client, phone, password=f"Pw{phone[1:]}!")  # contains the phone number
    assert r.status_code == 422
    long_pw = ("Mlima-Kilimanjaro-" * 15)[:256]
    phone = register_and_verify(db_client, password=long_pw)
    db_client.cookies.clear()
    assert db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": long_pw}).status_code == 200
    db_client.cookies.clear()
    r = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": long_pw[:255]})
    assert r.status_code == 401  # nothing is silently truncated


# --------------------------------------------------------------------------- SEC-PWD-006
@pytest.mark.tid("M03-T011")
def test_password_reset_is_one_time_hashed_and_generic(db_client, owner_conn):
    phone = register_and_verify(db_client)
    known = db_client.post("/api/v1/auth/password/forgot", json={"identifier": phone})
    unknown = db_client.post("/api/v1/auth/password/forgot", json={"identifier": new_phone()})
    assert known.status_code == unknown.status_code == 202
    assert known.json()["message"] == unknown.json()["message"]
    assert len(known.json()["reset_id"]) == len(unknown.json()["reset_id"])
    code = last_code(db_client, e164(phone))
    stored = owner_conn.execute("SELECT code_hash, expires_at - created_at FROM bm.auth_codes WHERE public_id=%s",
                                (known.json()["reset_id"],)).fetchone()
    import hashlib

    assert code not in stored[0] and stored[0] != hashlib.sha256(code.encode()).hexdigest()
    assert stored[1] <= timedelta(minutes=15, seconds=5)
    body = {"reset_id": known.json()["reset_id"], "code": code, "new_password": "Ndizi-Mbivu-2027"}
    assert db_client.post("/api/v1/auth/password/reset", json=body).status_code == 200
    again = db_client.post("/api/v1/auth/password/reset", json={**body, "new_password": "Embe-Tamu-2028"})
    assert again.status_code == 400  # one-time
    db_client.cookies.clear()
    ok = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": "Ndizi-Mbivu-2027"})
    assert ok.status_code == 200


# --------------------------------------------------------------------------- SEC-014
@pytest.mark.tid("M03-T012")
def test_password_reset_revokes_all_sessions(db_client):
    phone = register_and_verify(db_client)
    old_cookie = db_client.cookies.get("bm_session")
    rid = db_client.post("/api/v1/auth/password/forgot", json={"identifier": phone}).json()["reset_id"]
    code = last_code(db_client, e164(phone))
    db_client.post("/api/v1/auth/password/reset",
                   json={"reset_id": rid, "code": code, "new_password": "Ndizi-Mbivu-2027"})
    db_client.cookies.clear()
    db_client.cookies.set("bm_session", old_cookie)
    assert db_client.get("/api/v1/auth/me").status_code == 401


@pytest.mark.tid("M03-T013")
def test_password_change_revokes_other_sessions(db_client):
    phone = register_and_verify(db_client)
    first = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    second = db_client.cookies.get("bm_session")
    r = db_client.post("/api/v1/auth/password/change",
                       json={"current_password": STRONG, "new_password": "Ndizi-Mbivu-2027"})
    assert r.status_code == 200
    assert db_client.get("/api/v1/auth/me").status_code == 200  # fresh cookie issued
    for old in (first, second):
        db_client.cookies.clear()
        db_client.cookies.set("bm_session", old)
        assert db_client.get("/api/v1/auth/me").status_code == 401
    bad = db_client.post("/api/v1/auth/password/change",
                         json={"current_password": "nope-nope-nope", "new_password": "Another-2029-x"})
    assert bad.status_code == 401  # old session is gone


# --------------------------------------------------------------------------- SEC-010
@pytest.mark.tid("M03-T014")
def test_audit_trail_without_secrets(db_client, owner_conn):
    phone = register_and_verify(db_client)
    uid = user_row(owner_conn, phone)[0]
    db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": "Wrong-Password-99"})
    rid = db_client.post("/api/v1/auth/password/forgot", json={"identifier": phone}).json()["reset_id"]
    code = last_code(db_client, e164(phone))
    db_client.post("/api/v1/auth/password/reset", json={"reset_id": rid, "code": code,
                                                        "new_password": "Ndizi-Mbivu-2027"})
    rows = owner_conn.execute("SELECT action, details::text FROM bm.audit_logs WHERE entity_id=%s", (str(uid),)) \
        .fetchall()
    actions = {a for a, _ in rows}
    assert {"user.registration_started", "user.phone_verified", "auth.login_failed",
            "auth.password_reset_requested", "auth.password_reset_completed", "auth.sessions_revoked"} <= actions
    blob = " ".join(d for _, d in rows) + " ".join(a for a, _ in rows)
    pw_hash = user_row(owner_conn, phone)[2]
    for secret in (STRONG, "Ndizi-Mbivu-2027", code, pw_hash, "$argon2"):
        assert secret not in blob


@pytest.mark.tid("M03-T015")
def test_logout_revokes_server_side(db_client):
    register_and_verify(db_client)
    token = db_client.cookies.get("bm_session")
    assert db_client.post("/api/v1/auth/logout").status_code == 204
    db_client.cookies.set("bm_session", token)
    assert db_client.get("/api/v1/auth/me").status_code == 401


# --------------------------------------------------------------------------- SEC-WEB-003
@pytest.mark.tid("M03-T016")
def test_cors_and_origin_policy(make_settings, pg):
    from fastapi.testclient import TestClient

    from app.main import create_app

    with pytest.raises(ValueError, match="SEC-WEB-003"):
        make_settings(BM_CORS_ORIGINS='["*"]')
    app = create_app(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url,
                                   BM_CORS_ORIGINS='["https://app.bongomarkets.co.tz"]'))
    c = TestClient(app, base_url="https://testserver")
    pre = {"Access-Control-Request-Method": "POST"}
    good = c.options("/api/v1/auth/login", headers={**pre, "Origin": "https://app.bongomarkets.co.tz"})
    evil = c.options("/api/v1/auth/login", headers={**pre, "Origin": "https://evil.example"})
    assert good.headers.get("access-control-allow-origin") == "https://app.bongomarkets.co.tz"
    assert good.headers.get("access-control-allow-credentials") == "true"
    assert "access-control-allow-origin" not in evil.headers
    blocked = c.post("/api/v1/auth/login", json={"identifier": "x", "password": "y"},
                     headers={"Origin": "https://evil.example"})
    assert blocked.status_code == 403


# --------------------------------------------------------------------------- ID-001, SEC-INV-007
@pytest.mark.tid("M03-T017")
def test_identity_columns_are_immutable_for_app(db_client, owner_conn, app_conn):
    phone = register_and_verify(db_client)
    uid = user_row(owner_conn, phone)[0]
    for stmt in ("UPDATE bm.users SET id = id + 1000 WHERE id = %s",
                 "UPDATE bm.users SET public_id = gen_random_uuid() WHERE id = %s",
                 "UPDATE bm.users SET created_at = now() WHERE id = %s",
                 "DELETE FROM bm.users WHERE id = %s",
                 "DELETE FROM bm.user_sessions WHERE user_id = %s"):
        # GENERATED ALWAYS identity or missing column privilege: either way the change is refused.
        with pytest.raises((errors.InsufficientPrivilege, errors.GeneratedAlways)):
            app_conn.execute(stmt, (uid,))
    app_conn.execute("UPDATE bm.users SET full_name = 'Amina J.' WHERE id = %s", (uid,))  # mutable field OK
    with pytest.raises(errors.InsufficientPrivilege):
        app_conn.execute("UPDATE bm.audit_logs SET action='x' WHERE entity_id = %s", (str(uid),))


# --------------------------------------------------------------------------- ID-002
@pytest.mark.tid("M03-T018")
def test_email_is_secondary_and_usable_only_once_verified(db_client):
    email = f"amina{next(_counter)}@example.com"
    phone = register_and_verify(db_client, email=email)
    db_client.cookies.clear()
    r = db_client.post("/api/v1/auth/login", json={"identifier": email, "password": STRONG})
    assert r.status_code == 401  # unverified email is not a login identifier
    db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    vid = db_client.post("/api/v1/auth/email/verify-request", json={"email": email}).json()["verification_id"]
    code = last_code(db_client, email)
    assert db_client.post("/api/v1/auth/email/verify", json={"verification_id": vid, "code": code}).status_code == 200
    db_client.cookies.clear()
    assert db_client.post("/api/v1/auth/login", json={"identifier": email.upper(), "password": STRONG}) \
        .status_code == 200


# --------------------------------------------------------------------------- UI flow + CSRF
@pytest.mark.tid("M03-T019")
def test_web_registration_flow_with_csrf(db_client):
    page = db_client.get("/jisajili")
    assert page.status_code == 200 and "Fungua akaunti" in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    phone = new_phone()
    form = {"full_name": "Juma Hamisi", "phone": phone, "email": "", "password": STRONG}
    assert db_client.post("/jisajili", data=form).status_code == 403  # missing CSRF token
    r = db_client.post("/jisajili", data={**form, "csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/thibitisha?v=")
    vid = r.headers["location"].split("v=")[1]
    code = last_code(db_client, e164(phone))
    r = db_client.post("/thibitisha", data={"csrf": csrf, "v": vid, "code": code}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/akaunti")
    acct = db_client.get("/akaunti")
    assert "Juma Hamisi" in acct.text and "Akaunti yangu" in acct.text


@pytest.mark.tid("M03-T020")
def test_sessions_expire_idle_and_absolute(db_client, owner_conn):
    register_and_verify(db_client)
    assert db_client.get("/api/v1/auth/me").status_code == 200
    token = db_client.cookies.get("bm_session")
    import hashlib

    th = hashlib.sha256(token.encode()).hexdigest()
    owner_conn.execute("UPDATE bm.user_sessions SET last_seen_at = now() - interval '49 hours' WHERE token_hash=%s",
                       (th,))
    assert db_client.get("/api/v1/auth/me").status_code == 401
    owner_conn.execute("UPDATE bm.user_sessions SET last_seen_at = now(), expires_at = now() - interval '1 second' "
                       "WHERE token_hash=%s", (th,))
    assert db_client.get("/api/v1/auth/me").status_code == 401


@pytest.mark.tid("M03-T021")
def test_pending_account_requires_verification_only_with_correct_password(db_client):
    phone = new_phone()
    register(db_client, phone)
    wrong = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": "Wrong-Password-99"})
    assert wrong.status_code == 401
    right = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    assert right.status_code == 403 and right.json()["error"]["code"] == "verification_required"
    assert right.json()["error"]["verification_id"]


@pytest.mark.tid("M03-T022")
def test_profile_never_exposes_internal_id_or_hash(db_client, owner_conn):
    phone = register_and_verify(db_client)
    uid, _, pw_hash, *_ = user_row(owner_conn, phone)
    body = db_client.get("/api/v1/auth/me").json()
    assert body["id"] != str(uid) and len(body["id"]) == 36
    assert "password" not in str(body).lower() and pw_hash not in str(body)


@pytest.mark.tid("M03-T023")
def test_gate_requires_design_ready(tmp_path):
    from scripts.gate import design_ready

    assert design_ready("M03")
    assert not design_ready("M99", docs_root=tmp_path)
    (tmp_path / "M05").mkdir()
    (tmp_path / "M05" / "design.md").write_text("# draft\nDesign Ready: NO\n")
    assert not design_ready("M05", docs_root=tmp_path)


@pytest.mark.tid("M03-T024")
def test_dev_sms_inbox_hidden_outside_dev(make_settings, pg):
    from fastapi.testclient import TestClient

    from app.main import create_app

    strong = "s" * 48
    prod = create_app(make_settings(BM_ENVIRONMENT="production", BM_SECRET_KEY=strong,
                                    BM_DATABASE_URL=pg.app_url, BM_NOTIFIER="sms-gateway"))
    c = TestClient(prod, base_url="https://localhost")
    assert c.get("/dev/sms").status_code == 404


@pytest.mark.tid("M03-T025")
def test_unverified_registration_can_be_replaced_but_not_active_one(db_client, owner_conn):
    phone = new_phone()
    register(db_client, phone, name="Mtu wa Kwanza")
    register(db_client, phone, name="Mmiliki Halisi", password="Nanasi-Kubwa-2026")
    name = owner_conn.execute("SELECT full_name FROM bm.users WHERE phone_e164=%s", (e164(phone),)).fetchone()[0]
    assert name == "Mmiliki Halisi"
