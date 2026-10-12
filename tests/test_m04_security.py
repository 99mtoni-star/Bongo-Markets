"""Module 04 – MFA, Sessions na Password Recovery."""

from __future__ import annotations

import hashlib
import logging
import re
import time
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from psycopg import errors

from tests.test_m03_auth import STRONG, e164, last_code, new_phone, register, register_and_verify, user_row


@pytest.fixture(autouse=True)
def _reset_rate_limits(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    yield


class FakeClock:
    """Server-side TOTP clock under test control, so tests never wait for real 30 s windows."""

    def __init__(self):
        self.now = time.time()

    def time(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    import app.auth.mfa as mfa

    fake = FakeClock()
    monkeypatch.setattr(mfa, "time", fake)
    return fake


CLOCK: FakeClock | None = None


@pytest.fixture(autouse=True)
def _bind_clock(clock):
    global CLOCK
    CLOCK = clock
    yield
    CLOCK = None


class Totp:
    """Independent TOTP oracle (pyotp). Each code is from a fresh 30 s window, like a phone over time."""

    def __init__(self, secret: str):
        self.otp = pyotp.TOTP(secret)

    def code(self) -> str:
        CLOCK.now += 30  # move to the next time step; the server shares this clock
        return self.otp.at(CLOCK.now)


def enable_mfa(client) -> tuple[Totp, list[str]]:
    setup = client.post("/api/v1/auth/mfa/totp/setup")
    assert setup.status_code == 200, setup.text
    totp = Totp(setup.json()["secret"])
    r = client.post("/api/v1/auth/mfa/totp/confirm", json={"code": totp.code()})
    assert r.status_code == 200, r.text
    return totp, r.json()["recovery_codes"]


def mfa_login(client, phone: str, totp: Totp, password: str = STRONG):
    client.cookies.clear()
    r = client.post("/api/v1/auth/login", json={"identifier": phone, "password": password})
    assert r.status_code == 200 and r.json()["mfa_required"], r.text
    return client.post("/api/v1/auth/login/mfa", json={"challenge_id": r.json()["challenge_id"], "code": totp.code()})


def step_up(client, action: str, totp: Totp | None = None, password: str = STRONG) -> str:
    body = {"action": action, "password": password}
    if totp:
        body["mfa_code"] = totp.code()
    r = client.post("/api/v1/auth/step-up", json=body)
    assert r.status_code == 200, r.text
    return r.json()["step_up_token"]


def make_admin(client, owner_conn, role: str = "SUPER_ADMIN"):
    phone = register_and_verify(client)
    totp, _ = enable_mfa(client)
    uid = user_row(owner_conn, phone)[0]
    owner_conn.execute("INSERT INTO bm.user_platform_roles(user_id, role_code) VALUES (%s, %s)", (uid, role))
    assert mfa_login(client, phone, totp).status_code == 200
    return phone, totp


def switch(client, cookie: str) -> None:
    """Act as another device: replace the session cookie without leaving duplicates."""
    client.cookies.clear()
    client.cookies.set("bm_session", cookie)


def public_id(client) -> str:
    return client.get("/api/v1/auth/me").json()["id"]


# --------------------------------------------------------------------------- TOTP correctness + replay
@pytest.mark.tid("M04-T001")
def test_totp_matches_rfc6238_and_rejects_replay():
    # RFC 6238 Appendix B (SHA-1), secret "12345678901234567890", T=59 -> 94287082 (8 digits; we use 6).
    import base64

    from app.auth.mfa import totp_at, verify_totp

    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp_at(secret, 59 // 30) == "287082"
    s = pyotp.random_base32()
    now = time.time()
    code = pyotp.TOTP(s).at(now)
    step = verify_totp(s, code, last_used_step=None, now=now)
    assert step is not None
    assert verify_totp(s, code, last_used_step=step, now=now) is None  # same code cannot be replayed
    assert verify_totp(s, pyotp.TOTP(s).at(now - 120), last_used_step=None, now=now) is None  # too old


# --------------------------------------------------------------------------- enrollment
@pytest.mark.tid("M04-T002")
def test_totp_enrollment_encrypts_secret_and_upgrades_session(db_client, owner_conn):
    from app.auth.mfa import decrypt_secret

    phone = register_and_verify(db_client)
    other_device = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    setup = db_client.post("/api/v1/auth/mfa/totp/setup").json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/Bongo%20Markets") and "<svg" in setup["qr_svg"]
    uid = user_row(owner_conn, phone)[0]
    enc = owner_conn.execute("SELECT totp_secret_enc FROM bm.users WHERE id=%s", (uid,)).fetchone()[0]
    assert enc.startswith("v1:") and setup["secret"] not in enc
    settings = db_client.app.state.settings
    assert decrypt_secret(settings, enc, user_id=uid) == setup["secret"]
    with pytest.raises(Exception):
        decrypt_secret(settings, enc, user_id=uid + 1)  # ciphertext is bound to its user
    totp = Totp(setup["secret"])
    bad = db_client.post("/api/v1/auth/mfa/totp/confirm", json={"code": "000000"})
    assert bad.status_code == 400
    ok = db_client.post("/api/v1/auth/mfa/totp/confirm", json={"code": totp.code()})
    codes = ok.json()["recovery_codes"]
    assert len(codes) == 10 and all(re.fullmatch(r"[A-Z2-9]{5}-[A-Z2-9]{5}", c) for c in codes)
    sessions = db_client.get("/api/v1/auth/sessions").json()["sessions"]
    assert len(sessions) == 1 and sessions[0]["current"] and sessions[0]["mfa"]  # ID-010: others revoked
    switch(db_client, other_device)
    assert db_client.get("/api/v1/auth/me").status_code == 401


# --------------------------------------------------------------------------- MFA login
@pytest.mark.tid("M04-T003")
def test_mfa_login_challenge_is_bound_limited_and_single_use(db_client, owner_conn):
    phone = register_and_verify(db_client)
    totp, _ = enable_mfa(db_client)
    db_client.cookies.clear()
    r = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    assert r.json()["mfa_required"] and "set-cookie" not in r.headers
    cid = r.json()["challenge_id"]
    assert db_client.get("/api/v1/auth/me").status_code == 401
    for _ in range(5):
        assert db_client.post("/api/v1/auth/login/mfa", json={"challenge_id": cid, "code": "000000"}) \
            .status_code == 401
    exhausted = db_client.post("/api/v1/auth/login/mfa", json={"challenge_id": cid, "code": totp.code()})
    assert exhausted.status_code == 401  # attempts exhausted even with the right code
    good = mfa_login(db_client, phone, totp)
    assert good.status_code == 200 and "bm_session=" in good.headers["set-cookie"]
    # challenge is single-use
    r = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    cid2 = r.json()["challenge_id"]
    db_client.post("/api/v1/auth/login/mfa", json={"challenge_id": cid2, "code": totp.code()})
    assert db_client.post("/api/v1/auth/login/mfa", json={"challenge_id": cid2, "code": totp.code()}) \
        .status_code == 401
    # expired challenge
    r = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    owner_conn.execute("UPDATE bm.login_challenges SET expires_at = now() - interval '1 s' WHERE public_id=%s",
                       (r.json()["challenge_id"],))
    assert db_client.post("/api/v1/auth/login/mfa", json={"challenge_id": r.json()["challenge_id"],
                                                          "code": totp.code()}).status_code == 401


@pytest.mark.tid("M04-T004")
def test_recovery_codes_are_single_use(db_client, owner_conn):
    phone = register_and_verify(db_client)
    _, codes = enable_mfa(db_client)
    stored = owner_conn.execute("SELECT code_hash FROM bm.mfa_recovery_codes rc JOIN bm.users u ON u.id=rc.user_id "
                                "WHERE u.phone_e164=%s", (e164(phone),)).fetchall()
    assert all(codes[0] not in h for (h,) in stored)
    for attempt, expected in ((codes[0].lower().replace("-", " "), 200), (codes[0], 401)):
        db_client.cookies.clear()
        cid = db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG}) \
            .json()["challenge_id"]
        r = db_client.post("/api/v1/auth/login/mfa", json={"challenge_id": cid, "code": attempt})
        assert r.status_code == expected


# --------------------------------------------------------------------------- step-up (SEC-MFA-002, AUTH-008 v1.12.2)
@pytest.mark.tid("M04-T005")
def test_step_up_grant_is_bound_short_lived_and_single_use(db_client, owner_conn):
    phone = register_and_verify(db_client)
    totp, _ = enable_mfa(db_client)
    token = step_up(db_client, "MFA_DISABLE", totp)
    th = hashlib.sha256(token.encode()).hexdigest()
    created, expires = owner_conn.execute("SELECT created_at, expires_at FROM bm.step_up_grants WHERE token_hash=%s",
                                          (th,)).fetchone()
    assert expires - created <= timedelta(seconds=300)
    # wrong action
    r = db_client.post("/api/v1/auth/mfa/recovery-codes", headers={"X-Step-Up-Token": token})
    assert r.status_code == 403 and r.json()["error"]["code"] == "step_up_required"
    # another session cannot use it
    mine = db_client.cookies.get("bm_session")
    other = mfa_login(db_client, phone, totp)
    assert other.status_code == 200
    assert db_client.post("/api/v1/auth/mfa/totp/disable", headers={"X-Step-Up-Token": token}).status_code == 403
    switch(db_client, mine)
    # expired
    owner_conn.execute("UPDATE bm.step_up_grants SET expires_at = created_at WHERE token_hash=%s", (th,))
    assert db_client.post("/api/v1/auth/mfa/totp/disable", headers={"X-Step-Up-Token": token}).status_code == 403
    # the database itself refuses grants longer than 300 s
    with pytest.raises(errors.CheckViolation):
        owner_conn.execute("UPDATE bm.step_up_grants SET expires_at = created_at + interval '301 s' "
                           "WHERE token_hash=%s", (th,))
    # fresh grant works exactly once
    token2 = step_up(db_client, "RECOVERY_CODES", totp)
    assert db_client.post("/api/v1/auth/mfa/recovery-codes", headers={"X-Step-Up-Token": token2}).status_code == 200
    assert db_client.post("/api/v1/auth/mfa/recovery-codes", headers={"X-Step-Up-Token": token2}).status_code == 403


@pytest.mark.tid("M04-T006")
def test_disabling_mfa_requires_step_up_with_totp(db_client):
    register_and_verify(db_client)
    totp, _ = enable_mfa(db_client)
    assert db_client.post("/api/v1/auth/mfa/totp/disable").status_code == 403
    pw_only = db_client.post("/api/v1/auth/step-up", json={"action": "MFA_DISABLE", "password": STRONG})
    assert pw_only.status_code == 401  # TOTP factor is mandatory once enabled
    token = step_up(db_client, "MFA_DISABLE", totp)
    assert db_client.post("/api/v1/auth/mfa/totp/disable", headers={"X-Step-Up-Token": token}).status_code == 200
    assert db_client.get("/api/v1/auth/me").status_code == 200


# --------------------------------------------------------------------------- sessions (AUTH-004/005/009, SEC-002)
@pytest.mark.tid("M04-T007")
def test_session_listing_and_immediate_revocation(db_client, owner_conn):
    phone = register_and_verify(db_client)
    first = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    listing = db_client.get("/api/v1/auth/sessions").json()["sessions"]
    assert len(listing) == 2 and sum(s["current"] for s in listing) == 1
    text = str(listing)
    assert first not in text and "token" not in text
    uid = user_row(owner_conn, phone)[0]
    internal_ids = {str(r[0]) for r in owner_conn.execute("SELECT id FROM bm.user_sessions WHERE user_id=%s", (uid,))}
    assert not internal_ids & {s["id"] for s in listing}
    other = next(s for s in listing if not s["current"])
    assert db_client.delete(f"/api/v1/auth/sessions/{other['id']}").status_code == 200
    me = db_client.cookies.get("bm_session")
    switch(db_client, first)
    assert db_client.get("/api/v1/auth/me").status_code == 401  # revoked at once, no cache window
    switch(db_client, me)
    stored = owner_conn.execute("SELECT token_hash FROM bm.user_sessions WHERE user_id=%s", (uid,)).fetchall()
    assert all(len(h) == 64 and h != me for (h,) in stored)  # AUTH-005: only the hash is stored


# --------------------------------------------------------------------------- phone change (ID-005, ID-008, ID-010)
@pytest.mark.tid("M04-T008")
def test_phone_change_requires_step_up_and_new_number_code(db_client, owner_conn):
    phone = register_and_verify(db_client)
    other_session = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    db_client.post("/api/v1/auth/login", json={"identifier": phone, "password": STRONG})
    new = new_phone()
    assert db_client.post("/api/v1/auth/phone/change-request", json={"new_phone": new}).status_code == 403
    token = step_up(db_client, "PHONE_CHANGE")
    r = db_client.post("/api/v1/auth/phone/change-request", json={"new_phone": new},
                       headers={"X-Step-Up-Token": token})
    assert r.status_code == 202
    vid = r.json()["verification_id"]
    code = last_code(db_client, e164(new))  # sent to the NEW number only
    assert db_client.post("/api/v1/auth/phone/confirm", json={"verification_id": vid, "code": code}).status_code == 200
    assert user_row(owner_conn, new) is not None and user_row(owner_conn, phone) is None
    assert "imebadilishwa" in db_client.app.state.notifier.last_to(e164(phone)).body  # old number warned
    switch(db_client, other_session)
    assert db_client.get("/api/v1/auth/me").status_code == 401


@pytest.mark.tid("M04-T009")
def test_otp_is_bound_to_purpose_challenge_and_destination(db_client):
    phone = new_phone()
    vid = register(db_client, phone).json()["verification_id"]
    code = last_code(db_client, e164(phone))
    # A registration code/id cannot be redeemed as a password-reset or phone-change code (ID-005).
    r = db_client.post("/api/v1/auth/password/reset", json={"reset_id": vid, "code": code,
                                                            "new_password": "Ndizi-Mbivu-2027"})
    assert r.status_code == 400
    # The same 6 digits are not portable between challenges either (ID-004).
    other = new_phone()
    vid2 = register(db_client, other).json()["verification_id"]
    assert db_client.post("/api/v1/auth/verify-phone", json={"verification_id": vid2, "code": code}) \
        .status_code == 400 or last_code(db_client, e164(other)) == code
    assert db_client.post("/api/v1/auth/verify-phone", json={"verification_id": vid, "code": code}).status_code == 200


@pytest.mark.tid("M04-T010")
def test_password_reset_of_mfa_account_needs_second_factor(db_client):
    phone = register_and_verify(db_client)
    totp, _ = enable_mfa(db_client)
    rid = db_client.post("/api/v1/auth/password/forgot", json={"identifier": phone}).json()["reset_id"]
    code = last_code(db_client, e164(phone))
    body = {"reset_id": rid, "code": code, "new_password": "Ndizi-Mbivu-2027"}
    sms_only = db_client.post("/api/v1/auth/password/reset", json=body)
    assert sms_only.status_code == 400 and sms_only.json()["error"]["code"] == "mfa_required"
    ok = db_client.post("/api/v1/auth/password/reset", json={**body, "mfa_code": totp.code()})
    assert ok.status_code == 200
    assert mfa_login(db_client, phone, totp, password="Ndizi-Mbivu-2027").status_code == 200


# --------------------------------------------------------------------------- SMS pumping (ID-011)
@pytest.mark.tid("M04-T011")
def test_sms_pumping_limits(db_client, pg):
    from app.auth import ratelimit as rl
    from app.db.session import get_engine

    phone = register_and_verify(db_client)
    statuses = [db_client.post("/api/v1/auth/password/forgot", json={"identifier": phone}).status_code
                for _ in range(8)]
    assert 429 in statuses  # per-destination / per-identifier caps stop repeated SMS to one number
    engine = get_engine(db_client.app.state.settings)
    tiny = rl.Limit("sms-global-test", 3, 3600)
    for _ in range(3):
        rl.hit(engine, tiny, "all")
    with pytest.raises(rl.RateLimited):
        rl.hit(engine, tiny, "all")
    assert rl.SMS_GLOBAL.max_hits > 0 and rl.SMS_PER_DESTINATION.max_hits <= 10


# --------------------------------------------------------------------------- ID-012
@pytest.mark.tid("M04-T012")
def test_secrets_never_appear_in_logs(db_client, caplog):
    caplog.set_level(logging.DEBUG)
    phone = register_and_verify(db_client)
    reg_code = last_code(db_client, e164(phone))
    setup = db_client.post("/api/v1/auth/mfa/totp/setup").json()
    totp = Totp(setup["secret"])
    confirm = db_client.post("/api/v1/auth/mfa/totp/confirm", json={"code": totp.code()}).json()
    rid = db_client.post("/api/v1/auth/password/forgot", json={"identifier": phone}).json()["reset_id"]
    reset_code = last_code(db_client, e164(phone))
    session = db_client.cookies.get("bm_session")
    logs = "\n".join(r.getMessage() + " " + str(getattr(r, "extra_fields", "")) for r in caplog.records)
    for secret in (STRONG, reg_code, reset_code, setup["secret"], session, *confirm["recovery_codes"]):
        assert secret not in logs
    assert rid  # reset id is not a secret (useless without the code)


# --------------------------------------------------------------------------- roles (AUTH-008, AUTH-005 v1.12.2, ID-007)
@pytest.mark.tid("M04-T013")
def test_roles_cannot_be_self_assigned_and_grants_need_mfa_step_up(db_client, owner_conn):
    r = db_client.post("/api/v1/auth/register", json={"full_name": "Hacker", "phone": new_phone(),
                                                      "password": STRONG, "role": "SUPER_ADMIN"})
    assert r.status_code == 422  # unknown fields are rejected outright
    # target user with MFA
    register_and_verify(db_client)
    enable_mfa(db_client)
    target = public_id(db_client)
    # plain user cannot grant
    plain = db_client.post(f"/api/v1/admin/users/{target}/roles", json={"role": "SUPPORT"})
    assert plain.status_code == 403
    _, admin_totp = make_admin(db_client, owner_conn)
    no_step = db_client.post(f"/api/v1/admin/users/{target}/roles", json={"role": "SUPPORT"})
    assert no_step.status_code == 403 and no_step.json()["error"]["code"] == "step_up_required"
    pw_only = db_client.post("/api/v1/auth/step-up", json={"action": "ROLE_ASSIGN", "password": STRONG})
    assert pw_only.status_code == 401  # strong factor required
    token = step_up(db_client, "ROLE_ASSIGN", admin_totp)
    ok = db_client.post(f"/api/v1/admin/users/{target}/roles", json={"role": "SUPPORT"},
                        headers={"X-Step-Up-Token": token})
    assert ok.status_code == 201, ok.text
    actions = [a for (a,) in owner_conn.execute("SELECT action FROM bm.audit_logs WHERE action='role.granted'")]
    assert actions
    self_token = step_up(db_client, "ROLE_ASSIGN", admin_totp)
    me = public_id(db_client)
    selfg = db_client.post(f"/api/v1/admin/users/{me}/roles", json={"role": "FINANCE"},
                           headers={"X-Step-Up-Token": self_token})
    assert selfg.status_code == 403


@pytest.mark.tid("M04-T014")
def test_privileged_roles_require_totp_and_cannot_drop_mfa(db_client, owner_conn):
    _, admin_totp = make_admin(db_client, owner_conn)
    admin_cookie = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    register_and_verify(db_client)  # no MFA
    target = public_id(db_client)
    switch(db_client, admin_cookie)
    token = step_up(db_client, "ROLE_ASSIGN", admin_totp)
    r = db_client.post(f"/api/v1/admin/users/{target}/roles", json={"role": "FINANCE"},
                       headers={"X-Step-Up-Token": token})
    assert r.status_code == 409 and r.json()["error"]["code"] == "target_mfa_required"
    token = step_up(db_client, "MFA_DISABLE", admin_totp)
    r = db_client.post("/api/v1/auth/mfa/totp/disable", headers={"X-Step-Up-Token": token})
    assert r.status_code == 403 and r.json()["error"]["code"] == "mfa_required_for_role"
    # An admin session without the TOTP factor (aal1) cannot use admin APIs.
    owner_conn.execute("UPDATE bm.user_sessions SET aal = 1 WHERE token_hash=%s",
                       (hashlib.sha256(admin_cookie.encode()).hexdigest(),))
    r = db_client.post(f"/api/v1/admin/users/{target}/roles", json={"role": "SUPPORT"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "mfa_required"


# --------------------------------------------------------------------------- incident response (SEC-IR-003)
@pytest.mark.tid("M04-T015")
def test_incident_response_actions(db_client, owner_conn):
    victim_phone = register_and_verify(db_client)
    victim = public_id(db_client)
    victim_cookie = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    _, totp = make_admin(db_client, owner_conn, role="PLATFORM_ADMIN")

    def act(path, body=None):
        token = step_up(db_client, "INCIDENT_RESPONSE", totp)
        return db_client.post(path, json=body, headers={"X-Step-Up-Token": token})

    assert act(f"/api/v1/admin/incident/users/{victim}/suspend", {"reason": "account takeover"}).status_code == 200
    admin_cookie = db_client.cookies.get("bm_session")
    switch(db_client, victim_cookie)
    assert db_client.get("/api/v1/auth/me").status_code == 401
    db_client.cookies.clear()
    assert db_client.post("/api/v1/auth/login", json={"identifier": victim_phone, "password": STRONG}) \
        .status_code == 401
    switch(db_client, admin_cookie)
    assert act(f"/api/v1/admin/incident/users/{victim}/reinstate", {"reason": "resolved"}).status_code == 200
    assert act("/api/v1/admin/incident/payments", {"suspended": True, "reason": "provider breach"}) \
        .json()["payments_suspended"] is True
    flag = owner_conn.execute("SELECT value FROM bm.system_flags WHERE key='payments_suspended'").fetchone()[0]
    assert flag == "true"
    assert act(f"/api/v1/admin/incident/users/{victim}/sign-out").status_code == 200
    audited = {a for (a,) in owner_conn.execute("SELECT action FROM bm.audit_logs WHERE action LIKE 'incident.%'")}
    assert {"incident.user_suspended", "incident.user_reinstated", "incident.payments_suspended",
            "incident.sessions_revoked"} <= audited


# --------------------------------------------------------------------------- V13-SEC-002
@pytest.mark.tid("M04-T016")
def test_event_replay_guard(pg, make_settings):
    from app.db.session import session_factory
    from app.services.replay import ReplayRejected, accept_event

    settings = make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url)
    now = datetime.now(UTC)
    eid = f"evt-{time.time_ns()}"
    with session_factory(settings)() as db:
        accept_event(db, source="test", event_id=eid, event_time=now)
        db.commit()
        for kwargs, reason in (({"event_id": eid, "event_time": now}, "duplicate_event"),
                               ({"event_id": eid + "b", "event_time": now - timedelta(minutes=6)},
                                "outside_replay_window"),
                               ({"event_id": eid + "c", "event_time": now.replace(tzinfo=None)},
                                "timestamp_without_timezone"),
                               ({"event_id": "", "event_time": now}, "missing_or_invalid_event_id")):
            with pytest.raises(ReplayRejected) as exc:
                accept_event(db, source="test", **kwargs)
            assert exc.value.reason == reason
            db.rollback()


# --------------------------------------------------------------------------- operator CLI (SEC-IR-003)
@pytest.mark.tid("M04-T017")
def test_admin_cli_bootstrap_and_break_glass(db_client, owner_conn, pg, make_settings):
    from scripts.admin_cli import run

    owner_conn.execute("UPDATE bm.user_platform_roles SET revoked_at = now() WHERE role_code='SUPER_ADMIN' "
                       "AND revoked_at IS NULL")
    settings = make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url)
    no_mfa = register_and_verify(db_client)
    with pytest.raises(SystemExit, match="TOTP"):
        run(["bootstrap-super-admin", "--phone", no_mfa, "--operator", "ops"], settings)
    enable_mfa(db_client)
    assert "SUPER_ADMIN granted" in run(["bootstrap-super-admin", "--phone", no_mfa, "--operator", "ops"], settings)
    with pytest.raises(SystemExit, match="already exists"):
        run(["bootstrap-super-admin", "--phone", no_mfa, "--operator", "ops"], settings)
    with pytest.raises(SystemExit, match="reason"):
        run(["suspend-user", "--phone", no_mfa, "--operator", "ops"], settings)
    assert "revoked" in run(["revoke-sessions", "--phone", no_mfa, "--operator", "ops", "--reason", "drill"],
                            settings)
    assert "SUSPENDED" in run(["payments", "--suspend", "--operator", "ops", "--reason", "drill"], settings)
    assert "resumed" in run(["payments", "--resume", "--operator", "ops", "--reason", "drill over"], settings)
    rows = owner_conn.execute("SELECT actor_type, details->>'operator' FROM bm.audit_logs WHERE actor_type='cli'") \
        .fetchall()
    assert rows and all(op == "ops" for _, op in rows)
    owner_conn.execute("UPDATE bm.user_platform_roles SET revoked_at = now() WHERE role_code='SUPER_ADMIN' "
                       "AND revoked_at IS NULL")


@pytest.mark.tid("M04-T018")
def test_role_revocation_takes_effect_immediately(db_client, owner_conn):
    _, admin_totp = make_admin(db_client, owner_conn)
    admin_cookie = db_client.cookies.get("bm_session")
    db_client.cookies.clear()
    target_phone = register_and_verify(db_client)
    target_totp, _ = enable_mfa(db_client)
    target = public_id(db_client)
    switch(db_client, admin_cookie)
    token = step_up(db_client, "ROLE_ASSIGN", admin_totp)
    db_client.post(f"/api/v1/admin/users/{target}/roles", json={"role": "PLATFORM_ADMIN"},
                   headers={"X-Step-Up-Token": token})
    admin_cookie = db_client.cookies.get("bm_session")
    assert mfa_login(db_client, target_phone, target_totp).status_code == 200
    target_cookie = db_client.cookies.get("bm_session")
    switch(db_client, admin_cookie)
    token = step_up(db_client, "ROLE_ASSIGN", admin_totp)
    assert db_client.delete(f"/api/v1/admin/users/{target}/roles/PLATFORM_ADMIN",
                            headers={"X-Step-Up-Token": token}).status_code == 200
    switch(db_client, target_cookie)
    assert db_client.get("/api/v1/auth/me").status_code == 401  # privileged session gone at once


# --------------------------------------------------------------------------- web
@pytest.mark.tid("M04-T019")
def test_web_mfa_enrollment_and_login(db_client):
    phone = register_and_verify(db_client)
    page = db_client.get("/akaunti/usalama")
    assert page.status_code == 200 and "Washa MFA" in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    begin = db_client.post("/akaunti/usalama/mfa/anza", data={"csrf": csrf})
    assert "<svg" in begin.text
    secret = re.search(r"<code[^>]*>([A-Z2-7 ]+)</code>", begin.text).group(1).replace(" ", "")
    totp = Totp(secret)
    done = db_client.post("/akaunti/usalama/mfa/thibitisha", data={"csrf": csrf, "code": totp.code()})
    assert "namba zako za dharura" in done.text and done.headers["cache-control"] == "no-store"
    assert len(re.findall(r"<code>[A-Z2-9]{5}-[A-Z2-9]{5}</code>", done.text)) == 10
    db_client.cookies.delete("bm_session")
    r = db_client.post("/ingia", data={"csrf": csrf, "identifier": phone, "password": STRONG},
                       follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/ingia/mfa?c=")
    cid = r.headers["location"].split("c=")[1]
    r = db_client.post("/ingia/mfa", data={"csrf": csrf, "c": cid, "code": totp.code()}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/akaunti"
    assert "Imewashwa" in db_client.get("/akaunti").text


@pytest.mark.tid("M04-T020")
def test_changing_verified_email_needs_step_up(db_client):
    from tests.test_m03_auth import _counter

    email = f"asha{next(_counter)}@example.com"
    register_and_verify(db_client, email=email)
    vid = db_client.post("/api/v1/auth/email/verify-request", json={"email": email}).json()["verification_id"]
    db_client.post("/api/v1/auth/email/verify", json={"verification_id": vid, "code": last_code(db_client, email)})
    new_email = f"new{next(_counter)}@example.com"
    r = db_client.post("/api/v1/auth/email/verify-request", json={"email": new_email})
    assert r.status_code == 403 and r.json()["error"]["code"] == "step_up_required"
    token = step_up(db_client, "EMAIL_CHANGE")
    r = db_client.post("/api/v1/auth/email/verify-request", json={"email": new_email},
                       headers={"X-Step-Up-Token": token})
    assert r.status_code == 202


@pytest.mark.tid("M04-T021")
def test_unknown_step_up_action_and_rate_limit(db_client):
    register_and_verify(db_client)
    r = db_client.post("/api/v1/auth/step-up", json={"action": "BECOME_ADMIN", "password": STRONG})
    assert r.status_code == 422
    codes = [db_client.post("/api/v1/auth/step-up", json={"action": "PHONE_CHANGE", "password": "wrong-pass-x"})
             .status_code for _ in range(11)]
    assert codes[-1] == 429
