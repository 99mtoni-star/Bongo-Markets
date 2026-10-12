"""Module 06 – Shared UI, Header na Navigation."""

from __future__ import annotations

import re
import socket
import threading
import time
from pathlib import Path

import pytest

from tests.conftest import ROOT
from tests.test_m03_auth import STRONG, new_phone, register, register_and_verify
from tests.test_m04_security import make_admin

PAGES_ANON = ["/", "/hali", "/ingia", "/jisajili", "/umesahau-nenosiri", "/faragha", "/masharti", "/soko"]
PAGES_AUTH = ["/", "/akaunti", "/akaunti/usalama", "/soko"]


@pytest.fixture(autouse=True)
def _reset(owner_conn):
    owner_conn.execute("DELETE FROM bm.rate_limit_buckets")
    yield


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


@pytest.mark.tid("M06-T001")
def test_navigation_adapts_to_buyer_seller_and_admin(db_client, owner_conn):
    home = db_client.get("/").text
    assert 'href="/ingia"' in home and 'href="/jisajili"' in home and 'href="/soko"' in home
    assert '<details class="menu">' in home  # phone menu without JavaScript
    register_and_verify(db_client, name="Neema Mollel")
    home = db_client.get("/").text
    assert 'href="/akaunti"' in home and "Toka (Neema)" in home and 'href="/maduka"' in home
    assert "Usimamizi" not in home
    db_client.cookies.clear()
    make_admin(db_client, owner_conn)
    assert 'href="/simamizi/majukumu"' in db_client.get("/").text
    acct = db_client.get("/akaunti").text
    assert 'href="/akaunti" aria-current="page"' in acct


@pytest.mark.tid("M06-T002")
def test_strict_csp_and_no_inline_code(db_client):
    r = db_client.get("/")
    csp = r.headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
    for directive in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'",
                      "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"):
        assert directive in csp
    pages = [db_client.get(p).text for p in PAGES_ANON]
    register_and_verify(db_client)
    pages += [db_client.get(p).text for p in PAGES_AUTH]
    for html in pages:
        assert "<script" not in html.lower()
        assert not re.search(r"\sstyle=", html), "inline style attribute found"
        assert not re.search(r"\son[a-z]+=", html), "inline event handler found"


@pytest.mark.tid("M06-T003")
def test_user_content_is_output_encoded(db_client):
    payload = '<script>alert(1)</script><img src=x onerror=alert(1)>"\''
    phone = new_phone()
    r = register(db_client, phone, name=f"Amina {payload}")
    assert r.status_code == 202
    from tests.test_m03_auth import e164, last_code

    db_client.post("/api/v1/auth/verify-phone",
                   json={"verification_id": r.json()["verification_id"], "code": last_code(db_client, e164(phone))})
    for path in ("/akaunti", "/", "/akaunti/usalama"):
        html = db_client.get(path).text
        assert "<script>alert(1)</script>" not in html and "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in db_client.get("/akaunti").text


@pytest.mark.tid("M06-T004")
def test_csrf_and_origin_are_independent_controls(db_client):
    page = db_client.get("/ingia")
    token = csrf_of(page.text)
    form = {"csrf": token, "identifier": new_phone(), "password": STRONG}
    # valid CSRF token, foreign Origin -> rejected
    assert db_client.post("/ingia", data=form, headers={"Origin": "https://evil.example"}).status_code == 403
    # valid Origin, missing CSRF token -> rejected
    assert db_client.post("/ingia", data={**form, "csrf": ""}).status_code == 403
    # no Origin and no Referer -> rejected; matching Referer is accepted as fallback
    from fastapi.testclient import TestClient

    raw = TestClient(db_client.app, base_url="https://testserver", raise_server_exceptions=False)
    raw.cookies.set("bm_csrf", db_client.cookies.get("bm_csrf"))
    assert raw.post("/ingia", data=form).status_code == 403
    assert raw.post("/ingia", data=form, headers={"Referer": "https://testserver/ingia"}).status_code == 401
    # JSON API: allowed Origin but no X-CSRF-Token -> rejected
    r = raw.post("/api/v1/auth/login", json={"identifier": "x", "password": "y"},
                 headers={"Origin": "https://testserver"})
    assert r.status_code == 403 and "CSRF" in r.text
    ok = raw.post("/api/v1/auth/login", json={"identifier": "x", "password": "y"},
                  headers={"Origin": "https://testserver", "X-CSRF-Token": raw.cookies.get("bm_csrf")})
    assert ok.status_code == 401  # passed both controls, then normal login failure


@pytest.mark.tid("M06-T005")
def test_csrf_token_endpoint(db_client):
    from fastapi.testclient import TestClient

    c = TestClient(db_client.app, base_url="https://testserver")
    r = c.get("/api/v1/auth/csrf")
    token = r.json()["csrf_token"]
    cookie = r.headers["set-cookie"].lower()
    assert "bm_csrf=" in cookie and "httponly" in cookie and "samesite=strict" in cookie and "secure" in cookie
    assert c.cookies.get("bm_csrf") == token and r.headers["cache-control"] == "no-store"


@pytest.mark.tid("M06-T006")
def test_static_assets_are_versioned_and_safe(db_client):
    from app.web.layout import CSS_VERSION

    html = db_client.get("/").text
    assert f'/static/app.css?v={CSS_VERSION}' in html
    r = db_client.get(f"/static/app.css?v={CSS_VERSION}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/css")
    assert "immutable" in r.headers["cache-control"] and r.headers["x-content-type-options"] == "nosniff"
    assert db_client.get("/static/../app/main.py").status_code == 404


@pytest.mark.tid("M06-T007")
def test_application_log_retention_is_90_days():
    conf = (ROOT / "deploy" / "logrotate" / "bongo-markets").read_text()
    assert re.search(r"^\s*rotate 90$", conf, re.M) and re.search(r"^\s*maxage 90$", conf, re.M)
    assert "90 days" in (ROOT / "docs" / "operations" / "logging.md").read_text()


@pytest.mark.tid("M06-T008")
def test_secret_and_dependency_scanning_in_release_controls(tmp_path):
    import subprocess

    from scripts.scan_secrets import scan

    assert scan(ROOT) == []
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    (tmp_path / "config.py").write_text(f'KEY = "{fake_key}"\n')
    (tmp_path / ".env").write_text("BM_SECRET_KEY=x\n")
    found = scan(tmp_path, ["config.py", ".env"])
    assert any("aws-access-key" in f for f in found) and any(".env" in f for f in found)
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "scan_secrets.py" in ci and "pip-audit" in ci
    assert "Secret scan" in (ROOT / "scripts" / "gate.py").read_text()


@pytest.mark.tid("M06-T009")
def test_compliance_procedures_are_documented(db_client):
    breach = (ROOT / "docs" / "compliance" / "breach-response.md").read_text()
    for step in ("Detect", "escalate", "Contain", "Preserve evidence", "Notify"):
        assert step in breach
    xborder = (ROOT / "docs" / "compliance" / "cross-border-transfers.md").read_text()
    assert "approved Legal/Compliance basis" in xborder and "Register of processors" in xborder
    assert "CAP-CHAT-001" in (ROOT / "docs" / "compliance" / "feature-contracts.md").read_text()
    assert "nje ya Tanzania" in db_client.get("/faragha").text


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.tid("M06-T010")
def test_responsive_layout_in_real_browser(pg, make_settings):
    pytest.importorskip("playwright")
    import uvicorn
    from playwright.sync_api import sync_playwright

    from app.main import create_app

    app = create_app(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url, BM_COOKIE_SECURE="false"))
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            for width in (390, 1280):
                page = browser.new_page(viewport={"width": width, "height": 800})
                for path in ("/", "/ingia", "/jisajili", "/hali", "/faragha"):
                    page.goto(f"http://localhost:{port}{path}")
                    overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
                    assert overflow <= 0, (width, path, overflow)
                    menu_visible = page.locator("details.menu").is_visible()
                    assert menu_visible == (width < 700), (width, path)
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5)
    assert Path(ROOT / "docs" / "operations" / "browser-support.md").exists()
