"""Module 01 – Project Setup na Configuration."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.logging import JsonFormatter
from app.main import create_app

ROOT = Path(__file__).resolve().parent.parent
STRONG = "x" * 48
MARIADB = "mysql+pymysql://kar_app:pw@db:3306/kariakoo"


@pytest.mark.tid("M01-T001")
def test_config_from_env(make_settings):
    s = make_settings(KAR_APP_NAME="Kariakoo Test", KAR_LOG_LEVEL="DEBUG")
    assert s.app_name == "Kariakoo Test"
    assert s.log_level == "DEBUG"


@pytest.mark.tid("M01-T002")
@pytest.mark.parametrize("secret", ["change-me", "short", "secret"])
def test_production_rejects_weak_secret(make_settings, secret):
    with pytest.raises(ValueError, match="KAR_SECRET_KEY"):
        make_settings(KAR_ENVIRONMENT="production", KAR_SECRET_KEY=secret, KAR_DATABASE_URL=MARIADB)


@pytest.mark.tid("M01-T003")
def test_production_rejects_unsafe_settings(make_settings):
    with pytest.raises(ValueError) as exc:
        make_settings(
            KAR_ENVIRONMENT="production", KAR_SECRET_KEY=STRONG, KAR_DEBUG="true",
            KAR_DATABASE_URL="sqlite:///x.db", KAR_ALLOWED_HOSTS='["*"]',
        )
    msg = str(exc.value)
    assert "KAR_DEBUG" in msg and "MariaDB" in msg and "KAR_ALLOWED_HOSTS" in msg
    ok = make_settings(KAR_ENVIRONMENT="production", KAR_SECRET_KEY=STRONG, KAR_DATABASE_URL=MARIADB)
    assert ok.is_production_like


@pytest.mark.tid("M01-T004")
def test_health_probes(client):
    assert client.get("/health/live").json() == {"status": "ok"}
    r = client.get("/health/ready")
    assert r.status_code == 200 and r.json()["status"] == "ok"


@pytest.mark.tid("M01-T005")
def test_unhandled_error_is_controlled(make_settings):
    app = create_app(make_settings(KAR_ENVIRONMENT="test"))

    @app.get("/boom")
    def boom():
        raise RuntimeError("db password=hunter2 leaked")

    r = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500
    assert r.json() == {"error": {"code": 500, "message": "Internal server error"}}
    assert "hunter2" not in r.text and "Traceback" not in r.text


@pytest.mark.tid("M01-T006")
def test_security_headers_and_request_id(client):
    r = client.get("/health/live")
    for h in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy"):
        assert h in r.headers
    assert re.fullmatch(r"[0-9a-f]{32}", r.headers["X-Request-ID"])
    # Safe client-supplied ID is echoed; unsafe one is replaced.
    assert client.get("/health/live", headers={"X-Request-ID": "abc123"}).headers["X-Request-ID"] == "abc123"
    assert client.get("/health/live", headers={"X-Request-ID": "<script>"}).headers["X-Request-ID"] != "<script>"


@pytest.mark.tid("M01-T007")
def test_log_redaction():
    rec = logging.LogRecord("t", logging.INFO, __file__, 1, "login", None, None)
    rec.extra_fields = {"user": "amina", "password": "p@ss", "session_token": "abc", "Authorization": "Bearer x"}
    out = json.loads(JsonFormatter().format(rec))
    assert out["user"] == "amina"
    assert out["password"] == out["session_token"] == out["Authorization"] == "[REDACTED]"


@pytest.mark.tid("M01-T008")
def test_system_info_hides_secrets(make_settings):
    s = make_settings(KAR_ENVIRONMENT="test", KAR_SECRET_KEY="super-secret-value-123",
                      KAR_DATABASE_URL="sqlite:///./hidden-name.db")
    body = TestClient(create_app(s)).get("/api/v1/system/info").text
    assert "super-secret-value-123" not in body and "hidden-name" not in body
    assert "super-secret-value-123" not in repr(s)


@pytest.mark.tid("M01-T009")
def test_catalogue_integrity(tmp_path):
    from scripts.check_catalogue import check

    assert check() == []
    # Negative case: a duplicate ID must be detected.
    (tmp_path / "catalogue.yaml").write_text(
        "tests:\n  - {id: M01-T001, module: M01, requirements: [X]}\n"
        "  - {id: M01-T001, module: M01, requirements: [X]}\n"
    )
    marker = "pytest.mark." + 'tid("M01-T001")'  # split so the scanner ignores this literal
    (tmp_path / "test_x.py").write_text(f"import pytest\n@{marker}\ndef test_a(): pass\n")
    assert any("appears 2 times" in e for e in check(tmp_path / "catalogue.yaml", tmp_path))


@pytest.mark.tid("M01-T010")
def test_evidence_bundle(tmp_path):
    import hashlib
    import sys

    from scripts.evidence import run_bundle

    out, code = run_bundle("M01", [f"{sys.executable} -c \"print('hello')\""], tmp_path)
    assert code == 0
    ev = json.loads((out / "evidence.json").read_text())
    rec = ev["records"][0]
    assert rec["exit_code"] == 0 and rec["started_utc"].endswith("Z")
    assert ev["versions"]["python"] and ev["result"] == "PASS"
    assert rec["log_sha256"] == hashlib.sha256((out / rec["log"]).read_bytes()).hexdigest()
    manifest = (out / "MANIFEST.sha256").read_text()
    assert (out / "BUNDLE_DIGEST").read_text().strip() == hashlib.sha256(manifest.encode()).hexdigest()


@pytest.mark.tid("M01-T011")
def test_no_hardcoded_secrets():
    pattern = re.compile(
        r"""(?i)(password|secret|api[_-]?key|token)\s*=\s*["'][^"']{8,}["']|-----BEGIN [A-Z ]*PRIVATE KEY"""
    )
    offenders = [str(p) for p in (ROOT / "app").rglob("*.py") if pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


@pytest.mark.tid("M01-T012")
def test_status_page(client):
    r = client.get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    for i in range(1, 21):
        assert f"M{i:02d}" in r.text
    assert "<script" not in r.text.lower()


@pytest.mark.tid("M01-T013")
def test_docs_disabled_in_production(make_settings):
    s = make_settings(KAR_ENVIRONMENT="production", KAR_SECRET_KEY=STRONG, KAR_DATABASE_URL=MARIADB)
    c = TestClient(create_app(s), base_url="http://localhost")
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404
    assert "Strict-Transport-Security" in c.get("/health/live").headers


@pytest.mark.tid("M01-T014")
def test_untrusted_host_rejected(client):
    assert client.get("/health/live", headers={"Host": "evil.example"}).status_code == 400
