"""Test configuration.

Each test carries ``@pytest.mark.tid("Mxx-Tnnn")``. Module and ``protected``
markers are derived from the authoritative catalogue so they cannot drift.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

CATALOGUE = yaml.safe_load((Path(__file__).parent / "catalogue.yaml").read_text(encoding="utf-8"))
BY_ID = {e["id"]: e for e in CATALOGUE.get("tests", [])}


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "tid(id): Test Catalogue ID")
    config.addinivalue_line("markers", "protected: protected security/control regression")
    for i in range(1, 21):
        config.addinivalue_line("markers", f"module_m{i:02d}: tests for module M{i:02d}")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        marker = item.get_closest_marker("tid")
        if marker is None:
            raise pytest.UsageError(f"{item.nodeid} has no @pytest.mark.tid (DEV-004)")
        entry = BY_ID.get(marker.args[0])
        if entry is None:
            raise pytest.UsageError(f"{item.nodeid}: {marker.args[0]} not in catalogue")
        item.add_marker(getattr(pytest.mark, f"module_{entry['module'].lower()}"))
        if entry.get("protected"):
            item.add_marker(pytest.mark.protected)


@pytest.fixture
def make_settings(monkeypatch):
    from app.core.config import Settings

    def _make(**env: str) -> Settings:
        for key in list(__import__("os").environ):
            if key.startswith("BM_"):
                monkeypatch.delenv(key, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return Settings(_env_file=None)

    return _make


@pytest.fixture
def client(make_settings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    # Deliberately unreachable database: M01 tests must not depend on one.
    app = create_app(make_settings(BM_ENVIRONMENT="test",
                                   BM_DATABASE_URL="postgresql+psycopg://none:none@127.0.0.1:1/none"))
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------- PostgreSQL (M02+)
import os  # noqa: E402
import secrets  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
from types import SimpleNamespace  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from pgutil import parse, tool  # noqa: E402

TEST_DB = "bongomarkets_test"
TEST_ROLES = {"owner": "bmt_owner", "app": "bmt_app", "ro": "bmt_ro"}


def _admin_psql(admin, sql, db=None):
    subprocess.run([tool("psql"), *admin.args(db), "-v", "ON_ERROR_STOP=1", "-qc", sql],
                   env=admin.env(), check=True, capture_output=True)


def run_alembic(owner_url: str, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "BM_MIGRATION_DATABASE_URL": owner_url,
           "BM_DB_APP_ROLE": TEST_ROLES["app"], "BM_DB_READONLY_ROLE": TEST_ROLES["ro"]}
    return subprocess.run([sys.executable, "-m", "alembic", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True)


@pytest.fixture(scope="session")
def pg():
    admin_url = os.environ.get("BM_TEST_ADMIN_URL")
    if not admin_url:
        pytest.fail("BM_TEST_ADMIN_URL is not set (a PostgreSQL superuser URL is required for DB tests)")
    admin = parse(admin_url)
    pw = {k: secrets.token_urlsafe(18) for k in TEST_ROLES}
    _admin_psql(admin, f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)')
    for role in TEST_ROLES.values():
        _admin_psql(admin, f'DROP ROLE IF EXISTS "{role}"')
    subprocess.run(
        [tool("psql"), *admin.args(), "-q", "-v", "ON_ERROR_STOP=1", "-v", f"db_name={TEST_DB}",
         "-v", f"owner_role={TEST_ROLES['owner']}", "-v", f"owner_pw={pw['owner']}",
         "-v", f"app_role={TEST_ROLES['app']}", "-v", f"app_pw={pw['app']}",
         "-v", f"ro_role={TEST_ROLES['ro']}", "-v", f"ro_pw={pw['ro']}",
         "-f", str(ROOT / "db" / "bootstrap.sql")],
        env=admin.env(), check=True, capture_output=True,
    )

    def url(kind):
        return (f"postgresql+psycopg://{TEST_ROLES[kind]}:{pw[kind]}"
                f"@{admin.host}:{admin.port}/{TEST_DB}")

    owner_url = url("owner")
    res = run_alembic(owner_url, "upgrade", "head")
    assert res.returncode == 0, res.stderr
    return SimpleNamespace(admin_url=admin_url, owner_url=owner_url, app_url=url("app"), ro_url=url("ro"),
                           db=TEST_DB, roles=TEST_ROLES)


@pytest.fixture
def db_client(pg, make_settings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    app = create_app(make_settings(BM_ENVIRONMENT="test", BM_DATABASE_URL=pg.app_url))
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def app_conn(pg):
    import psycopg

    with psycopg.connect(pg.app_url.replace("+psycopg", ""), autocommit=True) as conn:
        yield conn


@pytest.fixture
def owner_conn(pg):
    import psycopg

    with psycopg.connect(pg.owner_url.replace("+psycopg", ""), autocommit=True) as conn:
        yield conn
