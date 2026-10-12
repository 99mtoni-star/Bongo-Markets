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
            if key.startswith("KAR_"):
                monkeypatch.delenv(key, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return Settings(_env_file=None)

    return _make


@pytest.fixture
def client(make_settings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    app = create_app(make_settings(KAR_ENVIRONMENT="test"))
    return TestClient(app, raise_server_exceptions=False)
