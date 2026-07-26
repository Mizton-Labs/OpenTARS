"""Tests for GET/POST /api/app/config-drift (issue-local-024 follow-up)."""

from __future__ import annotations

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.config import loader
from backend.main import app
from backend.normalizer import config as normalizer_config


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
    monkeypatch.setattr(loader, "SOURCES_PATH", tmp_path / "sources.yaml")
    monkeypatch.setattr(loader, "FIELDS_PATH", tmp_path / "feed-fields.yaml")
    monkeypatch.setattr(
        normalizer_config, "_NORMALIZER_CONFIG_PATH", tmp_path / "normalizer-config.yaml"
    )
    return TestClient(app), tmp_path


def test_get_config_drift_empty_when_no_files_present(client):
    c, _ = client
    resp = c.get("/api/app/config-drift")
    assert resp.status_code == 200
    assert resp.json() == {"reports": []}


def test_get_config_drift_reports_missing_core_field(client):
    c, tmp_path = client
    _write(
        tmp_path / "feed-fields.yaml",
        {"core_fields": [{"name": "indicator", "description": "d", "enabled": True}]},
    )
    _write(
        tmp_path / "feed-fields.yaml.example",
        {
            "core_fields": [
                {"name": "indicator", "description": "d", "enabled": True},
                {"name": "new_field", "description": "new", "enabled": True},
            ]
        },
    )
    resp = c.get("/api/app/config-drift")
    assert resp.status_code == 200
    reports = resp.json()["reports"]
    assert len(reports) == 1
    assert reports[0]["file"] == "feed-fields.yaml"
    assert reports[0]["missing_core_fields"] == [{"name": "new_field", "description": "new"}]


def test_apply_config_drift_adds_field_and_clears_it_from_the_report(client):
    c, tmp_path = client
    _write(tmp_path / "feed-fields.yaml", {"core_fields": []})
    _write(
        tmp_path / "feed-fields.yaml.example",
        {"core_fields": [{"name": "new_field", "description": "new", "enabled": True}]},
    )

    resp = c.post(
        "/api/app/config-drift/apply",
        json={"file": "feed-fields.yaml", "core_field_names": ["new_field"]},
    )
    assert resp.status_code == 200
    assert resp.json() == {"reports": []}

    live = yaml.safe_load((tmp_path / "feed-fields.yaml").read_text(encoding="utf-8"))
    assert live["core_fields"] == [{"name": "new_field", "description": "new", "enabled": True}]


def test_apply_config_drift_rejects_empty_selection(client):
    c, tmp_path = client
    _write(tmp_path / "application.yaml", {})
    _write(tmp_path / "application.yaml.example", {"app_title": ""})

    resp = c.post("/api/app/config-drift/apply", json={"file": "application.yaml"})
    assert resp.status_code == 400
    assert "at least one" in resp.json()["detail"]


def test_apply_config_drift_rejects_missing_file_field(client):
    c, _ = client
    resp = c.post("/api/app/config-drift/apply", json={"keys": ["x"]})
    assert resp.status_code == 400


def test_apply_config_drift_rejects_unknown_file(client):
    c, _ = client
    resp = c.post(
        "/api/app/config-drift/apply",
        json={"file": "not-real.yaml", "keys": ["x"]},
    )
    assert resp.status_code == 400
    assert "unknown config file" in resp.json()["detail"]


def test_apply_config_drift_rejects_non_string_keys(client):
    c, _ = client
    resp = c.post(
        "/api/app/config-drift/apply",
        json={"file": "application.yaml", "keys": [123]},
    )
    assert resp.status_code == 400
