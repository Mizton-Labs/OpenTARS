"""Tests for issue-local-042 (item 27): a configurable RunsStatusTable page
size — the runs table embedded per hunt package in the list's Table view,
and the one shown inside an open hunt package, previously rendered every
run unpaginated.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


class TestLoaderTHRunsTablePageSize:
    def test_default(self, tmp_path: Path) -> None:
        from backend.config.loader import load_th_runs_table_page_size

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            assert load_th_runs_table_page_size() == 10

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        from backend.config.loader import (
            load_th_runs_table_page_size,
            save_th_runs_table_page_size,
        )

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            save_th_runs_table_page_size(25)
            assert load_th_runs_table_page_size() == 25

    def test_invalid_raises(self, tmp_path: Path) -> None:
        from backend.config.loader import save_th_runs_table_page_size

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            with pytest.raises(ValueError):
                save_th_runs_table_page_size(1)  # below MIN
            with pytest.raises(ValueError):
                save_th_runs_table_page_size(1000)  # above MAX
            with pytest.raises(ValueError):
                save_th_runs_table_page_size(True)  # bool, not a real int

    def test_out_of_range_on_disk_falls_back_to_default(self, tmp_path: Path) -> None:
        from backend.config.loader import _write_yaml, load_th_runs_table_page_size

        cfg_path = tmp_path / "app.yaml"
        with patch("backend.config.loader.APP_CONFIG_PATH", cfg_path):
            _write_yaml(cfg_path, {"th_runs_table_page_size": 99999})
            assert load_th_runs_table_page_size() == 10


class TestRouteTHRunsTablePageSize:
    def test_get_returns_default(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            client = TestClient(app)
            resp = client.get("/api/app/th-runs-table-page-size")
            assert resp.status_code == 200
            assert resp.json() == {"th_runs_table_page_size": 10}

    def test_put_persists_and_get_reflects_it(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            client = TestClient(app)
            put_resp = client.put(
                "/api/app/th-runs-table-page-size", json={"th_runs_table_page_size": 15}
            )
            assert put_resp.status_code == 200, put_resp.text
            assert put_resp.json() == {"th_runs_table_page_size": 15}

            get_resp = client.get("/api/app/th-runs-table-page-size")
            assert get_resp.json() == {"th_runs_table_page_size": 15}

    def test_put_rejects_out_of_range(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            client = TestClient(app)
            resp = client.put(
                "/api/app/th-runs-table-page-size", json={"th_runs_table_page_size": 1}
            )
            assert resp.status_code == 400
