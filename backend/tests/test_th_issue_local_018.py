"""Tests for issue-local-018 Part 1 (HuntID/Run ID) and Part 8 (run comments)."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

# ── format_hunt_id / format_run_id ───────────────────────────────────────────


class TestFormatHelpers:
    def test_format_hunt_id_pads_to_two_digits(self):
        from backend.threat_hunting.db import format_hunt_id

        assert format_hunt_id("TH", 1) == "TH01"
        assert format_hunt_id("TH", 9) == "TH09"

    def test_format_hunt_id_does_not_truncate_past_two_digits(self):
        from backend.threat_hunting.db import format_hunt_id

        assert format_hunt_id("TH", 100) == "TH100"

    def test_format_hunt_id_none_seq_is_empty(self):
        from backend.threat_hunting.db import format_hunt_id

        assert format_hunt_id("TH", None) == ""

    def test_format_run_id(self):
        from backend.threat_hunting.db import format_run_id

        assert format_run_id("TH01", 1) == "TH01-X01"
        assert format_run_id("TH01", 12) == "TH01-X12"

    def test_format_run_id_empty_when_no_hunt_id(self):
        from backend.threat_hunting.db import format_run_id

        assert format_run_id("", 1) == ""
        assert format_run_id("TH01", None) == ""


# ── hunt_id_prefix config ────────────────────────────────────────────────────


class TestHuntIdPrefixConfig:
    def test_default_is_th(self, tmp_path, monkeypatch):
        from backend.config import loader

        monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
        assert loader.load_hunt_id_prefix() == "TH"

    def test_save_and_load_round_trip(self, tmp_path, monkeypatch):
        from backend.config import loader

        monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
        loader.save_hunt_id_prefix("HUNT")
        assert loader.load_hunt_id_prefix() == "HUNT"

    def test_save_rejects_disallowed_characters(self, tmp_path, monkeypatch):
        from backend.config import loader

        monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
        with pytest.raises(ValueError):
            loader.save_hunt_id_prefix("TH 01")  # space is not allowed
        with pytest.raises(ValueError):
            loader.save_hunt_id_prefix("TH/01")  # filesystem-unsafe

    def test_save_rejects_empty(self, tmp_path, monkeypatch):
        from backend.config import loader

        monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
        with pytest.raises(ValueError):
            loader.save_hunt_id_prefix("")

    def test_save_rejects_too_long(self, tmp_path, monkeypatch):
        from backend.config import loader

        monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
        with pytest.raises(ValueError):
            loader.save_hunt_id_prefix("A" * 25)  # max is 24


# ── hunt_id_prefix strftime support (issue-local-038) ────────────────────────


class TestHuntIdPrefixStrftime:
    def test_save_accepts_strftime_directives(self, tmp_path, monkeypatch):
        from backend.config import loader

        monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
        loader.save_hunt_id_prefix("TH-%Y%m%d")
        assert loader.load_hunt_id_prefix() == "TH-%Y%m%d"

    def test_format_hunt_id_expands_strftime_using_created_at_not_now(self):
        from backend.threat_hunting.db import format_hunt_id

        assert (
            format_hunt_id("TH-%Y%m%d", 1, "2026-01-15T10:30:00+00:00") == "TH-2026011501"
        )

    def test_format_hunt_id_static_prefix_ignores_created_at(self):
        from backend.threat_hunting.db import format_hunt_id

        assert format_hunt_id("TH", 1, "2026-01-15T10:30:00+00:00") == "TH01"

    def test_format_hunt_id_missing_created_at_falls_back_to_now(self):
        from backend.threat_hunting.db import format_hunt_id

        result = format_hunt_id("TH-%Y", 1, None)
        assert result.startswith("TH-2")  # any sane current year
        assert result.endswith("01")

    def test_format_hunt_id_unparseable_created_at_falls_back_to_now(self):
        from backend.threat_hunting.db import format_hunt_id

        result = format_hunt_id("TH-%Y", 1, "not-a-date")
        assert result.startswith("TH-2")
        assert result.endswith("01")

    @pytest.mark.asyncio
    async def test_create_hunt_package_stamps_date_prefix_from_creation_date(
        self, tmp_path, monkeypatch
    ):
        """A date-based prefix must reflect the package's OWN creation date,
        stable even if read again after that date has passed (not "now")."""
        from unittest.mock import patch

        from backend.config import loader
        from backend.threat_hunting import db as th_db

        monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
        loader.save_hunt_id_prefix("TH-%Y%m%d")

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")

        assert pkg["hunt_id_display"].startswith("TH-")
        assert pkg["hunt_id_display"].endswith("01")
        assert len(pkg["hunt_id_display"]) == len("TH-YYYYMMDD01")


# ── schema v6 migration ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_schema_v6_fresh_db_has_new_columns_and_table(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    pkg_cols = {row[1] for row in conn.execute("PRAGMA table_info(hunt_packages)")}
    run_cols = {row[1] for row in conn.execute("PRAGMA table_info(hunting_packages)")}
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
    conn.close()

    assert "hunt_seq" in pkg_cols
    assert "run_seq" in run_cols
    assert "run_comments" in tables
    assert version == th_db._TH_SCHEMA_VERSION


@pytest.mark.asyncio
async def test_schema_v5_migrates_to_v6_and_backfills_sequences(tmp_path: Path) -> None:
    """Two pre-existing packages, one with two runs — backfill assigns
    hunt_seq/run_seq in creation order (oldest = 1), per-package for runs."""
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"

    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE th_schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO th_schema_version (version) VALUES (5)")
    conn.execute(
        """CREATE TABLE hunt_packages (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'draft', created_by TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE hunting_packages (
            id TEXT PRIMARY KEY, hunt_package_id TEXT NOT NULL, threat_context TEXT,
            hypotheses TEXT, hunting_leads TEXT, deep_retrohunt TEXT, ttp_analysis TEXT,
            query_drafts TEXT, llm_provider TEXT, llm_model TEXT, generation_status TEXT,
            generation_errors TEXT, created_at TEXT NOT NULL, current_step TEXT,
            completed_steps TEXT, step_logs TEXT, research_effort TEXT,
            run_config TEXT DEFAULT '{}'
        )"""
    )
    conn.execute(
        "INSERT INTO hunt_packages VALUES ('pkg-old','Old','', 'draft', NULL, "
        "'2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO hunt_packages VALUES ('pkg-new','New','', 'draft', NULL, "
        "'2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO hunting_packages "
        "(id, hunt_package_id, created_at) VALUES ('run-old-1', 'pkg-old', '2026-01-01T00:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO hunting_packages "
        "(id, hunt_package_id, created_at) VALUES ('run-old-2', 'pkg-old', '2026-01-01T01:00:00+00:00')"
    )
    conn.commit()
    conn.close()

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    pkg_seqs = dict(conn.execute("SELECT id, hunt_seq FROM hunt_packages"))
    run_seqs = dict(conn.execute("SELECT id, run_seq FROM hunting_packages"))
    conn.close()

    assert pkg_seqs["pkg-old"] == 1
    assert pkg_seqs["pkg-new"] == 2
    assert run_seqs["run-old-1"] == 1
    assert run_seqs["run-old-2"] == 2


# ── create_hunt_package: hunt_seq assignment ─────────────────────────────────


@pytest.mark.asyncio
async def test_create_hunt_package_assigns_sequential_hunt_seq(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg1 = await th_db.create_hunt_package("first", "")
        pkg2 = await th_db.create_hunt_package("second", "")

        assert pkg1["hunt_id_display"] == "TH01"
        assert pkg2["hunt_id_display"] == "TH02"


@pytest.mark.asyncio
async def test_create_hunt_package_concurrent_creation_assigns_unique_sequences(
    tmp_path: Path,
) -> None:
    """issue-local-018: BEGIN IMMEDIATE must serialize concurrent creates so
    no two packages ever get the same hunt_seq."""
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        results = await asyncio.gather(
            *(th_db.create_hunt_package(f"pkg-{i}", "") for i in range(8))
        )

    seqs = sorted(pkg["hunt_seq"] for pkg in results)
    assert seqs == list(range(1, 9)), "every package must get a unique, consecutive hunt_seq"


@pytest.mark.asyncio
async def test_clone_hunt_package_gets_its_own_hunt_seq(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        src = await th_db.create_hunt_package("source", "")
        clone = await th_db.clone_hunt_package(src["id"], "clone of source")

        assert clone["hunt_id_display"] == "TH02"


# ── run_seq assignment via runner._save_generation_state ────────────────────


@pytest.mark.asyncio
async def test_save_generation_state_assigns_sequential_run_seq(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db
    from backend.threat_hunting.agents import runner

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")

        await runner._save_generation_state("run-a", pkg["id"], {}, status="running")
        await runner._save_generation_state("run-b", pkg["id"], {}, status="running")

        runs = await th_db.list_generation_runs(pkg["id"])
    by_id = {r["id"]: r for r in runs}
    assert by_id["run-a"]["run_id_display"] == "TH01-X01"
    assert by_id["run-b"]["run_id_display"] == "TH01-X02"


@pytest.mark.asyncio
async def test_save_generation_state_run_seq_scoped_per_package(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db
    from backend.threat_hunting.agents import runner

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg_a = await th_db.create_hunt_package("pkg-a", "")
        pkg_b = await th_db.create_hunt_package("pkg-b", "")

        await runner._save_generation_state("run-a1", pkg_a["id"], {}, status="running")
        await runner._save_generation_state("run-b1", pkg_b["id"], {}, status="running")

        runs_a = await th_db.list_generation_runs(pkg_a["id"])
        runs_b = await th_db.list_generation_runs(pkg_b["id"])
    assert runs_a[0]["run_id_display"] == "TH01-X01"
    assert runs_b[0]["run_id_display"] == "TH02-X01"


@pytest.mark.asyncio
async def test_save_generation_state_update_does_not_reassign_run_seq(tmp_path: Path) -> None:
    """A second save for the same run_id (UPDATE branch) must not touch run_seq."""
    from backend.threat_hunting import db as th_db
    from backend.threat_hunting.agents import runner

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")

        await runner._save_generation_state("run-a", pkg["id"], {}, status="running")
        await runner._save_generation_state("run-a", pkg["id"], {}, status="completed")

        runs = await th_db.list_generation_runs(pkg["id"])
    assert runs[0]["run_id_display"] == "TH01-X01"
    assert runs[0]["generation_status"] == "completed"


# ── list_hunt_packages / get_hunt_package expose display IDs ────────────────


@pytest.mark.asyncio
async def test_list_hunt_packages_includes_hunt_id_display(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        await th_db.create_hunt_package("pkg", "")

        packages = await th_db.list_hunt_packages()
    assert packages[0]["hunt_id_display"] == "TH01"


@pytest.mark.asyncio
async def test_hunt_id_prefix_change_relabels_dynamically(tmp_path: Path, monkeypatch) -> None:
    """Changing the prefix relabels every package on the next read — the
    display string is computed dynamically, never baked in at creation."""
    from backend.config import loader
    from backend.threat_hunting import db as th_db

    monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        await th_db.create_hunt_package("pkg", "")

        packages = await th_db.list_hunt_packages()
        assert packages[0]["hunt_id_display"] == "TH01"

        loader.save_hunt_id_prefix("HUNT")
        packages = await th_db.list_hunt_packages()
        assert packages[0]["hunt_id_display"] == "HUNT01"


# ── Run Comments CRUD ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_and_list_run_comments(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")
        await th_db.create_run_comment(pkg["id"], "run-1", "First note", created_by="alice")
        await th_db.create_run_comment(pkg["id"], "run-1", "Second note", created_by="bob")

        comments = await th_db.list_run_comments("run-1")
    assert [c["body"] for c in comments] == ["First note", "Second note"]  # oldest first
    assert comments[0]["created_by"] == "alice"


@pytest.mark.asyncio
async def test_list_run_comments_scoped_to_run(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")
        await th_db.create_run_comment(pkg["id"], "run-1", "For run 1")
        await th_db.create_run_comment(pkg["id"], "run-2", "For run 2")

        comments_1 = await th_db.list_run_comments("run-1")
        comments_2 = await th_db.list_run_comments("run-2")
    assert [c["body"] for c in comments_1] == ["For run 1"]
    assert [c["body"] for c in comments_2] == ["For run 2"]


@pytest.mark.asyncio
async def test_delete_run_comment(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")
        comment = await th_db.create_run_comment(pkg["id"], "run-1", "Delete me")

        deleted = await th_db.delete_run_comment(comment["id"])
        remaining = await th_db.list_run_comments("run-1")
    assert deleted is True
    assert remaining == []


@pytest.mark.asyncio
async def test_delete_run_comment_returns_false_for_unknown_id(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        deleted = await th_db.delete_run_comment("no-such-id")
    assert deleted is False


# ── Run Comments HTTP routes ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_route_create_list_delete_comment(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")

        client = TestClient(app)
        resp = client.post(
            f"/api/threat-hunting/packages/{pkg['id']}/runs/run-1/comments",
            json={"body": "Looks like a real C2 domain"},
        )
        assert resp.status_code == 201, resp.text
        comment = resp.json()
        assert comment["body"] == "Looks like a real C2 domain"

        resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/runs/run-1/comments")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

        resp = client.delete(
            f"/api/threat-hunting/packages/{pkg['id']}/runs/run-1/comments/{comment['id']}"
        )
        assert resp.status_code == 204

        resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/runs/run-1/comments")
        assert resp.json() == []


@pytest.mark.asyncio
async def test_route_create_comment_rejects_empty_body(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")

        client = TestClient(app)
        resp = client.post(
            f"/api/threat-hunting/packages/{pkg['id']}/runs/run-1/comments",
            json={"body": "   "},
        )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_route_create_comment_404s_for_unknown_package(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

        client = TestClient(app)
        resp = client.post(
            "/api/threat-hunting/packages/does-not-exist/runs/run-1/comments",
            json={"body": "hello"},
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_route_delete_comment_404s_for_unknown_comment(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")

        client = TestClient(app)
        resp = client.delete(
            f"/api/threat-hunting/packages/{pkg['id']}/runs/run-1/comments/no-such-id"
        )
    assert resp.status_code == 404
