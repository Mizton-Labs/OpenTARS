"""
Tests for issue-local-034's hunt package/run Delete + Archive lifecycle:
backend.threat_hunting.db's set_run_archived/hard_delete_run/
hard_delete_package, list_hunt_packages(include_archived=...), and the new
routes' admin-only gating for the two hard-delete endpoints (archive/
unarchive stays researcher+, same as every other Threat Hunting mutation).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest
from fastapi.testclient import TestClient

from backend.auth import db as auth_db
from backend.auth import service
from backend.main import app
from backend.threat_hunting import db as th_db


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", path):
        await th_db.init_threat_hunting_db()
        yield path


class TestSetRunArchived:
    @pytest.mark.asyncio
    async def test_toggles_independently_of_generation_status_and_package_status(
        self, db_path: Path
    ) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, generation_status, "
                    "created_at) VALUES ('run-1', ?, 'completed', '2026-01-01')",
                    (pkg["id"],),
                )
                await db.commit()

            ok = await th_db.set_run_archived("run-1", True)
            runs = await th_db.list_generation_runs(pkg["id"])
            pkg_after = await th_db.get_hunt_package(pkg["id"])

        assert ok is True
        assert runs[0]["archived"] is True
        assert runs[0]["generation_status"] == "completed"  # untouched
        assert pkg_after["status"] != "archived"  # package-level status untouched

    @pytest.mark.asyncio
    async def test_unarchive_toggle(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, created_at, archived) "
                    "VALUES ('run-1', ?, '2026-01-01', 1)",
                    (pkg["id"],),
                )
                await db.commit()

            await th_db.set_run_archived("run-1", False)
            runs = await th_db.list_generation_runs(pkg["id"])

        assert runs[0]["archived"] is False

    @pytest.mark.asyncio
    async def test_returns_false_for_unknown_run(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            ok = await th_db.set_run_archived("nonexistent", True)

        assert ok is False


class TestHardDeleteRun:
    @pytest.mark.asyncio
    async def test_cascades_through_every_related_table_leaves_sibling_run_untouched(
        self, db_path: Path
    ) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, created_at) "
                    "VALUES ('run-1', ?, '2026-01-01')",
                    (pkg["id"],),
                )
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, created_at) "
                    "VALUES ('run-2', ?, '2026-01-01')",
                    (pkg["id"],),
                )
                await db.execute(
                    "INSERT INTO extracted_iocs (id, evidence_item_id, hunt_package_id, run_id, "
                    "ioc, ioc_type, created_at) VALUES ('ioc-1', 'ev-1', ?, 'run-1', 'evil.com', "
                    "'domain', '2026-01-01')",
                    (pkg["id"],),
                )
                await db.execute(
                    "INSERT INTO task_results (id, hunt_package_id, run_id, task_type, status, "
                    "created_at) VALUES ('tr-1', ?, 'run-1', 'search', 'completed', '2026-01-01')",
                    (pkg["id"],),
                )
                await db.execute(
                    "INSERT INTO hunt_reports (id, hunt_package_id, run_id, created_at) "
                    "VALUES ('rep-1', ?, 'run-1', '2026-01-01')",
                    (pkg["id"],),
                )
                await db.execute(
                    "INSERT INTO run_comments (id, hunt_package_id, run_id, body, created_at) "
                    "VALUES ('c-1', ?, 'run-1', 'note', '2026-01-01')",
                    (pkg["id"],),
                )
                await db.execute(
                    "INSERT INTO threat_intel_analysis (id, hunt_package_id, run_id, created_at) "
                    "VALUES ('ti-1', ?, 'run-1', '2026-01-01')",
                    (pkg["id"],),
                )
                await db.commit()

            ok = await th_db.hard_delete_run("run-1")

            async with aiosqlite.connect(db_path) as db:

                async def count(table: str, run_id: str) -> int:
                    cur = await db.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE run_id = ?",
                        (run_id,),  # noqa: S608
                    )
                    return (await cur.fetchone())[0]

                cur = await db.execute(
                    "SELECT COUNT(*) FROM hunting_packages WHERE id = ?", ("run-1",)
                )
                remaining_run1 = (await cur.fetchone())[0]
                cur = await db.execute(
                    "SELECT COUNT(*) FROM hunting_packages WHERE id = ?", ("run-2",)
                )
                remaining_run2 = (await cur.fetchone())[0]
                remaining_iocs = await count("extracted_iocs", "run-1")
                remaining_tasks = await count("task_results", "run-1")
                remaining_reports = await count("hunt_reports", "run-1")
                remaining_comments = await count("run_comments", "run-1")
                remaining_ti = await count("threat_intel_analysis", "run-1")

        assert ok is True
        assert remaining_run1 == 0
        assert remaining_run2 == 1  # sibling run untouched
        assert remaining_iocs == 0
        assert remaining_tasks == 0
        assert remaining_reports == 0
        assert remaining_comments == 0
        assert remaining_ti == 0

    @pytest.mark.asyncio
    async def test_returns_false_for_unknown_run(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            ok = await th_db.hard_delete_run("nonexistent")

        assert ok is False


class TestHardDeletePackage:
    @pytest.mark.asyncio
    async def test_cascades_through_every_run_and_evidence_leaves_sibling_package_untouched(
        self, db_path: Path
    ) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            sibling = await th_db.create_hunt_package("Sibling", "")
            ev = await th_db.add_evidence_item(pkg["id"], item_type="file", blob_data=b"data")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, created_at) "
                    "VALUES ('run-1', ?, '2026-01-01')",
                    (pkg["id"],),
                )
                await db.execute(
                    "INSERT INTO extracted_iocs (id, evidence_item_id, hunt_package_id, run_id, "
                    "ioc, ioc_type, created_at) VALUES ('ioc-1', ?, ?, 'run-1', 'evil.com', "
                    "'domain', '2026-01-01')",
                    (ev["id"], pkg["id"]),
                )
                await db.commit()

            ok = await th_db.hard_delete_package(pkg["id"])

            async with aiosqlite.connect(db_path) as db:
                cur = await db.execute(
                    "SELECT COUNT(*) FROM hunt_packages WHERE id = ?", (pkg["id"],)
                )
                remaining_pkg = (await cur.fetchone())[0]
                cur = await db.execute(
                    "SELECT COUNT(*) FROM hunting_packages WHERE hunt_package_id = ?", (pkg["id"],)
                )
                remaining_runs = (await cur.fetchone())[0]
                cur = await db.execute(
                    "SELECT COUNT(*) FROM evidence_items WHERE hunt_package_id = ?", (pkg["id"],)
                )
                remaining_evidence = (await cur.fetchone())[0]
                cur = await db.execute(
                    "SELECT COUNT(*) FROM evidence_blobs WHERE evidence_item_id = ?", (ev["id"],)
                )
                remaining_blobs = (await cur.fetchone())[0]
                cur = await db.execute(
                    "SELECT COUNT(*) FROM extracted_iocs WHERE hunt_package_id = ?", (pkg["id"],)
                )
                remaining_iocs = (await cur.fetchone())[0]
                cur = await db.execute(
                    "SELECT COUNT(*) FROM hunt_packages WHERE id = ?", (sibling["id"],)
                )
                remaining_sibling = (await cur.fetchone())[0]

        assert ok is True
        assert remaining_pkg == 0
        assert remaining_runs == 0
        assert remaining_evidence == 0
        assert remaining_blobs == 0
        assert remaining_iocs == 0
        assert remaining_sibling == 1

    @pytest.mark.asyncio
    async def test_returns_false_for_unknown_package(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            ok = await th_db.hard_delete_package("nonexistent")

        assert ok is False


class TestIncludeArchivedListHuntPackages:
    @pytest.mark.asyncio
    async def test_default_excludes_opt_in_includes(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.update_hunt_package(pkg["id"], status="archived")

            default = await th_db.list_hunt_packages()
            opted_in = await th_db.list_hunt_packages(include_archived=True)

        assert default == []
        assert len(opted_in) == 1
        assert opted_in[0]["status"] == "archived"


class TestRoutesAdminGating:
    """Archive/unarchive is researcher+admin (same as every other TH
    mutation); the two hard-delete routes are admin-only — a stricter gate
    than the middleware's blanket researcher-level /api/threat-hunting/
    access, enforced by an explicit per-route dependency (defence in depth,
    same pattern as routes_app.py's admin-only settings)."""

    @pytest.fixture
    def auth_env(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        monkeypatch.setattr(th_db, "_TH_DB_PATH", tmp_path / "th.db")
        monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "1")
        service._failures.clear()

        async def _seed():
            await auth_db.init_users_db()
            await th_db.init_threat_hunting_db()
            await auth_db.create_user("admin", service.hash_password("Adminpass1"), role="admin")
            await auth_db.create_user(
                "researcher", service.hash_password("Researchpass1"), role="threat-researcher"
            )

        asyncio.run(_seed())
        yield
        service._failures.clear()

    def _login(self, username: str, password: str) -> TestClient:
        c = TestClient(app)
        r = c.post("/api/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return c

    def _seed_pkg_and_run(self) -> tuple[str, str]:
        async def _seed():
            pkg = await th_db.create_hunt_package("Hunt", "")
            async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, created_at) "
                    "VALUES ('run-1', ?, '2026-01-01')",
                    (pkg["id"],),
                )
                await db.commit()
            return pkg["id"]

        return asyncio.run(_seed()), "run-1"

    def test_archive_run_allowed_for_researcher(self, auth_env) -> None:
        pkg_id, run_id = self._seed_pkg_and_run()
        c = self._login("researcher", "Researchpass1")
        r = c.put(
            f"/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/archived", json={"archived": True}
        )
        assert r.status_code == 200, r.text
        assert r.json()["archived"] is True

    def test_hard_delete_run_forbidden_for_researcher(self, auth_env) -> None:
        pkg_id, run_id = self._seed_pkg_and_run()
        c = self._login("researcher", "Researchpass1")
        r = c.delete(f"/api/threat-hunting/packages/{pkg_id}/runs/{run_id}")
        assert r.status_code == 403

    def test_hard_delete_run_allowed_for_admin(self, auth_env) -> None:
        pkg_id, run_id = self._seed_pkg_and_run()
        c = self._login("admin", "Adminpass1")
        r = c.delete(f"/api/threat-hunting/packages/{pkg_id}/runs/{run_id}")
        assert r.status_code == 204

    def test_hard_delete_package_forbidden_for_researcher(self, auth_env) -> None:
        pkg_id, _ = self._seed_pkg_and_run()
        c = self._login("researcher", "Researchpass1")
        r = c.delete(f"/api/threat-hunting/packages/{pkg_id}/hard")
        assert r.status_code == 403

    def test_hard_delete_package_allowed_for_admin(self, auth_env) -> None:
        pkg_id, _ = self._seed_pkg_and_run()
        c = self._login("admin", "Adminpass1")
        r = c.delete(f"/api/threat-hunting/packages/{pkg_id}/hard")
        assert r.status_code == 204

    def test_soft_archive_route_unaffected(self, auth_env) -> None:
        # The existing DELETE /packages/{pkg_id} (soft archive) route is
        # untouched — still researcher+admin, not newly admin-gated.
        pkg_id, _ = self._seed_pkg_and_run()
        c = self._login("researcher", "Researchpass1")
        r = c.delete(f"/api/threat-hunting/packages/{pkg_id}")
        assert r.status_code == 204


class TestThNodeTimeoutConfig:
    def test_default_is_900(self) -> None:
        from backend.config.loader import load_th_node_timeout_seconds

        with patch("backend.config.loader.load_app_config", return_value={}):
            assert load_th_node_timeout_seconds() == 900

    def test_save_then_load_round_trips(self, tmp_path) -> None:
        from backend.config.loader import load_th_node_timeout_seconds, save_th_node_timeout_seconds

        cfg_path = tmp_path / "application.yaml"
        with patch("backend.config.loader.APP_CONFIG_PATH", cfg_path):
            save_th_node_timeout_seconds(1200)
            assert load_th_node_timeout_seconds() == 1200

    def test_save_rejects_out_of_range(self, tmp_path) -> None:
        from backend.config.loader import save_th_node_timeout_seconds

        cfg_path = tmp_path / "application.yaml"
        with patch("backend.config.loader.APP_CONFIG_PATH", cfg_path):
            with pytest.raises(ValueError):
                save_th_node_timeout_seconds(30)  # below the 60s minimum
            with pytest.raises(ValueError):
                save_th_node_timeout_seconds(9999)  # above the 3600s maximum

    def test_save_rejects_non_int(self, tmp_path) -> None:
        from backend.config.loader import save_th_node_timeout_seconds

        cfg_path = tmp_path / "application.yaml"
        with patch("backend.config.loader.APP_CONFIG_PATH", cfg_path):
            with pytest.raises(ValueError):
                save_th_node_timeout_seconds(True)  # bool is not a real int here
            with pytest.raises(ValueError):
                save_th_node_timeout_seconds(900.5)  # type: ignore[arg-type]

    def test_route_pair(self, tmp_path) -> None:
        cfg_path = tmp_path / "application.yaml"
        with patch("backend.config.loader.APP_CONFIG_PATH", cfg_path):
            c = TestClient(app)
            r = c.get("/api/app/th-node-timeout-seconds")
            assert r.status_code == 200
            assert r.json()["th_node_timeout_seconds"] == 900

            r = c.put("/api/app/th-node-timeout-seconds", json={"th_node_timeout_seconds": 1000})
            assert r.status_code == 200
            assert r.json()["th_node_timeout_seconds"] == 1000

            r = c.get("/api/app/th-node-timeout-seconds")
            assert r.json()["th_node_timeout_seconds"] == 1000

    def test_route_rejects_bad_body(self, tmp_path) -> None:
        cfg_path = tmp_path / "application.yaml"
        with patch("backend.config.loader.APP_CONFIG_PATH", cfg_path):
            c = TestClient(app)
            r = c.put("/api/app/th-node-timeout-seconds", json={"th_node_timeout_seconds": "soon"})
            assert r.status_code == 400
